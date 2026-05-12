from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import websockets

try:
    import frida  # type: ignore
except ImportError:  # pragma: no cover
    frida = None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    pid: int
    name: str
    platform: str
    state: str
    selected: bool = False
    attached: bool = False


@dataclass
class RuntimeEvent:
    timestamp: str
    process: str
    category: str
    module: str
    target: str
    summary: str
    # Extended observability fields — populated by Frida scripts
    severity: str = "info"
    thread_id: str = ""
    script_source: str = ""
    correlation_id: str = ""
    args: str = ""
    retval: str = ""
    backtrace: str = ""
    # Payload preview fields — populated by socket/stream observer scripts
    payload_ascii_preview: str = ""
    payload_hex_preview: str = ""


# ---------------------------------------------------------------------------
# REPL helper script — loaded automatically when a session is attached.
# Exports rpc.exports.evaluate(code) which evals JS in the Frida context
# and returns {ok: bool, result: string} or {ok: false, error: string}.
# ---------------------------------------------------------------------------

_REPL_HELPER_JS = r"""
'use strict';
rpc.exports = {
    evaluate: function(code) {
        try {
            var val = (0, eval)(code);
            if (val === undefined) return { ok: true, result: 'undefined' };
            if (val === null)      return { ok: true, result: 'null' };
            if (typeof val === 'function') {
                return { ok: true, result: '[Function: ' + (val.name || 'anonymous') + ']' };
            }
            if (typeof val === 'object') {
                try { return { ok: true, result: JSON.stringify(val, null, 2) }; }
                catch (e) { return { ok: true, result: String(val) }; }
            }
            return { ok: true, result: String(val) };
        } catch (e) {
            return { ok: false, error: (e && e.message) ? e.message : String(e) };
        }
    }
};
"""


# ---------------------------------------------------------------------------
# Frida backend
# ---------------------------------------------------------------------------

class FridaBackend:
    def __init__(self, sidecar: "FridaLinkSidecar") -> None:
        self.sidecar = sidecar
        self.device = None
        self.session = None
        self.attached_pid: int | None = None
        self.attached_name: str | None = None
        self.loaded_scripts: list[Any] = []
        self.repl_script: Any | None = None  # REPL helper — tracked separately

    def frida_available(self) -> bool:
        return frida is not None

    def detection_summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "host_frida_available": self.frida_available(),
            "android_device_visible": False,
            "device_label": None,
            "android_process_count": 0,
            "session_active": self.session is not None,
            "loaded_script_count": len(self.loaded_scripts),
            "attached_pid": self.attached_pid,
            "attached_name": self.attached_name,
            "error": None,
        }
        if frida is None:
            summary["error"] = "python package 'frida' is not installed"
            return summary
        try:
            device = self._resolve_device()
            processes = device.enumerate_processes()
            summary["android_device_visible"] = True
            summary["device_label"] = getattr(device, "name", None) or getattr(device, "id", None)
            summary["android_process_count"] = len(processes)
        except Exception as exc:
            summary["error"] = str(exc)
        return summary

    def enumerate_processes(self) -> list[ProcessInfo]:
        if frida is None:
            return []
        device = self._resolve_device()
        processes = device.enumerate_processes()
        attached_pid = self.attached_pid
        return [
            ProcessInfo(
                pid=process.pid,
                name=process.name,
                platform="android",
                state="running",
                attached=(process.pid == attached_pid),
            )
            for process in sorted(processes, key=lambda item: item.name.lower())
        ]

    def attach(self, pid: int) -> str:
        if frida is None:
            raise RuntimeError("Frida is not installed in the sidecar environment")
        self.detach()
        device = self._resolve_device()
        self.session = device.attach(pid)
        processes = {process.pid: process.name for process in device.enumerate_processes()}
        self.attached_pid = pid
        self.attached_name = processes.get(pid, f"pid:{pid}")
        self._load_repl_helper()
        return self.attached_name

    def spawn(self, identifier: str) -> tuple[int, str]:
        """Spawn a process by package name / path, attach to it (paused), return (pid, name)."""
        if frida is None:
            raise RuntimeError("Frida is not installed in the sidecar environment")
        self.detach()
        device = self._resolve_device()
        pid = device.spawn(identifier)
        self.session = device.attach(pid)
        self.attached_pid = pid
        # Look up the real display name (e.g. "BLEACH: Soul Resonance") from the
        # process list — the spawned process is present even while paused.
        processes = {process.pid: process.name for process in device.enumerate_processes()}
        self.attached_name = processes.get(pid, identifier)
        self.spawned_pid = pid
        self._load_repl_helper()
        return pid, self.attached_name

    def resume(self) -> None:
        """Resume a previously spawned (paused) process."""
        if frida is None:
            raise RuntimeError("Frida is not installed in the sidecar environment")
        pid = getattr(self, "spawned_pid", None)
        if pid is None:
            raise RuntimeError("No spawned process to resume")
        device = self._resolve_device()
        device.resume(pid)
        self.spawned_pid = None

    def detach(self) -> None:
        for script in self.loaded_scripts:
            try:
                script.unload()
            except Exception:
                pass
        self.loaded_scripts.clear()
        if self.repl_script is not None:
            try:
                self.repl_script.unload()
            except Exception:
                pass
            self.repl_script = None
        if self.session is not None:
            try:
                self.session.detach()
            except Exception:
                pass
        self.session = None
        self.attached_pid = None
        self.attached_name = None

    def _load_repl_helper(self) -> None:
        """Load the REPL evaluator helper into the active session."""
        if self.session is None:
            return
        try:
            script = self.session.create_script(_REPL_HELPER_JS)
            script.load()
            self.repl_script = script
            self.sidecar.log("REPL helper loaded")
        except Exception as exc:
            self.sidecar.log(f"REPL helper load failed (non-fatal): {exc}")
            self.repl_script = None

    def eval_repl(self, code: str) -> dict:
        """Evaluate JS code via the REPL helper. Returns {ok, result} or {ok:False, error}."""
        if self.repl_script is None:
            return {"ok": False, "error": "No active session — attach to a process first"}
        try:
            result = self.repl_script.exports.evaluate(code)
            return result if isinstance(result, dict) else {"ok": True, "result": str(result)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def load_script(self, script_name: str, content: str) -> None:
        if self.session is None:
            raise RuntimeError("No process is attached")
        runtime_script = self.session.create_script(content)
        runtime_script.on("message", lambda message, data: self._on_script_message(script_name, message, data))
        runtime_script.load()
        self.loaded_scripts.append(runtime_script)

    def post_to_scripts(self, message: dict) -> None:
        """Broadcast a message to all loaded scripts via script.post()."""
        for script in self.loaded_scripts:
            try:
                script.post(message)
            except Exception:
                pass

    def _resolve_device(self):
        if self.device is not None:
            return self.device
        assert frida is not None
        manager = frida.get_device_manager()
        try:
            self.device = manager.get_device("usb")
        except Exception:
            self.device = frida.get_usb_device(timeout=5)
        self.sidecar.log(f"Frida device resolved: {getattr(self.device, 'name', None) or getattr(self.device, 'id', 'usb')}")
        return self.device

    def _on_script_message(self, script_name: str, message: dict[str, Any], data: Any) -> None:
        process_name = self.attached_name or f"pid:{self.attached_pid}"

        if message.get("type") == "log":
            # console.log() / console.warn() / console.error() from Frida scripts
            level = str(message.get("level", "info"))
            text = str(message.get("payload", ""))
            severity_map = {"info": "info", "warning": "warn", "error": "error"}
            severity = severity_map.get(level, "info")
            event = RuntimeEvent(
                timestamp=self.sidecar.now(),
                process=process_name,
                category="console",
                module=script_name,
                target="log",
                summary=text,
                severity=severity,
                script_source=script_name,
            )
            self.sidecar.emit_event_threadsafe(event)
            return

        if message.get("type") != "send":
            # Script error or other Frida runtime message
            stack = message.get("stack")
            event = RuntimeEvent(
                timestamp=self.sidecar.now(),
                process=process_name,
                category="error",
                module=script_name,
                target=str(message.get("type", "error")),
                summary=str(stack or message.get("description", message)),
                severity="error",
                script_source=script_name,
            )
            self.sidecar.emit_event_threadsafe(event)
            return

        payload = message.get("payload")

        # Intercept candidates emitted by scripts that call emitIntercept()
        if isinstance(payload, dict) and payload.get("kind") == "intercept":
            self.sidecar.emit_intercept_threadsafe(
                {
                    "id": str(payload.get("id", f"{script_name}-{self.sidecar.now()}")),
                    "timestamp": payload.get("timestamp", self.sidecar.now()),
                    "process": str(payload.get("process", process_name)),
                    "direction": str(payload.get("direction", "outbound")),
                    "channel": str(payload.get("channel", "generic")),
                    "summary": str(payload.get("summary", "Intercept candidate")),
                    "payload": (
                        json.dumps(payload.get("payload", {}), indent=2)
                        if not isinstance(payload.get("payload"), str)
                        else payload.get("payload")
                    ),
                    "editable": bool(payload.get("editable", True)),
                }
            )
            return

        # Structured FridaLink event (type == 'fridalink_event' or any dict payload)
        if isinstance(payload, dict):
            severity = str(payload.get("severity", "info"))
            if severity not in ("info", "warn", "error"):
                severity = "info"

            event = RuntimeEvent(
                timestamp=str(payload.get("timestamp", self.sidecar.now())),
                process=str(payload.get("process", process_name)),
                category=str(payload.get("category", "script")),
                module=str(payload.get("module", script_name)),
                target=str(payload.get("target", payload.get("type", "send"))),
                summary=str(payload.get("summary", str(payload))),
                severity=severity,
                thread_id=str(payload.get("thread_id", "")),
                script_source=str(payload.get("script_source", script_name)),
                correlation_id=str(payload.get("correlation_id", "")),
                args=str(payload.get("args", "")),
                retval=str(payload.get("retval", "")),
                backtrace=str(payload.get("backtrace", "")),
                payload_ascii_preview=str(payload.get("payload_ascii_preview", "")),
                payload_hex_preview=str(payload.get("payload_hex_preview", "")),
            )
        else:
            # Plain string or unstructured payload
            event = RuntimeEvent(
                timestamp=self.sidecar.now(),
                process=process_name,
                category="script",
                module=script_name,
                target="message",
                summary=str(payload),
                script_source=script_name,
            )

        self.sidecar.emit_event_threadsafe(event)


# ---------------------------------------------------------------------------
# Script library helpers
# ---------------------------------------------------------------------------

def scan_script_library(scripts_dir: str) -> list[dict[str, Any]]:
    """Walk a directory tree and return metadata+content for every .js file."""
    if not os.path.isdir(scripts_dir):
        return []

    results: list[dict[str, Any]] = []
    for root, _dirs, files in os.walk(scripts_dir):
        for filename in sorted(files):
            if not filename.endswith(".js"):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    content = fh.read()
                meta = _parse_script_meta(content)
                parent = os.path.basename(root)
                category = meta.get("category", parent if parent != "scripts" else "general")
                script_id = "lib:" + os.path.relpath(filepath, scripts_dir).replace("\\", "/")
                results.append(
                    {
                        "id": script_id,
                        "name": meta.get("name", os.path.splitext(filename)[0]),
                        "category": category,
                        "description": meta.get("description", ""),
                        "version": meta.get("version", "1.0"),
                        "language": "javascript",
                        "content": content,
                        "is_library": True,
                    }
                )
            except Exception as exc:
                print(f"[fridalink] failed to read script {filepath}: {exc}", flush=True)

    return results


def _parse_script_meta(content: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for m in re.finditer(r"^//\s*@(\w+)\s+(.+)$", content, re.MULTILINE):
        meta[m.group(1)] = m.group(2).strip()
    return meta


# ---------------------------------------------------------------------------
# Sidecar server
# ---------------------------------------------------------------------------

class FridaLinkSidecar:
    def __init__(self, host: str, port: int, demo: bool, scripts_dir: str) -> None:
        self.host = host
        self.port = port
        self.demo = demo
        self.scripts_dir = scripts_dir
        self.clients: set[websockets.ServerConnection] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.backend = FridaBackend(self)
        self.intercepts: dict[str, dict[str, Any]] = {}

        # Seed the custom script list with a starter entry
        self.custom_scripts: list[dict[str, Any]] = [
            {
                "id": "starter-trace",
                "name": "Starter Trace Script",
                "language": "javascript",
                "description": "Example custom script entry",
                "content": (
                    "send({ type: 'fridalink_event', category: 'script', module: 'starter', "
                    "target: 'load', summary: 'starter script loaded', severity: 'info' });"
                ),
            }
        ]

        # Library scripts are loaded from disk on startup and on reload requests
        self.library_scripts: list[dict[str, Any]] = []
        self._load_library_scripts()

    def _load_library_scripts(self) -> None:
        if self.scripts_dir:
            self.library_scripts = scan_script_library(self.scripts_dir)
            self.log(
                f"script library loaded: {len(self.library_scripts)} script(s) from {self.scripts_dir}"
            )
        else:
            self.library_scripts = []

    def all_scripts(self) -> list[dict[str, Any]]:
        """Return custom scripts followed by library scripts."""
        return self.custom_scripts + self.library_scripts

    def log(self, message: str) -> None:
        print(f"[fridalink][{self.now()}] {message}", flush=True)

    async def run(self) -> None:
        self.loop = asyncio.get_running_loop()
        async with websockets.serve(self.handle_client, self.host, self.port):
            self.log(f"sidecar listening on ws://{self.host}:{self.port}/ws")
            if self.scripts_dir:
                self.log(f"script library path: {self.scripts_dir}")
            await asyncio.Future()

    async def handle_client(self, websocket: websockets.ServerConnection) -> None:
        self.clients.add(websocket)
        refresh_task: asyncio.Task | None = None
        demo_task: asyncio.Task | None = None
        try:
            self.log(f"client connected, clients={len(self.clients)}")
            await self.send_status(websocket, self.backend_status())
            await self.send_session_summary(websocket)
            await self.send_scripts(websocket)
            await self.send_process_list(websocket, self.current_processes())
            await self.send_intercepts(websocket)
            refresh_task = asyncio.create_task(self.process_poll_loop(websocket))
            if self.demo:
                demo_task = asyncio.create_task(self.demo_loop(websocket))

            async for raw_message in websocket:
                await self.handle_message(websocket, raw_message)
        finally:
            self.clients.discard(websocket)
            self.log(f"client disconnected, clients={len(self.clients)}")
            if refresh_task is not None:
                refresh_task.cancel()
            if demo_task is not None:
                demo_task.cancel()

    async def handle_message(self, websocket: websockets.ServerConnection, raw_message: str) -> None:
        try:
            message = json.loads(raw_message)
        except json.JSONDecodeError:
            await self.send_status(websocket, "Invalid JSON received")
            return

        message_type = message.get("type")

        if message_type == "hello":
            self.log("hello accepted")
            await self.send_status(websocket, "Hello accepted")
            return

        if message_type == "process_refresh":
            processes = self.current_processes()
            self.log(f"process refresh requested, count={len(processes)}")
            await self.send_process_list(websocket, processes)
            await self.send_status(websocket, "Process list refreshed")
            await self.send_session_summary(websocket)
            return

        if message_type == "attach":
            pid = int(message.get("pid"))
            if self.demo:
                await self.send_status(websocket, f"Demo attach to pid {pid}")
                await self.send_process_list(websocket, self.current_processes(attached_pid=pid))
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=self.process_name_for(pid),
                        category="attach",
                        module="session",
                        target=str(pid),
                        summary="Attached to demo process",
                    ),
                )
                return
            try:
                process_name = self.backend.attach(pid)
                self.log(f"attached to pid={pid} name={process_name}")
                await self.send_status(websocket, f"Attached to {process_name} ({pid})")
                await self.send_process_list(websocket, self.current_processes())
                await self.send_session_summary(websocket)
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=process_name,
                        category="attach",
                        module="session",
                        target=str(pid),
                        summary="Attached to target process",
                    ),
                )
            except Exception as exc:
                self.log(f"attach failed pid={pid}: {exc}")
                await self.send_status(websocket, f"Attach failed: {exc}")
                await self.send_session_summary(websocket)
            return

        if message_type == "spawn":
            identifier = str(message.get("identifier", "")).strip()
            if not identifier:
                await self.send_status(websocket, "Spawn failed: no identifier provided")
                return
            if self.demo:
                await self.send_status(websocket, f"Demo spawn: {identifier}")
                return
            scripts_to_load = message.get("scripts", [])  # [{name, content}, ...]
            try:
                pid, name = self.backend.spawn(identifier)
                self.log(f"spawned pid={pid} identifier={identifier}")

                # Load scripts while the process is still paused — this is the
                # window where hooks must be installed before the app runs.
                loaded = []
                failed = []
                for script_entry in scripts_to_load:
                    script_name = str(script_entry.get("name", "unknown"))
                    content = str(script_entry.get("content", ""))
                    if not content:
                        continue
                    try:
                        self.backend.load_script(script_name, content)
                        loaded.append(script_name)
                        self.log(f"pre-loaded script: {script_name}")
                    except Exception as script_err:
                        failed.append(script_name)
                        self.log(f"pre-load failed {script_name}: {script_err}")

                summary_parts = [f"Process spawned (paused): {name} pid={pid}"]
                if loaded:
                    summary_parts.append(f"Scripts loaded: {', '.join(loaded)}")
                if failed:
                    summary_parts.append(f"Scripts failed: {', '.join(failed)}")

                status_msg = f"Spawned {name} (pid {pid})"
                if loaded:
                    status_msg += f" — {len(loaded)} script(s) loaded"
                status_msg += " — click Resume to start app"

                await self.send_status(websocket, status_msg)
                await self.send_process_list(websocket, self.current_processes())
                await self.send_session_summary(websocket)
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=name,
                        category="spawn",
                        module="session",
                        target=identifier,
                        summary=" | ".join(summary_parts),
                    ),
                )
            except Exception as exc:
                self.log(f"spawn failed identifier={identifier}: {exc}")
                await self.send_status(websocket, f"Spawn failed: {exc}")
                await self.send_session_summary(websocket)
            return

        if message_type == "resume":
            if self.demo:
                await self.send_status(websocket, "Demo resume")
                return
            try:
                self.backend.resume()
                self.log("resumed spawned process")
                await self.send_status(websocket, "Process resumed — app is running")
                await self.send_session_summary(websocket)
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=self.backend.attached_name or "unknown",
                        category="spawn",
                        module="session",
                        target="resume",
                        summary="Process resumed",
                    ),
                )
            except Exception as exc:
                self.log(f"resume failed: {exc}")
                await self.send_status(websocket, f"Resume failed: {exc}")
            return

        if message_type == "detach":
            if self.demo:
                await self.send_status(websocket, "Demo detached")
                await self.send_process_list(websocket, self.current_processes())
                return
            previous_pid = self.backend.attached_pid
            previous_name = self.backend.attached_name or (
                self.process_name_for(previous_pid) if previous_pid else "unknown"
            )
            self.backend.detach()
            self.log("detached current session")
            await self.send_status(websocket, "Detached current session")
            await self.send_process_list(websocket, self.current_processes())
            await self.send_session_summary(websocket)
            if previous_pid is not None:
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=previous_name,
                        category="detach",
                        module="session",
                        target=str(previous_pid),
                        summary="Detached from target process",
                    ),
                )
            return

        if message_type == "script_run":
            script = message.get("script", {})
            script_name = script.get("name", "unknown")
            if self.demo:
                await self.send_status(websocket, f"Demo script run request received: {script_name}")
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process="BleachSoulRes",
                        category="script",
                        module="custom",
                        target=script_name,
                        summary="Custom script execution request accepted by demo sidecar",
                    ),
                )
                return
            try:
                self.backend.load_script(script_name, script.get("content", ""))
                self.log(f"loaded script name={script_name} attached_pid={self.backend.attached_pid}")
                await self.send_status(websocket, f"Loaded script: {script_name}")
                await self.send_session_summary(websocket)
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process=self.backend.attached_name or "unknown",
                        category="script",
                        module="custom",
                        target=script_name,
                        summary="Script loaded into attached session",
                    ),
                )
            except Exception as exc:
                self.log(f"script load failed name={script_name}: {exc}")
                await self.send_status(websocket, f"Script load failed: {exc}")
                await self.send_session_summary(websocket)
            return

        if message_type == "script_library_reload":
            # Operator clicked "Reload Library" in the UI
            scripts_dir = str(message.get("path", self.scripts_dir or ""))
            if scripts_dir:
                self.scripts_dir = scripts_dir
                self._load_library_scripts()
            await self.send_scripts(websocket)
            await self.send_status(
                websocket,
                f"Library reloaded: {len(self.library_scripts)} script(s) from {self.scripts_dir}",
            )
            return

        if message_type == "intercept_action":
            intercept_id = str(message.get("id", ""))
            action = str(message.get("action", "forward"))
            payload = str(message.get("payload", ""))
            self.intercepts.pop(intercept_id, None)
            await self.send_status(websocket, f"Intercept action '{action}' accepted for {intercept_id}")
            await self.send_event(
                websocket,
                RuntimeEvent(
                    timestamp=self.now(),
                    process=self.backend.attached_name or "unknown",
                    category="intercept",
                    module="queue",
                    target=intercept_id,
                    summary=f"Intercept action={action}, payload_length={len(payload)}",
                ),
            )
            return

        if message_type == "update_rules":
            rules = message.get("rules", [])
            self.backend.post_to_scripts({"type": "update_rules", "rules": rules})
            active = sum(1 for r in rules if r.get("enabled", True))
            self.log(f"pushed {len(rules)} rule(s) ({active} active) to loaded scripts")
            await self.send_status(websocket, f"Match & Replace: {active} active rule(s) pushed to session")
            return

        if message_type == "rpc_call":
            method = str(message.get("method", ""))
            args = message.get("args", [])
            if not method:
                await self.send_status(websocket, "rpc_call ignored: no method specified")
                return
            if self.demo:
                await self.send_status(websocket, f"Demo rpc_call: {method}({args})")
                await self.send_event(
                    websocket,
                    RuntimeEvent(
                        timestamp=self.now(),
                        process="BleachSoulRes",
                        category="rpc_result",
                        module="lua_il2cpp_inspector",
                        target=method,
                        summary=f"[DEMO] {method}() → demo result",
                        severity="info",
                        args=json.dumps({"method": method, "callArgs": args, "result": "demo"}),
                    ),
                )
                return
            loaded = len(self.backend.loaded_scripts)
            if loaded == 0:
                await self.send_status(websocket, f"rpc_call {method}: no scripts loaded — load a script first")
                return
            self.backend.post_to_scripts({"type": "rpc_call", "method": method, "args": args})
            self.log(f"rpc_call dispatched: {method}({args}) → {loaded} script(s)")
            await self.send_status(websocket, f"RPC dispatched: {method}() → result will appear as rpc_result event")
            return

        if message_type == "repl_eval":
            code = str(message.get("code", "")).strip()
            if not code:
                return
            if self.demo:
                await websocket.send(json.dumps({
                    "type":   "repl_result",
                    "code":   code,
                    "result": f"[DEMO] {code!r} → \"demo-result\"",
                    "error":  None,
                }))
                return
            # script.exports calls are synchronous/blocking — run off the event loop
            loop = asyncio.get_running_loop()
            result_dict = await loop.run_in_executor(None, lambda: self.backend.eval_repl(code))
            await websocket.send(json.dumps({
                "type":   "repl_result",
                "code":   code,
                "result": result_dict.get("result") if result_dict.get("ok") else None,
                "error":  result_dict.get("error")  if not result_dict.get("ok") else None,
            }))
            self.log(f"repl_eval: {code!r[:60]} → ok={result_dict.get('ok')}")
            return

        await self.send_status(websocket, f"Unhandled message type: {message_type}")

    # -----------------------------------------------------------------------
    # Background tasks
    # -----------------------------------------------------------------------

    async def process_poll_loop(self, websocket: websockets.ServerConnection) -> None:
        while True:
            await asyncio.sleep(4)
            await self.send_process_list(websocket, self.current_processes())
            await self.send_session_summary(websocket)

    async def demo_loop(self, websocket: websockets.ServerConnection) -> None:
        tick = 0
        while True:
            tick += 1
            await asyncio.sleep(2)
            await self.send_event(
                websocket,
                RuntimeEvent(
                    timestamp=self.now(),
                    process="BleachSoulRes",
                    category=random.choice(["call", "network", "jni", "message"]),
                    module=random.choice(["libil2cpp.so", "UnityPlayer", "libart.so", "custom.js"]),
                    target=random.choice(["UnitySendMessage", "ssl_write", "BattleEndClient", "InventorySync"]),
                    summary=random.choice(
                        [
                            "Runtime call observed",
                            "Socket payload emitted",
                            "IL2CPP method traced",
                            "Custom script message received",
                        ]
                    ),
                    severity=random.choice(["info", "info", "info", "warn", "error"]),
                ),
            )
            if tick % 3 == 0:
                await self.queue_intercept(
                    {
                        "id": f"demo-{tick}",
                        "timestamp": self.now(),
                        "process": "BleachSoulRes",
                        "direction": "outbound",
                        "channel": "http",
                        "summary": "Demo request candidate",
                        "payload": json.dumps({"path": "/demo", "body": {"tick": tick}}, indent=2),
                        "editable": True,
                    },
                    websocket,
                )

    # -----------------------------------------------------------------------
    # Process helpers
    # -----------------------------------------------------------------------

    def current_processes(self, attached_pid: int | None = None) -> list[ProcessInfo]:
        if self.demo:
            pid = attached_pid
            return [
                ProcessInfo(pid=1010, name="BleachSoulRes", platform="android", state="running", attached=(pid == 1010)),
                ProcessInfo(pid=1011, name="com.android.systemui", platform="android", state="running", attached=(pid == 1011)),
                ProcessInfo(pid=1020, name="zygote64", platform="android", state="background", attached=(pid == 1020)),
            ]
        try:
            return self.backend.enumerate_processes()
        except Exception as exc:
            self.log(f"process enumeration failed: {exc}")
            return []

    # -----------------------------------------------------------------------
    # Message senders
    # -----------------------------------------------------------------------

    async def send_status(self, websocket: websockets.ServerConnection, message: str) -> None:
        await websocket.send(json.dumps({"type": "status", "message": message}))

    async def send_session_summary(self, websocket: websockets.ServerConnection) -> None:
        summary = self.backend.detection_summary()
        await websocket.send(json.dumps({"type": "session_summary", "summary": summary}))

    async def send_process_list(self, websocket: websockets.ServerConnection, processes: list[ProcessInfo]) -> None:
        await websocket.send(json.dumps({"type": "process_list", "processes": [asdict(p) for p in processes]}))

    async def send_scripts(self, websocket: websockets.ServerConnection) -> None:
        await websocket.send(json.dumps({"type": "scripts", "scripts": self.all_scripts()}))

    async def send_intercepts(self, websocket: websockets.ServerConnection) -> None:
        await websocket.send(json.dumps({"type": "intercept_batch", "items": list(self.intercepts.values())}))

    async def send_event(self, websocket: websockets.ServerConnection, event: RuntimeEvent) -> None:
        payload = {"type": "event"}
        payload.update(asdict(event))
        await websocket.send(json.dumps(payload))

    # -----------------------------------------------------------------------
    # Thread-safe broadcast helpers (called from Frida callback threads)
    # -----------------------------------------------------------------------

    def emit_event_threadsafe(self, event: RuntimeEvent) -> None:
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast_event(event), self.loop)

    def emit_intercept_threadsafe(self, intercept: dict[str, Any]) -> None:
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.queue_intercept(intercept), self.loop)

    async def broadcast_event(self, event: RuntimeEvent) -> None:
        if not self.clients:
            return
        payload = {"type": "event"}
        payload.update(asdict(event))
        message = json.dumps(payload)
        await asyncio.gather(
            *(client.send(message) for client in list(self.clients)),
            return_exceptions=True,
        )

    async def queue_intercept(
        self,
        intercept: dict[str, Any],
        websocket: websockets.ServerConnection | None = None,
    ) -> None:
        intercept_id = str(intercept["id"])
        self.intercepts[intercept_id] = intercept
        message = json.dumps({"type": "intercept", **intercept})
        targets = [websocket] if websocket is not None else list(self.clients)
        if not targets:
            return
        await asyncio.gather(
            *(client.send(message) for client in targets if client is not None),
            return_exceptions=True,
        )

    # -----------------------------------------------------------------------
    # Misc helpers
    # -----------------------------------------------------------------------

    def backend_status(self) -> str:
        if self.demo:
            return "Client connected to demo mode"
        summary = self.backend.detection_summary()
        if not summary["host_frida_available"]:
            return "Client connected, but Frida is not installed in the Python sidecar"
        if summary["android_device_visible"]:
            target = summary["attached_name"] or summary["attached_pid"] or "none"
            device_label = summary["device_label"] or "android"
            return (
                f"Client connected, Frida host ok, device={device_label}, "
                f"processes={summary['android_process_count']}, "
                f"sessionActive={summary['session_active']}, "
                f"target={target}, loadedScripts={summary['loaded_script_count']}"
            )
        return (
            f"Client connected, Frida available on host, "
            f"but Android target is not visible: {summary['error']}"
        )

    @staticmethod
    def process_name_for(pid: int | None) -> str:
        mapping = {1010: "BleachSoulRes", 1011: "com.android.systemui", 1020: "zygote64"}
        return mapping.get(pid, f"pid:{pid}")

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FridaLink Python sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7766)
    parser.add_argument("--demo", action="store_true", help="Run with synthetic process and event data")
    parser.add_argument(
        "--scripts-dir",
        default="",
        help=(
            "Path to Frida script library directory. "
            "Defaults to ~/Burp/Scripts (C:\\Users\\<user>\\Burp\\Scripts on Windows, "
            "/home/<user>/Burp/Scripts on Linux), "
            "then falls back to <repo>/scripts."
        ),
    )
    return parser.parse_args()


def resolve_scripts_dir(explicit: str) -> str:
    """Return the script library path to use.

    Resolution order:
      1. Explicit --scripts-dir argument
      2. ~/Burp/Scripts  (C:\\Users\\<user>\\Burp\\Scripts on Windows,
                          /home/<user>/Burp/Scripts on Linux)
      3. <repo>/scripts  relative to this file (dev fallback)
    """
    if explicit:
        return explicit
    # Platform-aware default: ~/Burp/Scripts
    platform_candidate = Path.home() / "Burp" / "Scripts"
    if platform_candidate.is_dir():
        return str(platform_candidate)
    # Dev fallback: <repo>/scripts relative to python/src/fridalink_sidecar/
    here = Path(__file__).resolve().parent
    repo_candidate = here.parent.parent.parent / "scripts"
    if repo_candidate.is_dir():
        return str(repo_candidate)
    return ""


def main() -> None:
    args = parse_args()
    scripts_dir = resolve_scripts_dir(args.scripts_dir)
    sidecar = FridaLinkSidecar(
        host=args.host,
        port=args.port,
        demo=args.demo,
        scripts_dir=scripts_dir,
    )
    asyncio.run(sidecar.run())


if __name__ == "__main__":
    main()
