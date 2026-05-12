# FridaLink Sidecar Protocol

Transport:

- WebSocket
- path: `/ws`
- UTF-8 JSON messages

## Client to Sidecar

### hello

```json
{
  "type": "hello",
  "client": "fridalink-burp",
  "version": "0.1.0"
}
```

### script_run

```json
{
  "type": "script_run",
  "script": {
    "id": "starter-trace",
    "name": "Starter Trace Script",
    "language": "javascript",
    "description": "Example",
    "content": "send({type:'log'})"
  }
}
```

### process_refresh

```json
{
  "type": "process_refresh"
}
```

### attach

```json
{
  "type": "attach",
  "pid": 1010
}
```

### detach

```json
{
  "type": "detach"
}
```

## Sidecar to Client

### status

```json
{
  "type": "status",
  "message": "Connected to sidecar"
}
```

### session_summary

```json
{
  "type": "session_summary",
  "summary": {
    "host_frida_available": true,
    "android_device_visible": true,
    "device_label": "USB Device",
    "android_process_count": 312,
    "session_active": false,
    "loaded_script_count": 0,
    "attached_pid": null,
    "attached_name": null,
    "error": null
  }
}
```

### process_list

```json
{
  "type": "process_list",
  "processes": [
    {
      "pid": 1010,
      "name": "BleachSoulRes",
      "platform": "android",
      "state": "running",
      "selected": true,
      "attached": false
    }
  ]
}
```

### event

```json
{
  "type": "event",
  "timestamp": "2026-04-15T12:00:00Z",
  "process": "BleachSoulRes",
  "category": "call",
  "module": "libil2cpp.so",
  "target": "UnitySendMessage",
  "summary": "Runtime call observed"
}
```

### event_batch

```json
{
  "type": "event_batch",
  "events": [
    {
      "timestamp": "2026-04-15T12:00:00Z",
      "process": "BleachSoulRes",
      "category": "network",
      "module": "ssl",
      "target": "ssl_write",
      "summary": "Socket payload emitted"
    }
  ]
}
```

### scripts

```json
{
  "type": "scripts",
  "scripts": [
    {
      "id": "starter-trace",
      "name": "Starter Trace Script",
      "language": "javascript",
      "description": "Example script",
      "content": "send({type:'log'})"
    }
  ]
}
```
