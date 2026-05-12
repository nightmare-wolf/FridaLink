# FridaLink Architecture

## Components

### Burp Extension

- Kotlin
- Montoya API
- Swing UI
- WebSocket client to Python sidecar

Responsibilities:

- show current process inventory
- show runtime event stream
- manage custom scripts
- send script execution requests to sidecar

### Python Sidecar

- Python 3
- WebSocket server
- Frida integration point

Responsibilities:

- list devices and processes
- attach to a target process
- inject Frida scripts
- normalize runtime data into a stable event protocol
- stream updates to Burp

## Real-Time Update Flow

1. Burp extension connects to `ws://host:port/ws`
2. Sidecar replies with current process list and available scripts
3. Sidecar pushes:
   - `process_list`
   - `event`
   - `event_batch`
   - `scripts`
   - `status`
4. Burp updates tables immediately on the Swing event thread

## Custom Script Model

Scripts are treated as named artifacts with:

- `id`
- `name`
- `language`
- `description`
- `content`

Initial expectation:

- Frida scripts will usually be JavaScript
- Python entries can represent sidecar actions or wrappers later

## Near-Term Work

- add target selection and explicit attach/detach actions
- add event filtering by process, module, and category
- add structured event detail panel
- replace demo event generation with real Frida process enumeration
