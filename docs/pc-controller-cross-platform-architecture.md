# PC Controller: native C++ service and browser architecture

## Decision

The build produces a **PC Controller Docker image** containing a C++20 service and compiled HTML/CSS/TypeScript assets. A separate Zniffer image is built from the same native protocol library. Each image exposes its own HTTP UI and same-origin WebSocket API as a service, accessed from a regular browser on Windows, macOS, or Linux. This mirrors the useful driver plus administration UI split in `zwave-js` and `zwave-js-ui` while keeping the C# tools' functional scope and protocol behavior. The runtime images contain neither .NET/Mono nor Node.js; JavaScript executes in the user's browser. Use configurable service ports, authenticated browser sessions, WebSocket origin checks, and a versioned message schema. See the [Zniffer architecture](zniffer-cross-platform-architecture.md) for its capture and client-side file requirements.

This choice commits the project to a substantial **C#-to-C++ rewrite of domain behavior**. Similar syntax does not carry over the .NET object model, collections, tasks, events, serializers, file APIs, WPF models, or networking. The existing C# applications are the required behavior references; the JS repositories are architecture and secondary behavior references. The new UI can be delivered incrementally, but the C# core cannot disappear until equivalent native protocol and security paths pass hardware tests. The final product will not embed Node.js or use the JS driver as a runtime backend.

## What the Z-Wave JS repositories contribute

The checked-out [`zwave-js` packages](../.repos/zwave-js/packages/) separate serial bindings, command classes, core protocol types, and the [`Driver`](../.repos/zwave-js/packages/zwave-js/src/Driver.ts) and [`Zniffer`](../.repos/zwave-js/packages/zwave-js/src/Zniffer.ts) APIs. [`zwave-js-ui`'s `ZwaveClient`](../.repos/zwave-js-ui/api/lib/ZwaveClient.ts) and [`SocketManager`](../.repos/zwave-js-ui/api/lib/SocketManager.ts) adapt driver operations to a browser UI; [`SocketEvents.ts`](../.repos/zwave-js-ui/api/lib/SocketEvents.ts) names command, status, node, diagnostics, and Zniffer channels. The UI repository uses **Socket.IO**, with subscriptions and acknowledgements, not a plain WebSocket wire protocol. Our native API should reproduce the *separation and user experience*, while defining its own versioned plain-WebSocket contract. Neither reference repo replaces the C# feature baseline.

| C# PC Controller capability | JS reference | Native parity requirement |
| --- | --- | --- |
| Serial controller connection, node management, command classes, inclusion/exclusion, security/S2, SmartStart | Driver and control panel offer analogous flows. | Preserve the C# workflows, protocol results, prompts, and supported device modes; compare recorded exchanges. |
| ZIP/DTLS controller sessions and TCP/J-Link source discovery | The C# `ZipControllerSession` and `SourcesInfoService` implement these paths; the inspected JS UI primarily wraps the JS driver. | Port and test these source types explicitly; do not infer ZIP/DTLS parity from a serial or TCP tunnel. |
| NVM backup/restore, local and OTA firmware, topology, diagnostics | JS UI has analogous administration screens and backup support. | Match the C# file formats, command semantics, progress/cancel behavior, and diagnostic results. |
| Lab/test functions: IMA, ERTT, transmit/security settings, MPAN, raw commands, logs, statistics, polling | The C# commands and WPF views are broader than a generic node administration UI. | Inventory each command and screen; include it in the web UI or an explicitly designed advanced workspace. Do not silently discard it. |

Use the C# app as the tie-breaker where implementations differ. Keep a traceability sheet with one row per C# command/view: source path, expected behavior, native service method, web route, fixture/hardware test, and parity status. Both JS repositories are MIT licensed; retain notices if code is copied, and check their transitive dependencies before reuse.

## What must be migrated

| Existing code | Native target |
| --- | --- |
| `ZWaveController/Models/BasicControllerSession.cs` and `ZipControllerSession.cs` implement serial Serial API and ZIP/DTLS controller sessions. | Separate `SerialControllerSession` and `ZipControllerSession` with a shared command/session interface and explicit state machine. |
| `ZWaveController/Commands`, `Interfaces`, `Models`, and `Services` contain node management, security, SmartStart, command classes, firmware, NVM, statistics, and configuration. | Migrate use cases one workflow at a time; keep UI prompts and file pickers at the UI boundary. |
| `SourcesInfoService.cs` discovers serial, TCP/J-Link, and ZIP sources. | Native platform discovery adapters and structured source descriptions. |
| `z-wave-tools-core/BasicApplication`, `ZipApplication`, `ZWave`, `ZWaveXml`, and `Utils` contain the shared protocol stack and formats. | Port only the dependency slice needed by each workflow, with binary/behavioral parity tests. |
| `ZWaveControllerUI` has WPF/XAML views for node lists, topology, SmartStart, NVM, firmware, logs, and dialogs. | Web screens with backend-driven state, bounded event batches, and virtualized tables/trees. |

The shared Z-Wave stack and these two applications contain about 185,000 lines of C# in the inspected source directories, including generated command-class code. This is a scale indicator, not a migration estimate. Native assets for serial transport, S2 cryptography, and ZIP/DTLS already appear in the repository. Inspect their exported C interfaces, redistribution terms, and target-architecture coverage before deciding whether to wrap or replace them. The current project files list Windows, Linux, and macOS x64 assets but do not show macOS ARM64 assets.

## Target boundaries

```text
Browser UI: Controller workspace (assets served by Controller image)
     | same-origin HTTP + WebSocket: commands / replies / state events
C++ Controller service: controller sessions
     | per-device command queues and capture streams
     |                 |                   |
Serial API         ZIP/DTLS          configuration / file IO
     \                 /
     Z-Wave frames, command classes, security and node state
```

Define versioned commands and events with correlation IDs, timeouts, cancellation, structured errors, and channel subscriptions modeled after the JS UI's observable pattern. Batch high-frequency logs and network events; never send secret keys or passwords in logs. The backend owns controller sessions, ordering, retries, and persistent data and runs independently of browser tabs. The frontend owns layout, dialogs, selection, and presentation. Browser refresh or UI crash must not leave a controller operation in an ambiguous state. Authenticate sessions, validate WebSocket origins, and restrict host exposure through port binding or a TLS/authenticated reverse proxy. No Socket.IO compatibility is implied.

## Controller connection tabs

The Controller workspace uses the same **tab bar and `+` button** as the Zniffer workspace. Clicking `+` opens a popup with exactly two choices: **Connect to IP device** and **Connect to serial device**. There is no open-trace-file choice in Controller. The IP flow collects host/address, port, and the applicable controller connection mode (for example ZIP/DTLS or supported TCP/J-Link transport); the serial flow offers discovered ports and manual port entry. Validate inputs in the popup, then create a tab that shows connecting, ready, busy, disconnected, or error state. Both choices must be usable by keyboard.

Each Controller tab owns one `IControllerSession` equivalent in the native service, with a stable `sessionId`, source descriptor, command queue, node/network state, selected node, logs, and per-tab view state. All WebSocket commands, replies, progress, and events carry `sessionId` so updates from two connected controllers never mix. Switching tabs leaves other controller sessions connected and their operations running. Closing a tab cancels or finishes its pending operations according to their safety rules, disconnects that source, releases its resources, and affects no other tab. A device/endpoint already owned by another tab should be reported and its tab focused rather than opened twice. A connection failure stays visible on its tab and does not affect other sessions.

This extends the current C# [`ControllerSessionsContainer`](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/ControllerSessionsContainer.cs) model into an explicit web UI contract. It does not introduce file-opening tabs into Controller. The Zniffer workspace's three-choice popup and file document rules are specified in the [Zniffer architecture](zniffer-cross-platform-architecture.md).

## Docker deliverable

Build a multi-stage image with the Controller C++ service binary, its native runtime libraries, and compiled UI assets. Run one Controller service per container, with a configurable HTTP port and explicit persistent state for settings, keys, provisioning lists, and controller metadata. Publish an image for each supported Linux container architecture. IP/J-Link and ZIP/DTLS devices use the container's network path; serial controllers require explicit host device mapping and permissions. On Docker Desktop for Windows/macOS, direct USB/serial passthrough may need a host-side bridge; validate this before claiming serial parity. Include health checks, logs, graceful shutdown, documented port/device mapping, and backup/restore downloads and uploads through the browser. User files are selected in the browser and streamed as needed; they are never assumed to exist inside the container.

## Migration order and release gates

1. Build the C# command/view inventory, then prototype the shared C++ library, Controller service image, browser UI, versioned WebSocket protocol, tab bar, two-choice Controller `+` popup, and source discovery on supported Linux container architectures. Validate the existing native crypto, serial, and DTLS libraries first.
2. Port the minimal Serial API transport, frame parser, and controller connection/version flow. Compare exchanges against the C# implementation using recorded sessions and real devices.
3. Add basic node management and command sending with a web-based node list and log. Verify two controller tabs remain independently connected and that commands, logs, and progress stay with the correct `sessionId`. Preserve queue ordering, cancellation, and disconnect behavior.
4. Port security/S2 and SmartStart, then ZIP/DTLS sessions, NVM backup/restore, firmware operations, diagnostics, and topology. Each slice needs golden protocol traces and hardware-backed acceptance tests before replacing its Windows workflow.
5. Publish the two service images and run full device tests in supported container deployments, including browser access from Windows, macOS, and Linux. Check settings, provisioning lists, NVM images, and firmware file compatibility with the current application. Complete the command/view traceability sheet before retirement of the Windows tool.

The highest migration risks are the large stateful controller sessions, command-class coverage, native security/DTLS ABI compatibility, and container-specific device access. ZIP, secure inclusion, and C#-specific lab functions should be explicit release gates rather than assumed to work because basic serial commands do. The JS repositories show the target service/UI shape; they do not define a reduced feature list.

## Code references

- [`ZWaveController/Models`](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Models/)
- [`ZWaveController/Services/SourcesInfoService.cs`](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Services/SourcesInfoService.cs)
- [`ZWaveController/Commands`](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Commands/)
- [`ZWaveControllerUI/Views`](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveControllerUI/Views/)
- [`z-wave-tools-core`](../.repos/zw-sqa-tools/z-wave-tools-core/)
- [`zwave-js/packages/zwave-js/src/Driver.ts`](../.repos/zwave-js/packages/zwave-js/src/Driver.ts)
- [`zwave-js-ui/api/lib/ZwaveClient.ts`](../.repos/zwave-js-ui/api/lib/ZwaveClient.ts)
- [`zwave-js-ui/api/lib/SocketEvents.ts`](../.repos/zwave-js-ui/api/lib/SocketEvents.ts)
