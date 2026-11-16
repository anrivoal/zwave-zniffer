# Zniffer: native C++ service and browser architecture

## Implementation status (30 September 2026)

The first runnable service slice now exists in this repository: a C++20/libevent HTTP service, a browser tab UI, a streaming ZLF reader, PTI/DCH v2/v3 decoding, basic MPDU fields, serial 3.x/4.x framing and MPDU parsing, Serial API SOF/ACK/NAK/CAN parsing, IP/serial capture adapters, and native S0/S2 singlecast decryption. The service loads the BSD-3-Clause XML command and frame definitions from `assets/xml` to identify frame header definitions and fields, commands, and supported fixed-width and bounded variant parameters. Native CRC validation passes for all 9,919 and 9,840 radio frames in the first two fixtures. The Dockerfile builds only the native service and browser assets; user traces and keys are excluded from its build context. File tabs transfer bounded chunks from a local browser `File`, and live tabs poll bounded capture batches. The service does not persist trace or key files. The first two supplied ZLF v104 fixtures contain 9,919 and 9,841 PTI records respectively; both parse completely, with one non-radio DCH diagnostic in the second fixture. `trace_s2.zlf` contains 136 PTI records, an embedded attachment with seven keys, and 20 S2 message encapsulations; all 20 authenticate and decrypt during a browser-initiated second pass. `trace_s0.zlf` contains 131 PTI records and a six-key attachment; all seven S0 encapsulations authenticate and decrypt. Key-bearing Network Key Reports and S0 Network Key Sets are redacted from the API. `TC03486-US.zlf` contains 50,152 records and 13,855 PTI radio frames with valid CRC; its 38,270 Serial API records yield 37,979 parsed Serial API frames. It has four session attachments but no frame-comment attachment. A synthetic serial Zniffer 4.x record verifies MPDU and XML command decoding, while actual hardware capture remains unverified. The separate text key file is intentionally not imported yet.

This is an **early vertical slice**, not the parity release described below. In particular, the current transport is HTTP polling rather than the target WebSocket contract. Hardware capture, XML variant groups, marker-delimited fields, and complete MPDU/command-class decoding, S2 multicast/Long Range, frame-comment interpretation, radio controls, browser capture export, and authentication still require implementation and parity verification. The S0/S2 fixture results cover captured classic singlecast exchanges only.

## Decision

The build produces a **Zniffer Docker image** containing a C++20 service and compiled HTML/CSS/TypeScript assets. The service exposes the UI over HTTP and a versioned API over same-origin WebSocket. Users open it in a regular browser on Windows, macOS, or Linux. The image contains neither .NET/Mono nor a Node.js runtime; JavaScript executes in the user's browser. The PC Controller build produces a separate image, while both services compile the same native protocol library. See the [PC Controller architecture](pc-controller-cross-platform-architecture.md) for its image.

The service listens on a configurable port inside the container; deployment publishes that port to the desired host interface. Serve HTTP and WebSocket from the same origin, authenticate browser sessions, validate WebSocket origins, and use versioned JSON messages for commands, state, errors, and paged queries. Use binary WebSocket frames for high-rate data where useful. Keep device ownership in the service. A browser refresh can reattach to a live session; capture must report explicit backpressure or stop if no client can receive data and the bounded memory buffer fills. This is an architectural pattern inspired by Z-Wave JS UI, not a promise of wire compatibility with its Socket.IO API.

## What the Z-Wave JS repositories contribute

The checked-out [`zwave-js` Zniffer](../.repos/zwave-js/packages/zwave-js/src/lib/zniffer/Zniffer.ts) exposes capture events, frequency and Long Range configuration, frame parsing, and ZLF load/save. [`ZLFEntry.ts`](../.repos/zwave-js/packages/zwave-js/src/lib/zniffer/ZLFEntry.ts), [`ZLFAttachment.ts`](../.repos/zwave-js/packages/zwave-js/src/lib/zniffer/ZLFAttachment.ts), and the [ZLF parser test](../.repos/zwave-js/packages/zwave-js/src/lib/test/zniffer/parseZLFEntry.test.ts) provide independent examples and fixtures for validating a native parser. [`zwave-js-ui`'s Zniffer manager](../.repos/zwave-js-ui/api/lib/ZnifferManager.ts), [socket events](../.repos/zwave-js-ui/api/lib/SocketEvents.ts), and [Zniffer view](../.repos/zwave-js-ui/src/views/Zniffer.vue) show a driver-to-service-to-web-view flow with status, commands, live frames, and load/save controls. The two reference repositories are MIT licensed; use their structure as guidance and retain notices if source is copied.

| Requirement from the C# Zniffer | What the JS reference demonstrates | Native acceptance rule |
| --- | --- | --- |
| Serial device capture and frequency/LR controls | Driver `Zniffer` and UI manager implement these flows. | Match supported hardware generations, settings, and capture behavior in the C# app. |
| IP capture | The C# `PtiTcpZnifferService` uses a PTI/TCP stream. Z-Wave JS has a `tcp://` serial binding in `packages/serial/src/bindings/node.ts`. | Implement both protocols as distinct source adapters; a TCP serial tunnel is not evidence of PTI/TCP parity. |
| ZLF/ZWLF playback, comments, keys, sessions, and large traces | JS can load/save ZLF, but `ZLFAttachment.ts` marks frame-comment and session attachment parsing unimplemented; its UI fetches all frames into memory. | Preserve the C# file semantics and attachments; stream or page large traces from the native service rather than copying all frames to the browser. Multiple files and devices must coexist in separate tabs. |
| Frame details, filtering, decryption, export, and capture settings | JS UI provides a useful browser interaction pattern. | Inventory the C# commands and screens, then keep every supported workflow or record an explicit, approved scope change. |

When the C# and JS implementations differ, the **C# application's observable behavior and trace files define required parity**. Use JS tests and fixtures as a second oracle to find ambiguities, not as replacement specifications. Do not run the JS driver as a hidden dependency of the final native product.

## Existing code and conversion cost

| Existing implementation | Native migration |
| --- | --- |
| `z-wave-tools-core/ZnifferApplication` contains Zniffer device operations, frame layers, and PTI parsing. | Translate behavior and protocol states into C++; keep operation-by-operation parity tests. |
| `ZWaveZniffer/Services/SerialZnifferService.cs` uses the serial Zniffer stack; `PtiTcpZnifferService.cs` handles PTI over TCP. | Create `SerialCaptureSource` and `TcpPtiCaptureSource` behind a common capture interface. Preserve framing, baud rate detection, reconnect, and cancellation behavior. |
| `FileZnifferService.cs` calls `StorageReader`, while `ZWave/StorageHeader.cs`, `StorageReader.cs`, `StorageWriter.cs`, `Layers/DataChunk.cs`, and attachments define the trace format. | Port file parsing independently of the UI. Read `.zlf` and `.zwlf` before attempting capture; test all supported header versions, CRC, chunks, attachments, and partial-file loading. |
| `ZWaveZnifferUI` is WPF/XAML with trace tables, filters, dialogs, and detailed frame views. | Rebuild as web views with virtual scrolling and backend-side paging/filtering. |
| `ZWave/ZWave_netcore.csproj` already packages some native serial and crypto libraries. | Audit their C ABI, rights to redistribute, and availability for every OS/CPU target before writing replacements. |

This is a **rewrite of the managed protocol/application layers**, even though C# and C++ share some syntax. `BinaryReader`, collections, events, thread coordination, reflection, and .NET networking do not translate directly. The C# reader and capture services are reference implementations for regression tests, not code that a compiler can convert to C++. The existing IP path is PTI over TCP; `UdpZnifferService` is unfinished and is outside the initial parity scope.

## Target modules

```text
Browser UI: Zniffer workspace (assets served by Zniffer image)
     | same-origin HTTP + WebSocket: commands / events / file ranges
C++ Zniffer service: capture coordinator + per-tab trace state
     |                         |
serial / PTI-TCP adapters      ZLF/ZWLF reader and writer
     \                         /
      frame parser, Z-Wave decoder, security, filter engine
```

Process raw bytes and parsed records in bounded C++ memory. The UI receives bounded pages or event batches, never an entire trace file. Apply filtering and sorting before serialization; preserve frame order and timestamps. Expose explicit capture and playback states so reconnect, pause, stop, seek, and error reporting are deterministic. Normalize connection details as structured host/port or serial device data; the current TCP service's `host:port` string split does not cover IPv6 well.

## Source tabs and the add-source popup

The Zniffer workspace has a persistent tab bar with a **`+` button**. Clicking `+` opens a popup with exactly three source choices: **Open ZLF/ZWLF file**, **Connect to IP device**, and **Connect to serial device**. The file choice opens the browser's file picker. The IP choice requests a host/address and port, then connects through the PTI/TCP adapter. The serial choice lists available ports and permits manual port entry where discovery fails, then connects through the serial Zniffer adapter. The popup validates source-specific input and reports connection/open errors in the resulting tab without disturbing other tabs. Keyboard and accessibility behavior should make the `+` button and all three choices reachable without a mouse.

Each successful choice creates a **source tab**: a file tab for playback or a device tab for live capture. Tabs show a filename or device label plus loading/connecting/capturing/paused/error and modified states. Every tab owns its trace grid, frame details, filters, selected frame, scroll position, keys/comments, and save/export state. Switching tabs only changes the visible presentation; other file parses and device captures continue. Reopening the same browser file should focus its existing tab unless the user explicitly requests a second copy; use file size and fingerprint because browsers do not expose local paths. Two tabs must not acquire the same serial port or device connection at once; report the existing owner and offer to focus it.

Assign every tab a stable `documentId` independent of its filename or device address. The native service owns a source-session registry (`documentId`, file/IP/serial source descriptor, parser or connection state, bounded trace index, dirty state, cancellation token); the browser keeps the selected local `File` object, tab presentation state, and bounded visible rows. Commands such as `source.openFile`, `source.connectIp`, `source.connectSerial`, `trace.page`, `trace.filter`, `trace.save`, and `source.close`, as well as progress and error events, carry `documentId`. Closing a file tab cancels its parse/query work and releases its browser file handle; closing a device tab stops capture and disconnects that device. Prompt only when the closing tab has unsaved edits or capture data. Failure in one tab leaves every other tab usable.

**ZLF/ZWLF files always remain on the browser user's machine.** The browser owns the selected `File` and answers bounded byte-range requests from the C++ parser using `File.slice()`. The service parses incrementally, keeps only bounded indexes and caches in memory, and never writes source files or temporary trace copies inside the container. Batch range reads to avoid excessive WebSocket round trips. Saving/exporting streams data back to a browser download or browser-supported writable file handle. Refreshing the page may require the user to select the local file again; identify it by size and content fingerprint before resuming a tab. The current C# [`OpenCommand`](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Commands/OpenCommand.cs) clears the active log before loading a file, and its [`TabbedModelObject`](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Models/TabbedModelObject.cs) represents watch tabs; **unified file/IP/serial source tabs are a new explicit requirement**, not existing C# behavior to copy.

## Docker deliverable

Build a multi-stage image with the C++ service binary, its native runtime libraries, and compiled UI assets. Run one Zniffer service per container, with a configurable HTTP port. **No user trace or capture file is stored in the container or mounted into it.** Stream live-capture output to the browser for local saving, with explicit backpressure and reconnect behavior. Publish an image for each supported Linux container architecture. IP devices use the container's network path; serial capture requires an explicitly mapped host device and permissions. On Docker Desktop for Windows/macOS, direct USB/serial passthrough may need a host-side bridge; validate this before claiming serial parity. Include health checks, logs, graceful shutdown, and documented port/device mapping. Limit exposure through host port binding or a TLS/authenticated reverse proxy.

## Migration order and release gates

1. Create the shared native CMake workspace, Zniffer service image, browser UI, and versioned WebSocket contract. Verify Linux container architectures, browser support, device mapping, and packaging prerequisites early.
2. Establish a C# feature inventory and golden ZLF corpus. Port the ZLF/ZWLF header, chunks, attachments, and read-only playback. Compare frame counts, timestamps, payloads, and error behavior against the current C# app and relevant JS fixtures.
3. Add the tab bar, `+` popup with its three choices, browser file picker, ranged file protocol, source-session registry, and file tabs. Verify two files open concurrently without container-side copies, switching without state loss, cancellation during close, per-tab errors, and opening a new file while another tab contains a large trace.
4. Port frame parsing and display/filtering. Demonstrate smooth scrolling and search on large trace files before implementing the rest of the UI.
5. Add the popup's IP connection and PTI/TCP capture, then its serial connection, capture, and device discovery. Run reconnect/unplug and long-running capture tests on actual hardware in supported container deployments. Verify concurrent file and device tabs, device ownership, and that switching/opening/closing another tab does not interrupt a live capture.
6. Add browser-side save/export streams, security-key handling/decryption, and advanced capture settings. Compare written traces by reopening them in the current app. Audit native S2 crypto and serial libraries for each Linux image architecture.

The C# Windows program remains the behavior oracle during migration. Retire it only when the service passes the complete feature inventory and file/hardware parity gates. A WebSocket adds protocol, lifecycle, and endpoint security work. Browser-only file access and serial hardware mapping are explicit release gates.

## Code references

- [`ZWaveZniffer/Services`](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Services/)
- [`ZWaveZnifferUI`](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZnifferUI/)
- [`ZnifferApplication`](../.repos/zw-sqa-tools/z-wave-tools-core/ZnifferApplication/)
- [`ZWave/StorageHeader.cs`](../.repos/zw-sqa-tools/z-wave-tools-core/ZWave/StorageHeader.cs)
- [`ZWave/StorageReader.cs`](../.repos/zw-sqa-tools/z-wave-tools-core/ZWave/StorageReader.cs)
- [`zwave-js/packages/serial/src/bindings/node.ts`](../.repos/zwave-js/packages/serial/src/bindings/node.ts)
- [`zwave-js-ui/api/lib/ZnifferManager.ts`](../.repos/zwave-js-ui/api/lib/ZnifferManager.ts)
