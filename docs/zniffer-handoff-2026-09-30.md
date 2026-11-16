# Zniffer implementation handoff — 30 September 2026

## Scope and decisions

- Current priority: Zniffer. PC Controller implementation has not started.
- Target: a native C++ service in a Docker image, with a browser interface. No Mono runtime. The browser opens local trace files and sends bounded chunks; the service does not save those files in the container.
- The intended deliverable is one service image per application. Only the Zniffer image definition exists so far.
- The architecture and functional scope are documented in [zniffer-cross-platform-architecture.md](zniffer-cross-platform-architecture.md), [pc-controller-cross-platform-architecture.md](pc-controller-cross-platform-architecture.md), and [functional-inventory.md](functional-inventory.md).

## Current runnable state

- The Zniffer service was responding at `http://localhost:8091/` at handoff (`/api/health`: HTTP 200). The process was PID 45993, running `/tmp/zniffer-service`, compiled at 20:58 UTC. This is a development process, not a deployed Docker container; it may disappear when the devcontainer stops.
- `web/index.html`, `web/app.js`, and `web/app.css` are served from disk, so a browser reload gets the latest UI. The fix for duplicate empty tabs and the decoded XML field panel are live on 8091.
- The source tree also contains `src/zniffer/basic_serial.cpp`, compiled into `/tmp/zniffer-service-next` at 21:04 UTC. **That newer binary is not running on 8091.** Switching binaries would reset open server sessions, so do it when testing resumes.
- No Git commit has been made. Most implementation files are currently untracked; inspect `git status --short` before changing or committing anything.

## Implemented in the Zniffer source

- ZLF/ZWLF header and record parsing, PTI/DCH radio frames, serial Zniffer 3.x/4.x framing, and basic Serial API SOF/ACK/NAK/CAN framing.
- Native MPDU summary and CRC checks. The service uses the original `FrameDefinition.xml` and `ZWave_cmd_classes.xml` from `assets/xml` for frame headers, command names, parameter values, labels, bit fields, and basic variant groups.
- Embedded NetworkKeys attachments and S2/S0 singlecast authentication and decryption with OpenSSL. A second bounded browser upload pass handles keys appearing after encrypted frames. Network Key Report and Network Key Set bytes are redacted from API responses.
- Browser tabs for local files, IP PTI capture, and serial Zniffer capture; file rows are paged from browser IndexedDB. The GUI shows XML decoded fields for a selected row, raw record JSON, and text search. The tab duplication bug was fixed in `web/app.js`.
- A Dockerfile and CMake build definition are present. The Docker context excludes ZLF files and `.repos`.

## Verification completed

| Fixture | Observed result |
| --- | --- |
| `trace.zlf` | 9,919 PTI radio frames; all 9,919 CRCs valid. HTTP replay produced XML header fields and command parameters. |
| `10.150.64.94-zniffer.zlf` | 9,840 radio frames with valid CRCs plus one diagnostic record. |
| `trace_s2.zlf` | 20/20 S2 encapsulations authenticated and decrypted; three Network Key Reports redacted. |
| `trace_s0.zlf` | 7/7 S0 encapsulations authenticated and decrypted; one Network Key Set redacted. |
| `TC03486-US.zlf` | 50,152 records, including 13,855 PTI radio frames with valid CRCs. The newer Serial API parser identified 37,979 frames, including 18,995 SOF frames; 18,989 SOF checksums were valid. |

The native test program and the newer service compiled with `g++`; the test program passed. `node --check web/app.js` passed. CMake and Docker were unavailable in this devcontainer, so the CMake build and Docker image have **not** been verified here. IP and serial capture have not been tested against real hardware.

## Known gaps and risks

- XML decoding is partial: complex nested variant groups, markers, encapsulated commands, and some parameter rules still need parity work against the C# implementation. Do not describe XML syntax support as complete.
- No supplied ZLF contains a FrameComment attachment. Per-frame annotation parsing remains unverified; the original C# parser/serializer is itself a placeholder. Trace header comments can be edited and downloaded as a local copy.
- S2 multicast and Long Range security are not implemented. The S0/S2 validation above covers the supplied singlecast captures only.
- Radio configuration/discovery, live capture export, authentication for remote access, and WebSocket streaming remain open.
- Browser field display has been checked through API data and JavaScript syntax, but not through automated browser interaction. The user is testing it manually.
- PC Controller is documented but has no runnable implementation or Docker image.

## Resume sequence

1. Check `git status --short` and the 8091 process. Rebuild the current source and run tests; use `/tmp/zniffer-service-next` only as a temporary reference binary.
2. Restart 8091 with the current build when no browser session needs preserving. Verify `/api/health`, file opening, tab switching/closing, and the XML field panel on `trace.zlf`.
3. Continue XML syntax parity using the existing C# decoder and real captures. Obtain a ZLF with FrameComment attachments and, if possible, an actual serial Zniffer capture.
4. Validate live IP/serial connections with hardware, then build and test the Docker image in an environment with Docker and CMake.
5. Return to the remaining Zniffer functions in the functional inventory before starting PC Controller.

The user ended work for the evening. Resume only on their next instruction; the earlier 23:45 UTC cutoff was for this work session.
