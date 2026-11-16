# Z-Wave Zniffer Container

A standalone Z-Wave sniffer in a Docker container, with a web interface for analyzing captures.

The container starts the Zniffer web server automatically. It accepts ZLF/ZWLF files from the browser, PTI streams over TCP, and serial Zniffer devices. Capture files selected in the browser are streamed to the native C++ service in bounded chunks and are not stored in the container. Parsed rows are kept in the browser's IndexedDB for paging.

## Run locally

```sh
cmake -S . -B build
cmake --build build --target zniffer_service zlf_inspect
ZW_PORT=8080 ZW_WEB_ROOT=web ./build/zniffer_service
```

Open `http://localhost:8080` and select `+`. The popup accepts a local ZLF/ZWLF file, a PTI device over TCP (port 4901 by default), or a serial Zniffer device. A separate tab is created for each source. File bytes are sent in bounded chunks; the original file and downloaded comment edits stay on the browser user's computer. Live rows stay in browser IndexedDB until their tab is closed.

## Docker image

The standalone image uses Debian `trixie-slim`, builds the service from source, and starts the web server as its container command. The image builder stores the result in the local Docker daemon; it does not publish an image to a registry. Its build version comes from `git describe --tags --always --dirty`.

Run the graphical terminal menu, or choose an action directly:

```sh
python3 scripts/zniffer-image.py
python3 scripts/zniffer-image.py build
python3 scripts/zniffer-image.py release
```

`build` tags the local image as `zw-zniffer:<git-version>`. `release` requires a clean worktree, creates an annotated semantic version tag (initial default `0.0.1`, then the next patch version), builds `zw-zniffer:<tag>` locally, and pushes only the Git tag to the selected remote. A Git remote must be configured.

```sh
docker run --rm -p 127.0.0.1:8080:8080 zw-zniffer:0.0.1
```

For a serial device on Linux, map the device into the container and grant its host group access, for example:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --device=/dev/ttyUSB0:/dev/ttyUSB0 \
  --group-add "$(stat -c %g /dev/ttyUSB0)" zw-zniffer:0.0.1
```

The image contains the service binary and static web assets. It never writes a user-selected ZLF file or capture. IP capture reads DCH frames from a TCP stream; serial capture can read 3.x passively or send the 4.x stop/version/start commands before reading. The latter is based on the C# framing and still needs validation on actual hardware. The current slice displays DCH/PTI and serial Zniffer framing and radio MPDU fields, Serial API SOF/ACK/NAK/CAN records, basic Z-Wave MPDU fields, raw radio bytes, sessions, and key counts. Embedded NetworkKeys attachments are parsed into native key groups (Home ID, regular/temporary flag, and 16-byte keys). S2 singlecast messages with captured nonce exchanges are authenticated and decrypted using native OpenSSL AES-CMAC, CTR-DRBG, and AES-CCM. When keys occur after the frames, the browser performs a second bounded file pass; no file is stored in the container. Decrypted Network Key Report values are redacted from the API. S0 singlecast with captured nonce exchanges is also authenticated and decrypted with native OpenSSL AES. The same bounded second pass handles keys embedded after the frames. S0 Network Key Set values are redacted. The service loads the original BSD-3-Clause `FrameDefinition.xml` and `ZWave_cmd_classes.xml` from `assets/xml` to show frame header definitions and fields, command names, and fixed-width command parameters plus bounded variant and bit-mask byte fields. The native parser also checks Z-Wave frame CRCs. XML variant groups, marker-delimited fields, and nested encapsulated commands, frame-comment interpretation, S2 multicast/Long Range, radio configuration/discovery, live capture export, remote authentication, and WebSocket streaming still need work. Keep the published port on loopback for this development slice.

## Verification

```sh
cmake --build build --target zlf_tests
ctest --test-dir build --output-on-failure
./build/zlf_inspect trace.zlf
```

The supplied `trace.zlf` has ZLF version 104 and 9,919 PTI records. `10.150.64.94-zniffer.zlf` is also version 104, with 9,841 PTI records. Both parse through the HTTP API with matching record and frame counts; the second contains one DCH diagnostic. CRCs pass for all 9,919 and 9,840 radio frames respectively, and XML header definitions are identified for each. Neither has attachment or serial Zniffer records. A synthetic serial 4.x ZLF record validates frame, MPDU, and XML command decoding; an actual serial capture is still needed for hardware parity. The separate key file is excluded from Git and Docker and is not loaded by this slice.

`trace_s2.zlf` has 136 PTI records and one NetworkKeys attachment containing seven embedded keys. The HTTP file replay authenticates and decrypts all 20 S2 message encapsulations. Three decrypted Network Key Reports are reported by name and length only; their key bytes are not returned by the API. This fixture verifies the captured classic 100 kbps singlecast exchange, not every S2 mode.

`trace_s0.zlf` has 131 PTI records and one NetworkKeys attachment containing six embedded keys. The HTTP file replay authenticates and decrypts all seven S0 encapsulations. One decrypted Network Key Set is redacted. The public S0 fallback keys from the C# implementation are also available for legacy exchanges.

`TC03486-US.zlf` has 50,152 records, including 11,790 PTI records that yield 13,855 radio frames, plus 38,270 Serial API records. The native parser identifies all 13,855 PTI frames with valid CRC and 37,979 Serial API frames; 18,989 of 18,995 Serial API SOF frames have valid checksums. It contains four session attachments and no frame-comment attachment, so it cannot validate per-frame comment semantics.
