# IoT Smart Home Controller

A complete, 3-tier architecture IoT Smart Home Controller system built entirely in C. It supports remote monitoring and control of IoT devices (simulated via client scripts) using native WebSockets over TCP. 

## Features
* **Zero Dependencies (besides SQLite)**: Uses standard POSIX sockets, manual SHA1/Base64 implementation, and low-level framing.
* **I/O Multiplexing**: Handles multiple concurrent clients using `select()` on a single thread.
* **Real-Time Web UI**: Frontend written in HTML/JS with native WebSockets.
* **Persistent Storage**: Uses SQLite to log actions and store latest device states.

## Architecture

1. **IoT Device Layer**: C Clients (`device_client.exe`) connect to the server, performing the WebSocket Upgrade handshake and sending periodic `PING`/status updates.
2. **WebSocket Server**: Core server (`websocket_server.exe`) binds to TCP port 8080, managing all connections using an event loop (`select`). It parses JSON and routes commands.
3. **Web Client**: `index.html` connects via `ws://127.0.0.1:8080` to visualize device state and issue toggle commands.

## Build Instructions (GCC)

### Prerequisites
- GCC Compiler (Linux, macOS, or MSYS2/MinGW on Windows)
- SQLite3 development library installed (`libsqlite3-dev` on Debian/Ubuntu, `sqlite3` on MSYS2).

### Option 1: Linux / WSL / MSYS2 (Recommended)
Run the provided Makefile:
```bash
make
```

### Option 2: Windows Batch Script
If you are on Windows using MinGW and have SQLite installed in your path:
```cmd
build.bat
```

## Running the System
1. **Start the Server**:
   ```bash
   ./websocket_server
   ```
2. **Launch the Dashboard**:
   Open `index.html` in your web browser.
3. **Connect Simulated Devices**:
   Open new terminals and run:
   ```bash
   ./device_client light1
   ./device_client fan1
   ```
   Watch them appear automatically on your Web UI!

## In-Depth Explanations

### Concurrency Model (select vs Multithreading/epoll)
We chose `select()` for this project instead of spawning threads per connection. 
* **Threads**: Consumes a significant amount of memory per client (thread stack) and incurs heavy OS context-switching overhead.
* **`select()`**: Single-threaded. We monitor an array of file descriptors. It scales well for home-IoT (few hundred devices) but is O(N) complexity since it scans all FDs sequentially. 
* **epoll**: (Linux-only) A future optimization would be `epoll()`, which provides O(1) event notification, making it far superior for 10k+ concurrent connections, but less portable than POSIX `select()`.

### TCP Lifecycle & Socket States
* `socket()`, `bind()`, `listen()`, `accept()`, `recv()`, `send()`, `close()`.
* **TIME_WAIT**: If the server closes the connection first, the socket enters `TIME_WAIT` for 2*MSL (Maximum Segment Lifetime) to gracefully handle delayed packets. We use `setsockopt` with `SO_REUSEADDR` to bypass this and allow fast restarts.
* **CLOSE_WAIT**: Occurs when the client drops the connection (sends `FIN`) but our application hasn't explicitly called `close()`. By handling `recv() == 0` we promptly call `close(fd)` to prevent resource leaks.
* **TCP_NODELAY**: Enabled to disable Nagle's Algorithm, significantly reducing latency for small, time-sensitive WebSocket frames.

### WebSocket Protocol Implementation
To establish a connection over plain TCP:
1. Client sends HTTP `GET / HTTP/1.1` with `Upgrade: websocket` and `Sec-WebSocket-Key: <base64>`.
2. Server computes `Base64(SHA1(Key + MagicString))` and replies with `101 Switching Protocols` and `Sec-WebSocket-Accept`.
3. Following this, the channel becomes raw binary. We implemented frame masking (mandatory for client->server, optional server->client), opcode handling (Text 0x1, Close 0x8, Ping 0x9, Pong 0xA), and payload extraction within `%s/utils.c`.

### Security & Database Integration
* **SQLite Locking**: SQLite uses file-level locking. In a multithreaded architecture, DB locking could be a severe bottleneck. Since we use `select()` in a single thread, DB operations act as serialized atomic events naturally. (In prod, we would move long DB disk writes to a background worker to avoid blocking the event loop).
* **Security**: Currently demonstrates a hashed acceptance key, masking to prevent cache poisoning, and ping/pong to prevent dropped half-open connections. Future features include SHA-256 password hashing for a login UI layer.
