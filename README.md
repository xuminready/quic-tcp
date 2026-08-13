# QUIC-TCP

A Rust-based TCP proxy that transparently bridges connections via QUIC (over UDP), featuring Direct Mode and authenticated P2P UDP Hole Punching Mode with automatic connection restoration.

---

## Features

### 1. Protocol Tunneling (QUIC <-> TCP)
This implementation serves as a transparent proxy bridge, forwarding TCP stream data over single or multiple encrypted QUIC tunnels.

### 2. Concurrency & Scalability
Multiple concurrent client connections are handled asynchronously using Rust's non-blocking `mio` library:
- **`tcp-to-quic`**: Client-side proxy that accepts incoming TCP connections and bridges them over an underlying QUIC tunnel.
- **`quic-to-tcp`**: Server-side proxy that accepts incoming QUIC streams and proxies each stream to a target remote TCP connection.

### 3. State Management & Reliability
- **Early Data (0-RTT)**: Supports sending and receiving early data before full connection handshake completion.
- **Partial Writes**: Non-blocking buffer queues cleanly handle flow-controlled write states across both TCP and QUIC transports.
- **Periodic PING Keepalives (NAT Mapping Maintenance)**: Both `tcp-to-quic` and `quic-to-tcp` send periodic ACK-eliciting PING frames every 5 seconds over the QUIC tunnel in P2P mode to ensure bidirectional NAT state remains warm and never expires.
- **Dead Socket Detection & Automatic RESET**: If periodic PINGs go unanswered for >15 seconds (or the QUIC connection closes), `tcp-to-quic` detects the socket is no longer usable, sends an authenticated `RESET` report to `rendezvous-server`, which signals `quic-to-tcp` to cleanly reset active sessions and restart the 3-way UDP hole punching process to restore the connection seamlessly.

---

## P2P Mode & UDP Hole Punching Architecture

In P2P mode, `quic-to-tcp` and `tcp-to-quic` establish direct UDP socket communication through NAT firewalls without requiring manual port forwarding, coordinated by a central **Rendezvous Server**.

### Key P2P & Security Capabilities

1. **Dual-Tier Passcode Authentication (HMAC-SHA256)**:
   - **Rendezvous Server Registration Passcode (`server_reg_passcode`)**: Configured at `rendezvous-server` and solely used to authorize `quic-to-tcp` servers during registration (`REG`) and status updates (`STATUS`). If a server provides an invalid registration passcode, registration is rejected with:
     `ERR Server registration rejected: invalid rendezvous passcode`.
   - **Per-Server Passcode (`server_passcode`)**: Each `quic-to-tcp` server specifies its own unique passcode. Clients (`tcp-to-quic`) only need to provide the target TCP port and the specific server's passcode.
   - **Specific Rejection Reasons at Rendezvous Server**:
     - *Wrong Server Passcode*: `ERR Authentication failed: incorrect server passcode for target TCP port <port>`
     - *No Matching Server / Port*: `ERR No server registered matching target TCP port <port>`
     - *Server Busy*: `ERR Server for target TCP port <port> is currently BUSY and already connected to another client`
     - *Replay Attack*: `ERR Replay attack detected: duplicate or stale sequence number`

2. **Mutual Peer Authentication (Stream 0 & UDP Probes)**:
   - In **both Direct Mode and P2P Mode**, `quic-to-tcp` and `tcp-to-quic` directly authenticate each other using the server's passcode over reserved **Stream 0**.
   - Upon connection establishment, `tcp-to-quic` sends an authenticated `AUTH <seq> <hmac>` challenge on stream 0. `quic-to-tcp` validates the HMAC and replay sequence, replying with `AUTH_OK <seq> <hmac>`. Unauthenticated sessions or invalid passcodes are terminated immediately.
   - Proxy TCP data streams start at stream ID 4 (`current_stream_id = 4`).

3. **Replay Attack Filter**:
   - Every authenticated control packet and stream 0 handshake frame includes a timestamp-derived sequence number (`seq`).
   - Senders generate sequence numbers containing millisecond timestamps and unique counters.
   - Receivers (`rendezvous-server`, `quic-to-tcp`, and `tcp-to-quic`) enforce a 120-second sliding time window and track seen sequences in a memory-bounded `ReplayFilter` to eliminate replay attacks.

4. **Port-Based Automatic Matching (Non-Interactive)**:
   - Server registration metadata stores the public socket endpoint, target `<tcp_port>`, availability state (`IDLE` vs `BUSY`), and individual server passcode.
   - Clients specify their target `<Target_TCP_Port>`. `rendezvous-server` verifies the server passcode and coordinates the connection automatically.
   - `rendezvous-server` prints a periodic status report every 10 seconds summarizing all registered servers, target TCP ports, states, and connected clients.

5. **Exclusive `BUSY` Server Protection**:
   - Once a server accepts a client connection, its status transitions to **`BUSY`**.
   - Subsequent connection requests from other clients for that target TCP port are rejected while the server is active.
   - When the client connection closes, the server automatically transitions back to **`IDLE`**.

6. **Multi-Round Hole Punching with Retries & Progress Logs**:
   - **Multi-Round Probing**: Hole punching executes up to 3 rounds of probes (20 probes per round at 50ms intervals) with signed HMAC probes (`PEER_PUNCH`, `PEER_PUNCH_ACK`, `PEER_PUNCH_ACK_ACK`).
   - **Detailed Progress Logging**: Explicit progress logs track each stage:
     - `[Progress: Round X/3]`: Probing outbound NAT endpoints.
     - `STEP 1/3`: Initial direct probe received; outbound NAT hole verified.
     - `STEP 2/3`: Peer `ACK` received; bidirectional NAT mapping confirmed.
     - `STEP 3/3`: Peer `ACK_ACK` received; 3-way UDP hole punch complete.
     - `NAT Reflexive Endpoint Discovered`: Updates destination port if symmetric or port-translation NAT is detected.
   - **Handshake & Reconnect Retries**: `tcp-to-quic` retries the overall rendezvous handshake up to 3 times before giving up.
   - **Error Reporting**: If all rounds fail, an explicit error log is printed (`[P2P Hole Punch ERROR] Failed to establish UDP hole punch with peer after 3 rounds. Giving up.`).

7. **Rendezvous Server Decoupling & Fault Tolerance**:
   - The Rendezvous Server is solely a signaling and coordination mediator. Once the UDP hole punch succeeds, all TCP traffic, QUIC session encryption, stream multiplexing, and 5-second NAT keepalive PINGs travel **directly peer-to-peer**.
   - If the Rendezvous Server crashes or goes offline while a connection is established, all active peer sessions and new TCP connections over the established tunnel continue functioning without interruption.

---

## Build Instructions

### Build Prerequisites

#### Linux (Debian/Ubuntu/gLinux)
Requires `cmake`:
```bash
sudo apt update && sudo apt install -y cmake
```

#### macOS
Requires Xcode Command Line Tools and `cmake` (via Homebrew):
```bash
xcode-select --install
brew install cmake
```

#### Windows
Requires Visual Studio Desktop development with C++, `cmake`, and `go` (required by BoringSSL build scripts).

### Compile
Once prerequisites are installed, build release binaries using cargo:
```bash
cargo build --release
```

---

## Usage Guide

### Mode 1: Direct Mode (Static Remote Endpoint)

Use Direct Mode when `quic-to-tcp` has a publicly accessible IP address or configured port forwarding.

#### 1. Start Server Proxy (`quic-to-tcp`)
Listens on UDP for QUIC connections and proxies streams to a local TCP target server:
```bash
RUST_LOG=info cargo run --release --bin quic-to-tcp <Local_UDP_IP:Port> <Remote_TCP_IP:Port> [Server_Passcode]

# Example: listen on UDP port 4433, forward to local TCP port 8080 with passcode 'srv_pass123':
RUST_LOG=info cargo run --release --bin quic-to-tcp 127.0.0.1:4433 127.0.0.1:8080 srv_pass123
```

#### 2. Start Client Proxy (`tcp-to-quic`)
Listens on a local TCP port, connects to remote UDP server, authenticates over stream 0, and bridges TCP connections:
```bash
RUST_LOG=info cargo run --release --bin tcp-to-quic <Local_TCP_IP:Port> <Remote_UDP_IP:Port> [Server_Passcode]

# Example: listen on local TCP port 7070, bridge to 127.0.0.1:4433 with passcode 'srv_pass123':
RUST_LOG=info cargo run --release --bin tcp-to-quic 127.0.0.1:7070 127.0.0.1:4433 srv_pass123
```

---

### Mode 2: P2P Mode (Authenticated UDP Hole Punching)

Use P2P Mode when peers are behind NATs or firewalls.

#### 1. Start the Rendezvous Server
Run on a public server endpoint (or locally for testing):
```bash
RUST_LOG=info cargo run --release --bin rendezvous-server [port] [server_reg_passcode]

# Example (port 5050, server registration passcode 'rdv_secret'):
RUST_LOG=info cargo run --release --bin rendezvous-server 5050 rdv_secret
```
> **Note**: If `[server_reg_passcode]` is omitted, it defaults to `'secret123'`.

#### 2. Start the Server Proxy (`quic-to-tcp`) in P2P Mode
Registers at `rendezvous-server` using `Rendezvous_Passcode`, and configures its own `Server_Passcode`:
```bash
RUST_LOG=info cargo run --release --bin quic-to-tcp p2p <Rendezvous_Server_IP:Port> <Name> <Rendezvous_Passcode> <Server_Passcode> <Remote_TCP_IP:Port>

# Example: register as 'srv1' targeting local TCP port 8080:
RUST_LOG=info cargo run --release --bin quic-to-tcp p2p 127.0.0.1:5050 srv1 rdv_secret srv_pass123 127.0.0.1:8080
```

#### 3. Start the Client Proxy (`tcp-to-quic`) in P2P Mode
Connects to `rendezvous-server`, queries and authenticates with `Server_Passcode` for target TCP port `8080`, performs UDP hole punching, and authenticates peer on Stream 0:
```bash
RUST_LOG=info cargo run --release --bin tcp-to-quic p2p <Rendezvous_Server_IP:Port> <Server_Passcode> <Target_TCP_Port> <Local_TCP_IP:Port>

# Example: listen on local TCP port 7070 and proxy to remote TCP port 8080:
RUST_LOG=info cargo run --release --bin tcp-to-quic p2p 127.0.0.1:5050 srv_pass123 8080 127.0.0.1:7070
```

---

## Certificate Generation

The server proxy (`quic-to-tcp`) requires a TLS certificate and private key (`cert.crt` and `cert.key`) in its working directory.

Generate a self-signed certificate for development/testing:
```bash
openssl req -x509 -newkey rsa:2048 -keyout cert.key -out cert.crt -days 365 -nodes -subj "/CN=localhost"
```

---

## Project Structure

- [`src/lib.rs`](src/lib.rs): Core module re-exports and constants.
- [`src/p2p.rs`](src/p2p.rs): ReplayFilter, P2P handshake orchestration, HMAC-SHA256 authentication, 3-way UDP hole punching, and reconnection protocol.
- [`src/session.rs`](src/session.rs): QUIC session state management, Stream 0 mutual passcode authentication, non-blocking stream multiplexing, and partial write buffers.
- [`src/utils.rs`](src/utils.rs): Non-blocking helper routines and stream ID allocation (streams >= 4).
- [`src/bin/tcp_to_quic.rs`](src/bin/tcp_to_quic.rs): Client proxy binary supporting Direct and P2P modes with Stream 0 auth and reachability monitoring.
- [`src/bin/quic_to_tcp.rs`](src/bin/quic_to_tcp.rs): Server proxy binary supporting Direct and P2P modes with Stream 0 verification, keepalives, and status tracking.
- [`src/bin/rendezvous_server.rs`](src/bin/rendezvous_server.rs): Central coordination server for authenticated UDP hole punching, specific rejection reasons, and replay prevention.