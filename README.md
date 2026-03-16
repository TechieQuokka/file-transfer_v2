# upnp — Pure P2P File Transfer

A command-line tool for transferring files and folders directly between peers — no central server, no cloud, no accounts.

## Features

- **Pure P2P** — direct TCP connection between sender and receiver
- **TLS encrypted** — every session uses a freshly generated self-signed certificate
- **Ed25519 identity** — each peer has a persistent key pair; public keys are pinned on first contact
- **One-time auth code** — first connection requires a short code displayed by the receiver
- **Known peers** — authenticated peers are saved to `known_peers.yaml`; subsequent transfers reconnect automatically without a code
- **MITM detection** — aborts if a known peer's public key changes
- **Resume support** — interrupted transfers pick up from the last received chunk
- **BLAKE3 integrity check** — every file is verified after transfer
- **UPnP port mapping** — automatically opens the receiver port on the router
- **Progress bars** — per-file and total transfer progress

## Installation

```bash
cargo build --release
```

The binary is placed at `target/release/upnp`.

## Usage

### Receive (run on the destination machine)

```bash
upnp recv
```

Output example:
```
Auth code: a8f3-k2m9-x7q1

Available addresses:
  Local   192.168.1.10:55000
  Public  203.0.113.45:55000

Waiting for connection...
```

Share the address and auth code with the sender.

Options:

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Listening port | `55000` |
| `--path` | Save directory | `~/Downloads` |
| `--manual` | Prompt y/n for each incoming transfer | off |

### Send (run on the source machine)

**First connection** — requires the receiver's address and auth code:

```bash
upnp send --to 203.0.113.45:55000 --code a8f3-k2m9-x7q1 --path ./photos
```

**Subsequent connections** — reconnects to the most recent peer automatically:

```bash
upnp send --path ./photos
```

**Select a specific known peer by index:**

```bash
upnp send --index 2 --path ./photos
```

### Peer management

```bash
# List known peers
upnp send --list

# Add a peer manually (without transferring)
upnp send --add 203.0.113.45:55000

# Set an alias for peer #1
upnp send --index 1 --alias "home-pc"

# Remove peer #3
upnp send --remove 3
```

## How It Works

```
Sender                          Receiver
  │                                │
  │──── TLS connect ───────────────▶│
  │◀─── HandshakeResponse ─────────│  (receiver public key)
  │                                │
  │  [known peer]  verify key pin  │
  │  [new peer]    send auth code  │
  │◀─── AuthResponse ──────────────│
  │                                │
  │──── TransferManifest ──────────▶│  (file list + sizes + hashes)
  │◀─── ResumeInfo ────────────────│  (already-received chunks)
  │                                │
  │──── Chunks (256 KB each) ──────▶│
  │◀─── ChunkAck ──────────────────│
  │         ...                    │
  │──── TransferComplete ──────────▶│
```

1. Receiver binds a port and opens it via UPnP.
2. Both sides exchange Ed25519 public keys during the TLS handshake.
3. New peers authenticate with a one-time code; known peers are verified by stored public key.
4. Sender scans the path, builds a manifest, and streams 256 KB chunks.
5. Receiver reports already-received chunks so the sender can skip them on resume.
6. After all chunks arrive, receiver verifies the BLAKE3 hash before writing the final file.

## File Layout

```
<binary directory>/
└── .upnp/
    ├── identity/
    │   ├── private.key      # Ed25519 private key (keep secret)
    │   └── public.key
    └── known_peers.yaml     # Saved peer list
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `rustls` / `tokio-rustls` | TLS |
| `rcgen` | Self-signed certificate generation |
| `rupnp` / `ssdp-client` | UPnP port mapping |
| `ring` | Ed25519 key generation |
| `blake3` | File integrity hashing |
| `clap` | CLI argument parsing |
| `indicatif` | Progress bars |
| `serde` / `serde_json` / `serde_yaml_ng` | Serialization |

## License

MIT
