# SecureRCE — Encrypted Remote Command Execution Framework

A from-scratch, multi-agent remote execution framework built in C and Python, featuring mutual authentication, end-to-end encryption, and a persistent interactive shell — with zero reliance on SSH or TLS libraries.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [Configuration](#configuration)
- [Protocol Specification](#protocol-specification)
- [Design Decisions](#design-decisions)
- [Known Limitations & Future Work](#known-limitations--future-work)
- [Disclaimer](#disclaimer)

---

## Overview

SecureRCE is a three-component system — **server**, **agents**, and **CLI** — that allows an operator to dispatch shell commands to remote agents over an authenticated, fully encrypted channel.

Every byte sent over the wire after the initial handshake is encrypted with **AES-256-GCM**. The session key is never transmitted — it is independently derived on both sides using **ECDH (P-256) + HKDF-SHA256**. Agents and CLI operators must each present a shared secret token, verified after the encrypted channel is established.

The agent runs a **persistent bash shell** rather than spawning a new process per command, so stateful operations like `cd`, environment variable exports, and background jobs all work as expected.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Operator                         │
│                       [cli.c]                           │
│              Interactive REPL (port 9002)               │
└───────────────────────┬─────────────────────────────────┘
                        │  ECDH handshake + token auth
                        │  AES-256-GCM encrypted frames
                        ▼
┌─────────────────────────────────────────────────────────┐
│                      Server                             │
│                    [server.py]                          │
│   port 9001 (agents)      port 9002 (CLI, localhost)    │
│                                                         │
│   AgentRegistry — tracks connected, authenticated       │
│   agents and routes job output back to the CLI          │
└───────────┬─────────────────────────────────────────────┘
            │  ECDH handshake + token auth
            │  AES-256-GCM encrypted frames
            ▼
┌─────────────────────────────────────────────────────────┐
│                       Agent(s)                          │
│              [agent-001.c / agent-002.c]                │
│                                                         │
│   Persistent bash shell — stateful across commands      │
│   Auto-reconnect on disconnect                          │
└─────────────────────────────────────────────────────────┘
```

**Connection flow for a single command:**

```
CLI                     Server                    Agent
 │                         │                        │
 │── TCP connect ──────────▶│                        │
 │◀─ server pubkey ─────────│                        │
 │── CLI pubkey ───────────▶│                        │
 │   [both derive key]      │                        │
 │── MSG_HELLO (token) ────▶│                        │
 │◀─ MSG_AUTH_OK ───────────│                        │
 │── MSG_JOB_REQUEST ──────▶│                        │
 │                          │── MSG_JOB_ASSIGN ─────▶│
 │                          │◀─ MSG_JOB_OUTPUT ───────│
 │◀─ MSG_JOB_OUTPUT ────────│                        │
 │                          │◀─ MSG_JOB_EXIT ─────────│
 │◀─ MSG_JOB_EXIT ──────────│                        │
```

---

## Security Model

### Encryption

- **Algorithm:** AES-256-GCM — authenticated encryption that provides both confidentiality and integrity.  A forged or tampered frame will fail authentication and be dropped.
- **Key exchange:** ECDH on NIST P-256 (prime256v1). Both parties generate a fresh ephemeral keypair per connection. The raw shared secret is never used directly.
- **Key derivation:** HKDF-SHA256 with a fixed salt (`rce-framework-v1-salt`) and context label (`session-key`) stretches the ECDH output into a 32-byte AES key. The private key is zeroed from memory immediately after derivation.
- **IV:** A fresh 12-byte random IV is generated for every encrypted frame via `RAND_bytes`. Nonce reuse is therefore impossible under normal operation.

### Authentication

- Agents and CLI operators each hold a 32-byte pre-shared token.
- The token is sent **only after** the encrypted channel is established, so it is never exposed on the wire in plaintext.
- The server uses `hmac.compare_digest` for all token comparisons, avoiding timing side-channels.
- An unauthenticated connection receives `MSG_ERROR` and is dropped — no job traffic is possible without a valid token.

### Transport isolation

- The CLI port (9002) binds exclusively to `127.0.0.1`. Remote CLI access is not possible without an additional tunnel (e.g., SSH port forwarding).
- The agent port (9001) binds to `0.0.0.0`, intended for agents on separate hosts.

### What this project does NOT provide

- **Forward secrecy across reconnects** — a compromised long-term token allows impersonation on future connections (the ECDH itself is ephemeral, but the token is static).
- **Certificate pinning / PKI** — there is no identity binding between a public key and an agent identity beyond the token.
- **Replay protection** — GCM authentication covers integrity but there is no sequence number or timestamp to prevent frame replay within a session.

---

## Project Structure

```
.
├── agent/
│   ├── agent-001.c          # Agent instance 1
│   └── agent-002.c          # Agent instance 2 (persistent shell)
├── common/
│   ├── auth.c / auth.h          # Auth payload build & parse
│   ├── framing.c / framing.h    # Length-prefixed frame I/O
│   ├── handshake_wire.c / .h    # ECDH handshake (client + server sides)
│   ├── protocol.h               # Message type constants, size limits
│   └── secure_channel.c / .h   # Encrypt-then-frame / decrypt-then-return
├── crypto/
│   ├── crypto.c / crypto.h      # AES-256-GCM encrypt & decrypt (OpenSSL EVP)
│   └── handshake.c / handshake.h # ECDH key generation & HKDF derivation
├── user/
│   └── cli.c                    # Interactive operator CLI
├── server.py                    # Async Python server (asyncio)
└── Makefile
```

### Component responsibilities

| File | Language | Role |
|------|----------|------|
| `server.py` | Python | Central broker — handshakes, authenticates, routes jobs |
| `agent-00N.c` | C | Connects to server, runs commands in a persistent bash shell |
| `cli.c` | C | Operator REPL — sends commands, streams output |
| `crypto.c` | C | AES-256-GCM via OpenSSL EVP API |
| `handshake.c` | C | ECDH keypair generation + HKDF key derivation |
| `framing.c` | C | Reliable length-prefixed read/write over TCP |
| `secure_channel.c` | C | Composes framing + crypto into `send_secure` / `recv_secure` |
| `auth.c` | C | Serialises / parses the agent identity+token payload |

---

## Prerequisites

### System

| Dependency | Minimum version | Notes |
|------------|-----------------|-------|
| GCC | 9+ | Or any C11-compliant compiler |
| OpenSSL | 1.1.1+ | Provides EVP, ECDH, HKDF |
| Python | 3.10+ | For the server |
| `cryptography` (Python) | 38.0+ | `pip install cryptography` |

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install gcc libssl-dev python3 python3-pip
pip3 install cryptography
```

### macOS (Homebrew)

```bash
brew install openssl python
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip3 install cryptography
```

---

## Building

```bash
git clone https://github.com/w0rtyy/SecureRCE.git
cd securerce
make
```

This produces:

```
agent/agent-001
agent/agent-002
user/cli
```

To clean:

```bash
make clean
```

---

## Running

### Step 1 — Generate tokens

Each agent and each CLI operator needs a unique 32-byte token. The server, agents, and CLI must all share the same values.

```python
# Run once to generate a token
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Step 2 — Configure the server

Open `server.py` and populate `KNOWN_AGENTS` and `KNOWN_CLI_TOKENS` with the hex tokens you generated:

```python
KNOWN_AGENTS: dict[str, bytes] = {
    "agent-001": bytes.fromhex("YOUR_64_HEX_CHAR_TOKEN_HERE"),
    "agent-002": bytes.fromhex("YOUR_64_HEX_CHAR_TOKEN_HERE"),
}

KNOWN_CLI_TOKENS: dict[str, bytes] = {
    "operator-001": bytes.fromhex("YOUR_64_HEX_CHAR_TOKEN_HERE"),
}
```

### Step 3 — Configure agents

In each `agent/agent-00N.c`, set `AGENT_TOKEN` to the matching token bytes:

```c
// agent-001.c
static const unsigned char AGENT_TOKEN[AGENT_TOKEN_LEN] = {
    0xAB, 0xCD, /* ... all 32 bytes ... */
};
```

And set `AGENT_ID` to the corresponding key from `KNOWN_AGENTS`:

```c
#define AGENT_ID "agent-001"
```

Rebuild after any token change:

```bash
make
```

### Step 4 — Configure the CLI

In `user/cli.c`, set `CLI_TOKEN` to the matching token bytes for your operator entry.

> **Recommendation:** In a real deployment, load the token from an environment variable or a file with `chmod 600` permissions rather than hardcoding it.

### Step 5 — Start everything

Open three terminals.

**Terminal 1 — Server:**
```bash
python3 server.py
```

**Terminal 2 — Agent:**
```bash
./agent/agent-001
```

The agent will connect, perform the handshake, authenticate, and wait for commands. It reconnects automatically if the server restarts.

**Terminal 3 — CLI:**
```bash
./user/cli agent-001
```

You should see:

```
[CLI] Connecting to server at 127.0.0.1:9002...
[CLI] Connected
[CLI] Handshake complete
[CLI] Authenticated
[CLI] Agent: agent-001
════════════════════════════════════════
Type commands to execute on agent.
Type 'exit' or 'quit' to disconnect.
════════════════════════════════════════

agent-001> whoami
root

[Exit code: 0]

agent-001> cd /tmp && pwd
/tmp

[Exit code: 0]

agent-001> exit
[CLI] Disconnecting...
[CLI] Connection closed
```

### Running agents on a remote host

The agent only needs to know where the server is. Change `SERVER_HOST` in `agent-00N.c` before building:

```c
#define SERVER_HOST "192.168.1.100"   // your server's IP
#define SERVER_PORT 9001
```

The CLI always connects to `127.0.0.1:9002` (localhost only). To operate from a remote machine, use SSH port forwarding:

```bash
ssh -L 9002:127.0.0.1:9002 user@server-host
./cli agent-001
```

---

## Configuration

| Constant | Location | Default | Description |
|----------|----------|---------|-------------|
| `SERVER_HOST` | `agent-00N.c` | `127.0.0.1` | Server IP the agent connects to |
| `SERVER_PORT` | `agent-00N.c` | `9001` | Agent port |
| `AGENT_ID` | `agent-00N.c` | `agent-00N` | Identity string sent during auth |
| `AGENT_TOKEN` | `agent-00N.c` | all zeros | 32-byte pre-shared secret |
| `RECONNECT_DELAY_SEC` | `agent-00N.c` | `5` | Seconds between reconnect attempts |
| `CLI_TOKEN` | `cli.c` | all zeros | 32-byte operator token |
| `AGENT_PORT` | `server.py` | `9001` | Port the server listens for agents |
| `CLI_PORT` | `server.py` | `9002` | Port the server listens for CLI (localhost only) |
| `KNOWN_AGENTS` | `server.py` | — | Map of agent-id → 32-byte token |
| `KNOWN_CLI_TOKENS` | `server.py` | — | Map of operator-id → 32-byte token |

---

## Protocol Specification

### Wire frame format

Every message — plaintext during handshake, ciphertext afterward — uses the same framing:

```
┌─────────────────────┬──────────┬─────────────────────────┐
│  Length (4 bytes)   │  Type    │  Payload (variable)     │
│  big-endian uint32  │  1 byte  │  up to 65,535 bytes     │
│  includes type byte │          │                         │
└─────────────────────┴──────────┴─────────────────────────┘
```

### Message types

| Value | Name | Direction | Plaintext? | Description |
|-------|------|-----------|------------|-------------|
| 1 | `MSG_HELLO` | both | handshake only | Public key (65 bytes) during ECDH; auth payload afterward |
| 2 | `MSG_AUTH_OK` | server → client | encrypted | Confirm successful authentication |
| 3 | `MSG_JOB_REQUEST` | CLI → server | encrypted | JSON: `{"agent_id": "...", "command": "..."}` |
| 4 | `MSG_JOB_ASSIGN` | server → agent | encrypted | `[id_len:1][job_id:N][command]` |
| 5 | `MSG_JOB_OUTPUT` | agent → server → CLI | encrypted | `[id_len:1][job_id:N][stdout+stderr chunk]` |
| 6 | `MSG_JOB_EXIT` | agent → server → CLI | encrypted | `[id_len:1][job_id:N][exit_code:4 big-endian]` |
| 7 | `MSG_ERROR` | server → client | encrypted | Human-readable error string |

### Encrypted payload layout

After framing is stripped, each encrypted payload is:

```
┌─────────────────┬──────────────────────┬────────────────┐
│  IV (12 bytes)  │  Ciphertext (N bytes) │  GCM tag (16B) │
└─────────────────┴──────────────────────┴────────────────┘
```

---

## Design Decisions

**Why implement crypto from scratch instead of using TLS?**  
Using OpenSSL's EVP API directly — rather than wrapping the whole thing in TLS — keeps the protocol surface small and explicit. Every byte on the wire has a known purpose. It also makes the handshake, key derivation, and frame format easy to audit and explain.

**Why a persistent shell instead of `exec` per command?**  
A fresh process per command would break `cd`, environment variables, shell functions, and any stateful workflow. The persistent shell uses a unique sentinel string to detect command completion and capture the exit code, making it behave like an interactive terminal session.

**Why Python for the server?**  
`asyncio` handles concurrent agent and CLI connections cleanly without threads or a custom event loop. The cryptography library provides the same AES-256-GCM and ECDH primitives as OpenSSL, keeping both sides of the protocol compatible.

**Why `hmac.compare_digest` for token comparison?**  
A plain `==` on byte strings short-circuits on the first mismatched byte, leaking information about how close a wrong token is to a valid one through timing differences. `compare_digest` always takes constant time regardless of where the mismatch occurs.

---

## Known Limitations & Future Work

- **Tokens are static** — rotating tokens requires restarting agents. A future version could add a token-refresh handshake.
- **Single active job per agent** — the agent serialises jobs; a second `MSG_JOB_ASSIGN` while one is running is rejected. A job queue with parallel workers would address this.
- **No sequence numbers** — frames carry no counter, so a man-in-the-middle who records a session and replays it within the same TCP connection could in theory inject old messages. Adding a monotonic nonce would close this.
- **Tokens hardcoded in source** — production use should load tokens from environment variables or a secrets manager.
- **No agent heartbeat** — the server only discovers a dead agent when it tries to send a job. A periodic ping/pong would enable faster failure detection.

---

## Disclaimer

SecureRCE is a **educational project** built to explore systems programming, applied cryptography, and network protocol design from first principles.

In architecture it deliberately mimics a lightweight **Command & Control (C2) framework** — a class of tool used in offensive security and red team operations — with a central broker, persistent agents that beacon outward, and an operator interface for dispatching commands. The intent is to understand how such systems are built and secured, not to provide operational offensive tooling.

**This project should not be deployed against systems you do not own or have explicit written permission to test.** Unauthorised use of remote execution tooling may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent legislation in your jurisdiction.

The default tokens are all-zero placeholders. Any real deployment — even in a lab — should use randomly generated tokens as described in the [Running](#running) section.
