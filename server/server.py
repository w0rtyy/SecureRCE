"""
server.py - Secure task execution hub

Listen on 2 ports:
    AGENT_PORT  (9001): Agent connects, authenticate, awaits job
    CLI_PORT    (9002): Operator CLI connects, dispatches job
    
Wire Protocol (same as framing.c):
    [4-bytes big-endian length (includes byte type)]
    [1 byte type]
    [payload bytes]
"""

import asyncio
import struct
import os
import logging
import json
import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, EllipticCurvePublicKey, SECP256R1
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ──── Configuration ────
AGENT_PORT = 9001
CLI_PORT   = 9002

# Known Agents: agent_id -> 32-byte token (hex-coded for config readability)
# In prod this lives in a config file or db
KNOWN_AGENTS: dict[str, bytes] = {
    "agent-001": bytes.fromhex("00" * 32),   # Replace with real tokens
    "agent-002": bytes.fromhex("00" * 32),
}

# Known CLI operators: operator_id -> 32-byte token
# Mirrors KNOWN_AGENTS — add one entry per human operator.
# The CLI sends its token as a raw 32-byte MSG_HELLO payload after the handshake.
KNOWN_CLI_TOKENS: dict[str, bytes] = {
    "operator-001": bytes.fromhex("00" * 32),   # Replace with real token
}

# Message type constraints — match protocol.h
MSG_HELLO       = 1
MSG_AUTH_OK     = 2
MSG_JOB_REQUEST = 3
MSG_JOB_ASSIGN  = 4
MSG_JOB_OUTPUT  = 5
MSG_JOB_EXIT    = 6
MSG_ERROR       = 7

MAX_FRAME_LEN = 65536
EC_PUBKEY_LEN = 65

# ──── Logging ────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("server_audit.log"),
    ]
)
log = logging.getLogger("server")


# ──── Frame (mirrors framing.c) ────
async def recv_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """Read one frame. Return (type, payload). Raises on errors."""
    hdr    = await reader.readexactly(4)
    length = struct.unpack(">I", hdr)[0]

    if length < 1 or length > MAX_FRAME_LEN:
        raise ValueError(f"Invalid frame length: {length}")

    data     = await reader.readexactly(length)
    msg_type = data[0]
    payload  = data[1:]
    return msg_type, payload

async def send_frame(writer: asyncio.StreamWriter, msg_type: int, payload: bytes):
    """Write one frame."""
    length = 1 + len(payload)
    hdr    = struct.pack(">I", length)
    writer.write(hdr + bytes([msg_type]) + payload)
    await writer.drain()


# ──── Crypto bridge ────
IV_LEN  = 12
TAG_LEN = 16

def py_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns iv + ciphertext + tag."""
    iv         = os.urandom(IV_LEN)
    aesgcm     = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    return iv + ct_and_tag

def py_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Input: iv + ciphertext + tag. Raises on auth failure."""
    if len(ciphertext) < IV_LEN + TAG_LEN:
        raise ValueError("Ciphertext too short")
    iv         = ciphertext[:IV_LEN]
    ct_and_tag = ciphertext[IV_LEN:]
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(iv, ct_and_tag, None)

async def recv_secure(reader, key: bytes) -> tuple[int, bytes]:
    """Receive an encrypted frame and decrypt it."""
    msg_type, enc_payload = await recv_frame(reader)
    plain = py_decrypt(enc_payload, key)
    return msg_type, plain

async def send_secure(writer, msg_type: int, payload: bytes, key: bytes):
    """Encrypt payload and send as a frame."""
    enc = py_encrypt(payload, key)
    await send_frame(writer, msg_type, enc)


# ──── Handshake (server side) ────
async def do_server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
) -> bytes:
    """
    Performs ECDH handshake as server.
    Returns 32-byte session key.
    """
    backend = default_backend()

    # 1. Generate ephemeral P-256 keypair
    private_key = generate_private_key(SECP256R1(), backend)

    # 2. Serialise our public key to uncompressed point (65 bytes)
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    assert len(pub_bytes) == EC_PUBKEY_LEN

    # Send our public key (plaintext — this IS the handshake)
    await send_frame(writer, MSG_HELLO, pub_bytes)
    log.debug("Sent public key (%d bytes)", len(pub_bytes))

    # 3. Receive peer's public key
    msg_type, peer_pub_bytes = await recv_frame(reader)
    if msg_type != MSG_HELLO or len(peer_pub_bytes) != EC_PUBKEY_LEN:
        raise ValueError("Unexpected handshake frame")

    peer_pub_key = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), peer_pub_bytes)

    # 4. ECDH — compute shared secret
    shared_secret = private_key.exchange(ECDH(), peer_pub_key)

    # 5. HKDF — derive session key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"rce-framework-v1-salt",
        info=b"session-key",
        backend=backend
    )
    session_key = hkdf.derive(shared_secret)
    log.debug("Derived session key")
    return session_key


# ──── Agent Session State ────
@dataclass
class AgentSession:
    agent_id:     str
    session_key:  bytes
    connected_at: float                = field(default_factory=time.time)
    job_queue:    asyncio.Queue        = field(default_factory=asyncio.Queue)
    output_queue: asyncio.Queue        = field(default_factory=asyncio.Queue)
    writer:       Optional[asyncio.StreamWriter] = None

class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AgentSession] = {}
        self._lock = asyncio.Lock()

    async def register(self, session: AgentSession):
        async with self._lock:
            self._agents[session.agent_id] = session
            log.info("AUDIT: Agent registered: %s", session.agent_id)

    async def unregister(self, agent_id: str):
        async with self._lock:
            self._agents.pop(agent_id, None)
            log.info("AUDIT: Agent disconnected: %s", agent_id)

    async def get(self, agent_id: str) -> Optional[AgentSession]:
        async with self._lock:
            return self._agents.get(agent_id)

    async def list_ids(self) -> list[str]:
        async with self._lock:
            return list(self._agents.keys())

registry = AgentRegistry()


# ───── Agent Connection Handler ─────
async def handle_agent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Lifecycle:
        1. ECDH handshake
        2. Receive encrypted MSG_HELLO with auth payload
        3. Validate agent_id + token
        4. Send MSG_AUTH_OK
        5. Enter job dispatch loop
    """
    peer     = writer.get_extra_info("peername")
    agent_id = None
    log.info("Agent connection from %s", peer)

    try:
        # ── Handshake ──
        session_key = await do_server_handshake(reader, writer)
        log.info("Handshake completed with %s", peer)

        # ── Auth ──
        msg_type, auth_payload = await recv_secure(reader, session_key)
        if msg_type != MSG_HELLO:
            raise ValueError(f"Expected MSG_HELLO for auth, got {msg_type}")

        # Parse: [id_len:1][agent_id:N][token:32]
        id_len = auth_payload[0]
        if id_len == 0 or id_len > 64 or len(auth_payload) < 1 + id_len + 32:
            raise ValueError("Malformed auth payload")

        agent_id = auth_payload[1 : 1 + id_len].decode("ascii")
        token    = auth_payload[1 + id_len : 1 + id_len + 32]

        known_token = KNOWN_AGENTS.get(agent_id)
        if known_token is None or known_token != token:
            log.warning("AUDIT: Auth FAILED for claimed id: %s from %s", agent_id, peer)
            await send_secure(writer, MSG_ERROR, b"auth_failed", session_key)
            return

        log.info("AUDIT: Auth ok for agent_id: %s from %s", agent_id, peer)

        session = AgentSession(
            agent_id=agent_id,
            session_key=session_key,
            writer=writer
        )
        await registry.register(session)

        await send_secure(writer, MSG_AUTH_OK, b"ok", session_key)

        # ── Job dispatch loop ──
        await agent_job_loop(reader, writer, session)

    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError) as e:
        log.warning("Agent %s disconnected: %s", peer, e)
    finally:
        if agent_id:
            await registry.unregister(agent_id)
        writer.close()

async def agent_job_loop(
    reader:  asyncio.StreamReader,
    writer:  asyncio.StreamWriter,
    session: AgentSession
):
    """
    Concurrently:
        1. Pull jobs from session.job_queue and send them to agent
        2. Read output frames from agent and push to session.output_queue
    """
    key = session.session_key

    async def sender():
        while True:
            job_id, command = await session.job_queue.get()
            job_id_bytes    = job_id.encode()
            payload         = bytes([len(job_id_bytes)]) + job_id_bytes + command.encode()
            await send_secure(writer, MSG_JOB_ASSIGN, payload, key)
            log.info("AUDIT: Dispatched job_id=%s to agent=%s: %s",
                     job_id, session.agent_id, command)

    async def receiver():
        while True:
            msg_type, payload = await recv_secure(reader, key)

            if msg_type == MSG_JOB_OUTPUT:
                id_len = payload[0]
                job_id = payload[1 : 1 + id_len].decode()
                chunk  = payload[1 + id_len:]
                await session.output_queue.put((job_id, MSG_JOB_OUTPUT, chunk))

            elif msg_type == MSG_JOB_EXIT:
                id_len   = payload[0]
                job_id   = payload[1 : 1 + id_len].decode()
                exitcode = struct.unpack(">I", payload[1 + id_len : 1 + id_len + 4])[0]
                await session.output_queue.put((job_id, MSG_JOB_EXIT, exitcode))

            else:
                log.warning("Unexpected message type %d from agent", msg_type)

    await asyncio.gather(sender(), receiver())


# ───── CLI Connection Handler ─────
async def handle_cli(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Lifecycle (mirrors handle_agent):
        1. ECDH handshake  — derives session key, encrypts everything after
        2. Receive encrypted MSG_HELLO carrying a 32-byte operator token
        3. Validate token against KNOWN_CLI_TOKENS
        4. Send MSG_AUTH_OK
        5. Loop: receive encrypted MSG_JOB_REQUEST, stream back encrypted output

    The CLI sends its token as a raw 32-byte payload (no id_len prefix) so the
    server does a constant-time comparison against every known token.  This
    avoids leaking which token matched (timing side-channel).
    """
    peer        = writer.get_extra_info("peername")
    operator_id = None
    log.info("CLI connection from %s", peer)

    try:
        # ── Step 1: ECDH handshake ──
        # Exactly the same call used for agent connections — the protocol is identical; only what comes *after* the handshake differs.
        session_key = await do_server_handshake(reader, writer)
        log.info("CLI handshake completed with %s", peer)

        # ── Step 2: Receive operator token ──
        msg_type, auth_payload = await recv_secure(reader, session_key)
        if msg_type != MSG_HELLO:
            raise ValueError(f"Expected MSG_HELLO for CLI auth, got {msg_type}")

        if len(auth_payload) != 32:
            raise ValueError(f"CLI auth payload must be 32 bytes, got {len(auth_payload)}")

        # ── Step 3: Validate token ──
        # Iterate all known tokens so no single early-exit leaks *which* entry matched.  hmac.compare_digest gives constant-time byte comparison.
        import hmac
        matched_id = None
        for oid, known_token in KNOWN_CLI_TOKENS.items():
            if hmac.compare_digest(known_token, auth_payload):
                matched_id = oid
                break   # one match is enough; tokens are unique per operator

        if matched_id is None:
            log.warning("AUDIT: CLI auth FAILED from %s", peer)
            await send_secure(writer, MSG_ERROR, b"auth_failed", session_key)
            return

        operator_id = matched_id
        log.info("AUDIT: CLI auth ok for operator: %s from %s", operator_id, peer)

        # ── Step 4: Confirm auth ──
        await send_secure(writer, MSG_AUTH_OK, b"ok", session_key)

        # ── Step 5: Job loop ──
        # All frames are now encrypted with session_key.
        while True:
            msg_type, payload = await recv_secure(reader, session_key)

            if msg_type != MSG_JOB_REQUEST:
                await send_secure(writer, MSG_ERROR, b"Expected MSG_JOB_REQUEST", session_key)
                continue

            # Parse JSON request
            req             = json.loads(payload.decode("utf-8"))
            target_agent_id = req["agent_id"]
            command         = req["command"]

            log.info("AUDIT: operator=%s requested command on agent=%s: %s",
                     operator_id, target_agent_id, command)

            # Find the target agent
            session = await registry.get(target_agent_id)
            if session is None:
                await send_secure(
                    writer, MSG_ERROR,
                    f"agent {target_agent_id} not connected".encode(),
                    session_key
                )
                continue

            # Generate a unique job_id
            job_id = f"job-{int(time.time() * 1000) % 1000000:06d}"
            log.info("Dispatching job_id=%s to agent=%s", job_id, target_agent_id)

            # Dispatch to agent
            await session.job_queue.put((job_id, command))

            # Stream output back to CLI for THIS job
            while True:
                received_job_id, frame_type, data = await session.output_queue.get()

                if received_job_id != job_id:
                    # Not our job — put it back and yield
                    await session.output_queue.put((received_job_id, frame_type, data))
                    await asyncio.sleep(0.01)
                    continue

                if frame_type == MSG_JOB_OUTPUT:
                    job_id_bytes   = received_job_id.encode()
                    output_payload = bytes([len(job_id_bytes)]) + job_id_bytes + data
                    await send_secure(writer, MSG_JOB_OUTPUT, output_payload, session_key)

                elif frame_type == MSG_JOB_EXIT:
                    job_id_bytes = received_job_id.encode()
                    exit_bytes   = struct.pack(">I", data)
                    exit_payload = bytes([len(job_id_bytes)]) + job_id_bytes + exit_bytes
                    await send_secure(writer, MSG_JOB_EXIT, exit_payload, session_key)
                    break   # inner loop only — outer loop waits for next command

    except (asyncio.IncompleteReadError, json.JSONDecodeError,
            KeyError, ConnectionResetError, ValueError) as e:
        log.warning("CLI %s disconnected: %s", peer, e)
    finally:
        if operator_id:
            log.info("AUDIT: CLI operator %s disconnected from %s", operator_id, peer)
        writer.close()


# ───── Entry Point ─────
async def main():
    agent_server = await asyncio.start_server(
        handle_agent, "0.0.0.0", AGENT_PORT
    )
    cli_server = await asyncio.start_server(
        handle_cli, "127.0.0.1", CLI_PORT
    )

    log.info("Server started — agent port %d, CLI port %d", AGENT_PORT, CLI_PORT)

    async with agent_server, cli_server:
        await asyncio.gather(
            agent_server.serve_forever(),
            cli_server.serve_forever()
        )

if __name__ == "__main__":
    asyncio.run(main())