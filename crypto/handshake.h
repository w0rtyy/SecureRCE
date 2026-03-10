#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

// Size of the serielized EC Public Key (uncompressed P-256 Point)
// 1 byte prefix (0x04) + 32 bytes X + 32 Bytes Y = 65 Bytes 

#define EC_PUBKEY_LEN 65

// Opaque handle for an in-progress handshake 
// Holds the private key until derive_session_key() is called
typedef struct handshake_ctx handshake_ctx_t;

// Step 1: Generate an ephemeral EC key pair
// Returns a new context with private key stored inside
// Writes the public(EC_PUBKEY_LEN bytes) key into pubkey_out
// Caller must call handshake_ctx_free() when done
handshake_ctx_t *handshake_generate(unsigned char pubkey_out[EC_PUBKEY_LEN]);

// Step 2: Given the peer's public key derive the session key
// Uses ECDH + HKDF to produce KEY_LEN bytes written into session_key_out
// Free ctx internally
int handshake_derive(
    handshake_ctx_t *ctx,
    const unsigned char peer_pubkey[EC_PUBKEY_LEN],
    unsigned char session_key_out[32]               // KEY_LEN from crypto.h
);

void handshake_ctx_free(handshake_ctx_t *ctx);


#endif
