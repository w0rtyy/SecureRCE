#include "handshake.h"
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

// Opaque struct (Callers never see this)
struct handshake_ctx {
    EVP_PKEY *priv_key;     // Our ephemeral private key (P-256)
};

// Step 1: Generate ephemeral EC Keypair
handshake_ctx_t *handshake_generate(unsigned char pubkey_out[EC_PUBKEY_LEN]){
    handshake_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if(!ctx)
        return NULL;

    // Create a parameter generator for P-256 (prime256v1)
    // P-256 is the standard NSA suite B-Curve 
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx)
        goto error;

    if(EVP_PKEY_keygen_init(pctx) != 1)
        goto error_pctx;
    
    // Set the curve
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1)
        goto error_pctx;
        
    // Generate the key pair
    if(EVP_PKEY_keygen(pctx, &ctx->priv_key) != 1)
        goto error_pctx;
    
    EVP_PKEY_CTX_free(pctx);

    // Serialize the PUBLIC key to raw bytes (uncompressed point format)
    // Format: 0x04 | X (32 bytes) | Y (32 bytes) = 65 bytes
    // Public Key is shared, Priv key is never shared
    size_t pub_len = EC_PUBKEY_LEN;
    if(EVP_PKEY_get_raw_public_key(ctx->priv_key, NULL, &pub_len) != 1){
        // EVP_PKEY_get_raw_public_key doesn't work for EC keys the same way.
        // Use the lower-level EC_KEY API for serialization instead:
        const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(ctx->priv_key);
        if(!ec_key) 
            goto error;

        const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_key);
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);

        size_t len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pubkey_out, EC_PUBKEY_LEN, NULL);
        
        if(len != EC_PUBKEY_LEN)
            goto error;
    }   
    return ctx;

error_pctx:
    EVP_PKEY_CTX_free(pctx);
error:
    handshake_ctx_free(ctx);
    return NULL;
}

// Step 2: Derive session key from peer's public key
int handshake_derive(
    handshake_ctx_t *ctx,
    const unsigned char peer_pubkey[EC_PUBKEY_LEN],
    unsigned char session_key_out[32]
) {
    if (!ctx || !ctx->priv_key) return -1;

    int ret = -1;
    EC_KEY *peer_ec = NULL;
    EC_POINT *point = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    unsigned char *shared_secret = NULL;
    size_t secret_len = 0;

    // Deserialize peer's raw public key bytes back into an EVP_PKEY
    peer_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peer_ec) goto cleanup;

    const EC_GROUP *group = EC_KEY_get0_group(peer_ec);
    point = EC_POINT_new(group);
    if (!point) goto cleanup;

    // Parse the 0x04 | X | Y bytes into an actual EC_POINT
    if (EC_POINT_oct2point(group, point, peer_pubkey, EC_PUBKEY_LEN, NULL) != 1)
        goto cleanup;

    if (EC_KEY_set_public_key(peer_ec, point) != 1) goto cleanup;

    // Wrap EC_KEY into EVP_PKEY for the derive API
    peer_key = EVP_PKEY_new();
    if (!peer_key) 
        goto cleanup;
    if (EVP_PKEY_set1_EC_KEY(peer_key, peer_ec) != 1) 
        goto cleanup;

    // Perform ECDH: compute shared_secret = my_privkey * peer_pubkey
    derive_ctx = EVP_PKEY_CTX_new(ctx->priv_key, NULL);
    if (!derive_ctx) 
        goto cleanup;

    if (EVP_PKEY_derive_init(derive_ctx) != 1) goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_key) != 1) 
        goto cleanup;

    // First call: get the size of the shared secret
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) != 1) 
        goto cleanup;

    shared_secret = malloc(secret_len);
    if (!shared_secret) 
        goto cleanup;

    // Second call: actually compute it
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) != 1) 
        goto cleanup;
    
    // ADD:
    printf("[DEBUG] Shared secret (first 8 bytes): ");
    for (size_t i = 0; i < 8; i++) printf("%02x", shared_secret[i]);
    printf("\n");

    // Now run HKDF to stretch the raw shared secret into a proper AES key
    // HKDF(input_key_material, salt, info) → output_key
    // 
    // - salt:   optional, adds domain separation. We use a fixed string.
    // - info:   context label. Binds the key to its purpose.
    //           If you derived two keys (one for enc, one for MAC) they'd have
    //           different info strings and therefore be completely independent.

    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!hkdf_ctx) 
        goto cleanup;

    if (EVP_PKEY_derive_init(hkdf_ctx) != 1) 
        goto hkdf_cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) != 1) 
        goto hkdf_cleanup;

    // Salt: optional random value. Using a fixed label here for simplicity.
    // In production you'd exchange a random salt during the handshake too.
    const unsigned char salt[] = "rce-framework-v1-salt";
    if (EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, salt, sizeof(salt)-1) != 1)
        goto hkdf_cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret, secret_len) != 1)
        goto hkdf_cleanup;

    const unsigned char info[] = "session-key";
    if (EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, info, sizeof(info)-1) != 1)
        goto hkdf_cleanup;

    size_t key_len = 32; // KEY_LEN
    if (EVP_PKEY_derive(hkdf_ctx, session_key_out, &key_len) != 1)
        goto hkdf_cleanup;

    ret = 0; // success

hkdf_cleanup:
    EVP_PKEY_CTX_free(hkdf_ctx);
cleanup:
    if (shared_secret) {
        // Zero out the shared secret immediately — it should never sit in memory
        memset(shared_secret, 0, secret_len);
        free(shared_secret);
    }
    if (derive_ctx) 
        EVP_PKEY_CTX_free(derive_ctx);
    if (peer_key) 
        EVP_PKEY_free(peer_key);
    if (peer_ec) 
        EC_KEY_free(peer_ec);
    if (point) 
        EC_POINT_free(point);

    handshake_ctx_free(ctx); // private key is no longer needed
    return ret;
}

void handshake_ctx_free(handshake_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->priv_key) 
        EVP_PKEY_free(ctx->priv_key);
    free(ctx);
}
