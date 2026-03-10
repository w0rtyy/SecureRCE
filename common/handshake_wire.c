#include "handshake_wire.h"
#include "protocol.h"
#include "framing.h"
#include "../crypto/handshake.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Server sends public key first
int server_handshake(int fd, unsigned char session_key_out[32]){
    unsigned char my_pubkey[EC_PUBKEY_LEN];

    // Generate ephemeral key pair
    handshake_ctx_t *ctx = handshake_generate(my_pubkey);
    if(!ctx)
        return -1;

    // Sending public key a raw MSG_HELLO
    if(send_frame(fd, MSG_HELLO, my_pubkey, EC_PUBKEY_LEN) < 0){
        handshake_ctx_free(ctx);
        return -1;
    }

    // Recieve peer public key
    uint8_t type;
    unsigned char *peer_pubkey = NULL;
    uint32_t peer_len = 0;

    if(recv_frame(fd, &type, &peer_pubkey, &peer_len) < 0)
        return -1;
    
    if(type != MSG_HELLO || peer_len != EC_PUBKEY_LEN){
        free(peer_pubkey);
        return -1;
    }

    // Derive session key 
    int ret = handshake_derive(ctx, peer_pubkey, session_key_out);
    free(peer_pubkey);
    return ret;
}

// Agent receives the server public key first, then sends 
int agent_handshake(int fd, unsigned char session_key_out[32]){
    // Recieve server's public key first
    uint8_t type;
    unsigned char *peer_pubkey = NULL;
    uint32_t peer_len = 0;

    if(recv_frame(fd, &type, &peer_pubkey, &peer_len) < 0){
        fprintf(stderr, "[Agent] Failed to receive server pubkey\n");
        return -1;
    }
    
    if(type != MSG_HELLO || peer_len != EC_PUBKEY_LEN)
        return -1;

    // Generate Agent's ephemeral key pair
    unsigned char my_pubkey[EC_PUBKEY_LEN];
    handshake_ctx_t *ctx = handshake_generate(my_pubkey);
    if(!ctx){
        fprintf(stderr, "[Agent] Failed to generate keypair\n");
        free(peer_pubkey);
        return -1;
    }

    // Send agent's public key
    if(send_frame(fd, MSG_HELLO, my_pubkey, EC_PUBKEY_LEN) < 0){
        handshake_ctx_free(ctx);
        fprintf(stderr, "[Agent] Failed to send pubkey\n");
        free(peer_pubkey);
        return -1;
    }

    int ret = handshake_derive(ctx, peer_pubkey, session_key_out);
    free(peer_pubkey);

    if (ret < 0) {
        fprintf(stderr, "[Agent] Failed to derive session key\n");
        return -1;
    }
    
    return ret;
}