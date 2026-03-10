#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdlib.h>

#define AGENT_TOKEN_LEN 32
#define AGENT_ID_MAX 64

// MSG_HELLO into out_buf
// out_buf must be atleast (1 + id_len + AGENT_TOKEN_LEN) bytes
// Returns total length written or -1 on error
int auth_build_payload(const char *agent_id, const unsigned char token[AGENT_TOKEN_LEN], unsigned char *out_buf, size_t out_buf_size);

// Parse a received MSG_HELLO auth payload
// Write null terminated agent_id into id_out (Must be AGENT_ID_MAX bytes)
// Write token into token_out
// Return 0 on success, -1 on malformed payload
int auth_parse_payload(const unsigned char *payload, uint32_t payload_len, char id_out[AGENT_ID_MAX], unsigned char token_out[AGENT_TOKEN_LEN]);

#endif