#include "auth.h"
#include <string.h>
#include <stdint.h>

int auth_build_payload(const char *agent_id, const unsigned char token[AGENT_TOKEN_LEN], unsigned char *out_buf, size_t out_buf_size){
    size_t id_len = strlen(agent_id);
    if(id_len == 0 || id_len > 255)
        return -1;
    
    size_t needed = 1 + id_len + AGENT_TOKEN_LEN;
    if(out_buf_size < needed)
        return -1;

    out_buf[0] = (uint8_t)id_len;
    memcpy(out_buf + 1, agent_id, id_len);
    memcpy(out_buf + 1 + id_len, token, AGENT_TOKEN_LEN);
    
    return (int)needed;
}

int auth_parse_payload(const unsigned char *payload, uint32_t payload_len, char id_out[AGENT_ID_MAX], unsigned char token_out[AGENT_TOKEN_LEN]){
    if(payload_len < 2 + AGENT_TOKEN_LEN)
        return -1;

    uint8_t id_len = payload[0];
    if(id_len == 0 || id_len >= AGENT_ID_MAX )
        return -1;
    if(payload_len < (uint32_t)(1 + id_len + AGENT_TOKEN_LEN))
        return -1;
    
    memcpy(id_out, payload + 1, id_len);
    id_out[id_len] = '\0';

    memcpy(token_out, payload + 1 + id_len, AGENT_TOKEN_LEN);
    return 0;
}