#include "framing.h"
#include "protocol.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

// Helper function to write all bytes into the frame
// write() is allowed to have fewer bytes 
// This helper function guarentees delivery or failure
static int write_all(int fd, const void *buffer, size_t len){ 
    size_t total = 0;
    const unsigned char *p = buffer;

    while(total < len){
        ssize_t n = write(fd, p + total, len - total);
        if(n <= 0){
            return -1; // error or connection closed
        }
        total += n;
    }

    return 0;
}


// Helper function to read exact bytes from the frame
// To accomodate TCP partial reads 
// Prevents corrupted messages
static int read_exact(int fd, void *buffer, size_t len){
    size_t total = 0;
    unsigned char *p = (unsigned char *) buffer;

    while(total < len){
        ssize_t n = read(fd, p + total, len - total);
        if(n <= 0){
            return -1;  // error or EOF
        }
        total += (size_t)n; 
    }

    return 0;
}


// Sending a frame 
int send_frame(int fd, uint8_t type, const unsigned char* payload, uint32_t payload_len){
    assert(payload_len < UINT32_MAX);
    uint32_t len = payload_len + 1; // +1 for type
    
    uint32_t net_len = htonl(len);

    if(write_all(fd, &net_len, sizeof(net_len)) < 0) // length is sent first
        return -1;
    
    if(write_all(fd, &type, sizeof(type)) < 0) // type is sent seperatly
        return -1;
    
    if(payload_len > 0){                        // payload is opaque
        if(write_all(fd, payload, payload_len) < 0)
            return -1;
    }
    
    return 0;
}


// Receiving a frame
int recv_frame(int fd, uint8_t *type, unsigned char **payload, uint32_t *payload_len){
    uint32_t net_len;
    uint32_t len;

    if(read_exact(fd, &net_len, sizeof(net_len)) < 0)
        return -1;
    
    len = ntohl(net_len);
    if(len < 1 || len > MAX_FRAME_SIZE)
        return -1;

    if(read_exact(fd, type, sizeof(*type)) < 0)
        return -1;

    *payload_len = len - 1;
    *payload = NULL;

    if(*payload_len > 0){
        *payload = malloc(*payload_len);
        if(!*payload)
            return -1;  
        
        if(read_exact(fd, (void *)*payload, *payload_len) < 0){
            free(*payload);
            return -1;  
        }  
    }

    return 0;
}



// Test main function with encryption (not the main file just for testing purpose)
/*
#ifndef TEST_FRAMING

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "secure_channel.h"

#define MSG_HELLO 1

// Shared encryption key between server and agent
unsigned char shared_key[32];

void *agent_thread(void *arg) {
    int server_fd = *(int *)arg;
    
    // Accept connection from server
    int conn_fd = accept(server_fd, NULL, NULL);
    printf("[Agent] Connected to server\n");
    
    // Receive encrypted MSG_HELLO from server
    uint8_t type;
    unsigned char *payload;
    uint32_t payload_len;
    
    if (recv_secure(conn_fd, &type, &payload, &payload_len, shared_key) == 0) {
        printf("[Agent] Received encrypted frame with type: %d\n", type);
        if (payload_len > 0) {
            printf("[Agent] Decrypted payload: %.*s\n", payload_len, payload);
            free(payload);
        }
    } else {
        printf("[Agent] Failed to receive encrypted frame\n");
    }
    
    // Send encrypted MSG_HELLO back
    const unsigned char *msg = (unsigned char *)"Hello from agent (encrypted)";
    if (send_secure(conn_fd, MSG_HELLO, msg, strlen((char *)msg), shared_key) == 0) {
        printf("[Agent] Sent encrypted MSG_HELLO back\n");
    } else {
        printf("[Agent] Failed to send encrypted frame\n");
    }
    
    close(conn_fd);
    return NULL;
}

int main() {
    printf("=== Encrypted Framing Test ===\n\n");
    
    // Generate shared encryption key
    if (!RAND_bytes(shared_key, sizeof(shared_key))) {
        fprintf(stderr, "Failed to generate encryption key\n");
        return 1;
    }
    printf("[Setup] Generated 256-bit encryption key\n");
    
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 1);
    
    // Start agent thread
    pthread_t thread;
    pthread_create(&thread, NULL, agent_thread, &server_fd);
    
    sleep(1); // Give agent time to listen
    
    // Server connects to agent
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("[Server] Connected to agent\n");
    
    // Server sends encrypted MSG_HELLO
    const unsigned char *msg = (unsigned char *)"Hello from server (encrypted)";
    if (send_secure(client_fd, MSG_HELLO, msg, strlen((char *)msg), shared_key) == 0) {
        printf("[Server] Sent encrypted MSG_HELLO\n");
    } else {
        printf("[Server] Failed to send encrypted frame\n");
    }
    
    // Server receives encrypted MSG_HELLO back
    uint8_t type;
    unsigned char *payload;
    uint32_t payload_len;
    
    if (recv_secure(client_fd, &type, &payload, &payload_len, shared_key) == 0) {
        printf("[Server] Received encrypted frame with type: %d\n", type);
        if (payload_len > 0) {
            printf("[Server] Decrypted payload: %.*s\n", payload_len, payload);
            free(payload);
        }
    } else {
        printf("[Server] Failed to receive encrypted frame\n");
    }
    
    close(client_fd);
    pthread_join(thread, NULL);
    close(server_fd);
    
    printf("\n=== Test Complete ===\n");
    printf("Both parties successfully exchanged encrypted messages using AES-256-GCM\n");
    return 0;
}

#endif
*/