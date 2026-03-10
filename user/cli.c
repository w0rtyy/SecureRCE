#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "../common/framing.h"
#include "../common/protocol.h"

#define SERVER_HOST "127.0.0.1"
#define CLI_PORT    9002
#define MAX_INPUT   4096

static int connect_to_cli_port(void){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CLI_PORT);
    inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr);

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static void print_usage(const char *prog){
    fprintf(stderr, "Usage: %s <agent_id>\n", prog);
    fprintf(stderr, "  Example: %s agent-001\n", prog);
    fprintf(stderr, "\nInteractive commands:\n");
    fprintf(stderr, "  <command>       - Execute command on agent\n");
    fprintf(stderr, "  exit            - Close connection and quit\n");
    fprintf(stderr, "  quit            - Close connection and quit\n");
}

static int send_job_request(int fd, const char *agent_id, const char *command){
    char json[MAX_PAYLOAD];
    int json_len = snprintf(json, sizeof(json), 
                           "{\"agent_id\":\"%s\",\"command\":\"%s\"}", 
                           agent_id, command);
    
    if(json_len <= 0 || json_len >= (int)sizeof(json)){
        fprintf(stderr, "[CLI] Command too long\n");
        return -1;
    }

    if(send_frame(fd, MSG_JOB_REQUEST, (unsigned char *)json, (uint32_t)json_len) < 0){
        fprintf(stderr, "[CLI] Failed to send job request\n");
        return -1;
    }

    return 0;
}

static int receive_job_output(int fd){
    while(1){
        uint8_t type;
        unsigned char *payload = NULL;
        uint32_t payload_len = 0;

        if(recv_frame(fd, &type, &payload, &payload_len) < 0){
            fprintf(stderr, "[CLI] Lost connection\n");
            return -1;
        }

        if(type == MSG_JOB_OUTPUT){
            if(payload_len < 1){
                free(payload);
                continue;
            }
            
            uint8_t id_len = payload[0];
            size_t output_start = 1 + id_len;
            
            if(output_start < payload_len){
                fwrite(payload + output_start, 1, payload_len - output_start, stdout);
                fflush(stdout);
            }
            
            free(payload);
        }
        else if(type == MSG_JOB_EXIT){
            // Payload: [id_len:1][job_id:N][exit_code:4]
            // Skip the job_id header and extract the exit code
            
            if(payload_len < 5){
                fprintf(stderr, "[CLI] Malformed MSG_JOB_EXIT payload\n");
                free(payload);
                break;
            }
            
            uint8_t id_len = payload[0];
            size_t exit_code_start = 1 + id_len;
            
            if(exit_code_start + 4 > payload_len){
                fprintf(stderr, "[CLI] Malformed MSG_JOB_EXIT: not enough bytes\n");
                free(payload);
                break;
            }
            
            // Extract 4-byte big-endian exit code
            int exit_code = (payload[exit_code_start + 0] << 24) | 
                            (payload[exit_code_start + 1] << 16) | 
                            (payload[exit_code_start + 2] << 8) | 
                            (payload[exit_code_start + 3]);
            
            printf("\n[Exit code: %d]\n", exit_code);
            free(payload);
            break;
        }
        else if(type == MSG_ERROR){    
            fprintf(stderr, "[CLI Error] %.*s\n", (int)payload_len, payload);
            free(payload);
            return -1;
        }
        else{
            fprintf(stderr, "[CLI] Unexpected message type: %d\n", type);
            free(payload);
        }
    }

    return 0;
}

int main(int argc, char *argv[]){
    if(argc < 2){
        print_usage(argv[0]);
        return 1;
    }

    const char *agent_id = argv[1];

    printf("[CLI] Connecting to server at %s:%d...\n", SERVER_HOST, CLI_PORT);
    int fd = connect_to_cli_port();
    if(fd < 0){
        fprintf(stderr, "[CLI] Cannot connect to server CLI port %d\n", CLI_PORT);
        fprintf(stderr, "[CLI] Make sure the server is running.\n");
        return 1;
    }

    printf("[CLI] Connected to server\n");
    printf("[CLI] Agent: %s\n", agent_id);
    printf("════════════════════════════════════════\n");
    printf("Type commands to execute on agent.\n");
    printf("Type 'exit' or 'quit' to disconnect.\n");
    printf("════════════════════════════════════════\n\n");

    char input[MAX_INPUT];
    while(1){
        printf("%s> ", agent_id);
        fflush(stdout);

        if(!fgets(input, sizeof(input), stdin)){
            printf("\n");
            break;
        }

        size_t len = strlen(input);
        if(len > 0 && input[len-1] == '\n'){
            input[len-1] = '\0';
            len--;
        }

        if(len == 0){
            continue;
        }

        if(strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0){
            printf("[CLI] Disconnecting...\n");
            break;
        }

        if(send_job_request(fd, agent_id, input) < 0){
            fprintf(stderr, "[CLI] Failed to send command\n");
            break;
        }

        if(receive_job_output(fd) < 0){
            fprintf(stderr, "[CLI] Connection error\n");
            break;
        }

        printf("\n");
    }

    close(fd);
    printf("[CLI] Connection closed\n");
    return 0;
}