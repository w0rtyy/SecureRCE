#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "../common/auth.h"
#include "../common/framing.h"
#include "../common/handshake_wire.h"
#include "../common/secure_channel.h"
#include "../common/protocol.h"

// ─── Agent Configuration ───

#define SERVER_HOST     "127.0.0.1"
#define SERVER_PORT     9001
#define AGENT_ID        "agent-001"        // Must match the agent_id (KNOWN_AGENTS) in server.py (32 bytes)

static const unsigned char AGENT_TOKEN[AGENT_TOKEN_LEN] = {0};

#define RECONNET_DELAY_SEC 5
#define OUTPUT_CHUNK_SIZE 1024

// ─── Payload Helpers ───

/*
    - MSG_JOB_ASSIGN payload format:
        [job_id_len : 1 byte] [job_id : N bytes] [command string]

    - MSG_JOB_OUTPUT payload format:
        [job_id_len : 1 byte] [job_id : N bytes] [output chunk]

    - MSG_JOB_EXIT payload format:
        [job_id_len : 1 byte] [job_id : N bytes] [exit_code : 4 bytes big-endian]
*/

static int parse_job_assign(
    const unsigned char *payload, uint32_t payload_len, char job_id_out[64], char cmd_out[MAX_PAYLOAD]
){
    if(payload_len < 2)
        return -1;
    uint8_t id_len = payload[0];
    if(id_len == 0 || (uint32_t)(1 + id_len) >= payload_len)
        return -1;
    
    memcpy(job_id_out, payload + 1, id_len);
    job_id_out[id_len] = '\0';

    uint32_t cmd_len = payload_len - 1 - id_len;
    if(cmd_len >= MAX_PAYLOAD)
        return -1;
    
    memcpy(cmd_out, payload + 1 + id_len, cmd_len);
    cmd_out[cmd_len] = '\0';

    return 0;
}

// A MSG_JOB_OUTPUT or MSG_JOB_EXIT payload header into out.
// Returns number of header bytes written
static int build_job_header(const char *job_id, unsigned char *out, size_t out_size){
    size_t id_len = strlen(job_id);
    if(id_len == 0 || id_len > 63 || out_size < 1 + id_len)
        return -1;
    out[0] = (uint8_t)id_len;
    memcpy(out + 1, job_id, id_len);
    return (int)(1 + id_len);
}

// ─── Job Execution ───
/*
    execute_job() - the core of agent
    Runs `command` in a shell, captures stdout + stderr
    streams output back to the server in MSG_JOB_OUTPUT chunks
    sends MSG_JOB_EXIT when done

    Using `/bin/sh -c`, else we have to parse arguments. 
*/

static void execute_job(int fd, const unsigned char *session_key, const char *job_id, const char *command){
    printf("[Agent] Executing job %s: %s\n", job_id, command);

    // Create pipe (pipe_fd[0]: Read, pipe_fd[1]: Write)
    int pipe_fd[2];
    if(pipe(pipe_fd) < 0){
        perror("pipe");
        return;
    }

    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return;
    }

    if(pid == 0){
        // ─── Child Process ─── 
        // Redirect stdout & stderr to write end
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);

        // Execution of command
        execl("/bin/sh", "/bin/sh", "-c", command, NULL);
        perror("execl");
        _exit(127);                                         // exit() flush's parent's buffer, _exit() does not.
    }
    else {
        // ─── Parent Process ─── 
        close(pipe_fd[1]);

        // Prepare the header buffer: [id_len][job_id]
        unsigned char header[65];
        int hdr_len = build_job_header(job_id, header, sizeof(header));
        if(hdr_len < 0){
            close(pipe_fd[0]);
            return;
        }

        // Read the output in chucks and  stream to server
        unsigned char chunk[OUTPUT_CHUNK_SIZE];
        ssize_t n;

        while((n = read(pipe_fd[0], chunk, sizeof(chunk))) > 0){
            // MSG_JOB_OUTPUT payload: header + chunk
            size_t payload_len = hdr_len + n;
            unsigned char *payload = malloc(payload_len);
            if(!payload)
                break;
            
            memcpy(payload, header, hdr_len);
            memcpy(payload + hdr_len, chunk, n);

            send_secure(fd, MSG_JOB_OUTPUT, payload, (uint32_t)payload_len, session_key);
            free(payload);
        }
        
        close(pipe_fd[0]);

        // Wait for child. Get exit code
        int status;
        waitpid(pid, &status, 0);
        int exit_code =WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        // MSG_JOB_EXIT: header + 4 byte big-endian exit code
        size_t exit_payload_len = hdr_len + 4;
        unsigned char *exit_payload = malloc(exit_payload_len);
        if(exit_payload){
            memcpy(exit_payload, header, hdr_len);
            // Big-endian 4 byte exit code - matching server.py unpack(">I")
            exit_payload[hdr_len + 0] = (exit_code >> 24) & 0xFF;
            exit_payload[hdr_len + 1] = (exit_code >> 16) & 0xFF;
            exit_payload[hdr_len + 2] = (exit_code >>  8) & 0xFF;
            exit_payload[hdr_len + 3] = (exit_code      ) & 0xFF;

            send_secure(fd, MSG_JOB_EXIT, exit_payload, (uint32_t)exit_payload_len, session_key);
            free(exit_payload);
        } 

        printf("[Agent] Job %s exited with code %d\n", job_id, exit_code);
    }
} 

// ─── Connection loop ───
static int connect_to_server(void){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    if(inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr) <= 0){
        fprintf(stderr, "Invalid Server address\n");
        close(fd);
        return -1;
    }

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        close(fd);
        return -1;
    }

    return fd;
}

static int do_agent_session(int fd){
    unsigned char session_key[32];

    // ─── Handshake ───
    printf("[Agent] Performing handshake...\n");
    fflush(stdout);
    if(agent_handshake(fd, session_key) < 0){
        fprintf(stderr, "[Agent] Handshake Failed\n");
        return -1;
    }
    printf("[Agent] Handshake complete, session key derived \n");


    // ADD THIS - print the FULL 32-byte session key
    printf("[Agent] Session key (hex): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", session_key[i]);
    }
    printf("\n");
    fflush(stdout);
    // ─── Authentication ───
    unsigned char auth_buf[1 + 64 + AGENT_TOKEN_LEN];
    int auth_len = auth_build_payload(AGENT_ID, AGENT_TOKEN, auth_buf, sizeof(auth_buf));
    if(auth_len < 0){
        fprintf(stderr, "[Agent] Failed to build auth payload\n");
        return -1;
    }

    if(send_secure(fd, MSG_HELLO, auth_buf, (uint32_t)auth_len, session_key) < 0){
        fprintf(stderr, "[Agent] Failed to send auth\n");
        return -1;
    }

    // Waiting for MSG_AUTH_OK
    uint8_t type;
    unsigned char *resp = NULL;
    uint32_t resp_len = 0;

    if(recv_secure(fd, &type, &resp, &resp_len, session_key) < 0){
        fprintf(stderr, "[Agent] No auth repsonse\n");
        return -1;
    }
    free(resp);

    if(type != MSG_AUTH_OK){
        fprintf(stderr, "[Agent] Auth rejected by server\n");
        return -1;
    }
    printf("[Agent] Authenticated as %s\n", AGENT_ID);

    // ─── Job Loop ───
    printf("[Agent] Entering job loop\n");

    while(1){
        unsigned char *payload = NULL;
        uint32_t payload_len = 0;

        if(recv_secure(fd, &type, &payload, &payload_len, session_key) < 0){
            fprintf(stderr, "[Agent] Lost connection to server\n");
            free(payload);
            return -1;
        }

        if(type == MSG_JOB_ASSIGN){
            char job_id[64] = {0};
            char command[MAX_PAYLOAD] = {0};

            if(parse_job_assign(payload, payload_len, job_id, command) == 0){
                execute_job(fd, session_key, job_id, command);
            }else{
                fprintf(stderr, "[Agent] Malformed MSG_JOB_ASSIGN\n");
            }
        }else if(type == MSG_ERROR){
            fprintf(stderr, "[Agent] Error from server\n");
            free(payload);
            return -1;
        }
        // Any other unknown msg types ignore 

        free(payload);
    }
}

// ─── main() function ───
int main(void){
    // Ignoring SIGPIPES. Handling errors using return values not signal
    // Necessary as without SIGPIPES writing into closed sockets kills the process immediately 
    signal(SIGPIPE, SIG_IGN);

    printf("[Agent] Starting, Will connect to %s: %d\n", SERVER_HOST, SERVER_PORT);

    while(1){
        int fd = connect_to_server();
        if(fd < 0){
            printf("[Agent] Cannot reach server. Retrying in %d\n", RECONNET_DELAY_SEC);
            sleep(RECONNET_DELAY_SEC);
            continue;
        }

        printf("[Agent] Connected to server \n");
        do_agent_session(fd);                       // blocks until session ends
        close(fd);

        printf("[Agent] Session ended. Reconnecting in %d\n", RECONNET_DELAY_SEC);
        sleep(RECONNET_DELAY_SEC);
    }

    return 0;       // unreachable
}


