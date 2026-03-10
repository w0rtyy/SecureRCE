#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/select.h>

#include "../common/framing.h"
#include "../common/secure_channel.h"
#include "../common/auth.h"
#include "../common/protocol.h"
#include "../common/handshake_wire.h"

// ─── Configuaration ───
#define SERVER_HOST             "127.0.0.1"
#define SERVER_PORT             9001
#define AGENT_ID                "agent-002"
#define RECONNECT_DELAY_SEC     5

static const unsigned char AGENT_TOKEN[AGENT_TOKEN_LEN] = {0};

// ───  Persistent Shell Structure ───
typedef struct {
    pid_t pid;                  // Process ID of bash shell
    int stdin_fd;               // File Descriptor to write commands TO bash
    int stdout_fd;              // File Descriptor to read command FROM bash
    int stderr_fd;              // File Descriptor to read errors FROM bash
    char marker[64];            // Unique string to detect command completion
} persistent_shell_t;

// ─── Job Tracking ───
typedef struct {
    char job_id[64];            // Identifies the Job
    char *output_buffer;        // Accumulates the output 
    size_t output_size;         // Accumulates the bytes of output
    size_t output_capacity;     // Size of allocated buffer
    int exit_code;              // Command's exit status
} shell_job_t;

static persistent_shell_t *global_shell = NULL;     // Persistent shell
static shell_job_t *current_job = NULL;             // Currently Running job

// ─── Helper functions ───
static int build_job_header(const char *job_id, unsigned char *out, size_t out_size) {
    size_t id_len = strlen(job_id);
    if(id_len == 0 || id_len > 63 || out_size < 1 + id_len)
        return -1;
    out[0] = (uint8_t)id_len;
    memcpy(out + 1, job_id, id_len);
    return (int)(1 + id_len);
}

static int parse_job_assign(const unsigned char *payload, uint32_t payload_len, char job_id_out[64], char cmd_out[MAX_PAYLOAD]) {
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

static void append_to_buffer(char **buffer, size_t *size, size_t *capacity, const char *data, size_t len) {
    // BUG FIX: Was using (*capacity) + 2, should multiply by 2 for proper exponential growth
    if(*size + len >= *capacity){
        *capacity = (*capacity) * 2 + len;  // Double capacity + new data size
        *buffer = realloc(*buffer, *capacity);
    }
    if(*buffer){
        memcpy(*buffer + *size, data, len);
        *size += len;
    }
}

// ─── Persistence Shell Management ───
static persistent_shell_t *start_persistent_shell(void) {
    persistent_shell_t *shell = calloc(1, sizeof(*shell));
    if(!shell)
        return NULL;

    int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
    if(pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0){
        perror("pipe");
        free(shell);
        return NULL;
    } 

    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
        close(stdin_pipe[0]); close(stdin_pipe[1]);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        free(shell);
        return NULL;
    }

    if(pid == 0){
        // ─── Child: Bash Shell ─── 
        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);

        close(stdin_pipe[0]); close(stdin_pipe[1]);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);

        execl("/bin/bash", "bash", "--norc", "--noprofile", NULL);
        perror("execl bash");
        _exit(127);
    }

    // ─── Parent: Agent ─── 
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    shell->pid = pid;
    shell->stdin_fd = stdin_pipe[1];
    shell->stdout_fd = stdout_pipe[0];
    shell->stderr_fd = stderr_pipe[0];

    // Make stdout/stderr non-blocking
    int flags = fcntl(shell->stdout_fd, F_GETFL, 0);
    fcntl(shell->stdout_fd, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(shell->stderr_fd, F_GETFL, 0);
    fcntl(shell->stderr_fd, F_SETFL, flags | O_NONBLOCK);

    // Generate unique marker
    snprintf(shell->marker, sizeof(shell->marker), "__CMDEND_%d__", pid);

    printf("[Agent] Started persistent shell (PID %d)\n", pid);

    // Disable prompt
    const char *setup_cmds = 
        "PS1=''\n"
        "PS2=''\n"
        "set +o histexpand\n";
    write(shell->stdin_fd, setup_cmds, strlen(setup_cmds));

    // Drain startup output
    usleep(200000);         // 200ms
    char drain[4096];
    for(int i = 0; i < 3; i++){  // Drain multiple times
        while(read(shell->stdout_fd, drain, sizeof(drain)) > 0);
        while(read(shell->stderr_fd, drain, sizeof(drain)) > 0);
        usleep(50000);  // 50ms between drains
    }

    return shell;
}

static void stop_persistent_shell(persistent_shell_t *shell) {
    if(!shell)
        return;

    kill(shell->pid, SIGTERM);
    waitpid(shell->pid, NULL, 0);

    close(shell->stdin_fd);
    close(shell->stdout_fd);
    close(shell->stderr_fd);
    free(shell);
}

// ─── Execute Command in Shell ───
static void execute_in_shell(const char *job_id, const char *command) {
    if(!global_shell){
        fprintf(stderr, "[Agent] No persistent shell available\n");
        return;
    }

    if(current_job){
        fprintf(stderr, "[Agent] Shell busy with job %s, rejecting %s\n", 
                current_job->job_id, job_id);
        return;
    }

    // Create job
    current_job = calloc(1, sizeof(shell_job_t));
    if(!current_job)
        return;

    strncpy(current_job->job_id, job_id, sizeof(current_job->job_id) - 1);
    current_job->output_capacity = 4096;
    current_job->output_buffer = malloc(current_job->output_capacity);
    current_job->output_size = 0;
    current_job->exit_code = -1;

    printf("[Agent] Executing: %s\n", command);

    // Send command
    write(global_shell->stdin_fd, command, strlen(command));
    write(global_shell->stdin_fd, "\n", 1);

    // Send marker
    char marker_line[128];
    snprintf(marker_line, sizeof(marker_line), "echo %s\n", global_shell->marker);
    write(global_shell->stdin_fd, marker_line, strlen(marker_line));
    
    // Capture exit code
    write(global_shell->stdin_fd, "echo EXITCODE:$?\n", 17);
}

// ─── Read Shell Output ─── 
static void read_shell_output(int server_fd, const unsigned char *session_key) {
    if(!current_job || !global_shell)
        return;

    char chunk[1024];
    ssize_t n;

    // Read stdout
    while((n = read(global_shell->stdout_fd, chunk, sizeof(chunk))) > 0){
        append_to_buffer(&current_job->output_buffer, 
                         &current_job->output_size, 
                         &current_job->output_capacity, 
                         chunk, n);
    }
    
    // Read stderr
    while((n = read(global_shell->stderr_fd, chunk, sizeof(chunk))) > 0){
        append_to_buffer(&current_job->output_buffer, 
                         &current_job->output_size, 
                         &current_job->output_capacity, 
                         chunk, n);
    }

    // Check for completion
    if(current_job->output_size == 0)
        return;
        
    // Null-terminate for string search
    // BUG FIX: Was checking output_size > capacity, should be >=
    if(current_job->output_size >= current_job->output_capacity){
        current_job->output_capacity++;
        current_job->output_buffer = realloc(current_job->output_buffer, 
                                             current_job->output_capacity);
    }
    current_job->output_buffer[current_job->output_size] = '\0';

    // Look for marker
    char *marker_pos = strstr(current_job->output_buffer, global_shell->marker);
    if(!marker_pos)
        return;  // Command not finished yet
    // Command complete!
    
    // Extract exit code
    int exit_code = 0;
    char *exitcode_pos = strstr(marker_pos, "EXITCODE:");
    if(exitcode_pos)
        exit_code = atoi(exitcode_pos + 9);

    // Calculate output length (everything before marker)
    size_t output_len = marker_pos - current_job->output_buffer;

    // Trim trailing whitespace before marker
    while(output_len > 0 && 
          (current_job->output_buffer[output_len - 1] == '\n' || 
           current_job->output_buffer[output_len - 1] == '\r' ||
           current_job->output_buffer[output_len - 1] == ' ')){
        output_len--;
    }

    // Send output if any
    if(output_len > 0){
        unsigned char header[65];
        int hdr_len = build_job_header(current_job->job_id, header, sizeof(header));

        if(hdr_len >= 0){  // BUG FIX: Was checking > 0, should be >= 0
            size_t payload_len = hdr_len + output_len;
            unsigned char *payload = malloc(payload_len);
            if(payload){
                memcpy(payload, header, hdr_len);
                memcpy(payload + hdr_len, current_job->output_buffer, output_len);

                send_secure(server_fd, MSG_JOB_OUTPUT, payload, 
                           (uint32_t)payload_len, session_key);
                printf("[DEBUG] MSG_JOB_OUTPUT sent\n");
                free(payload);
            }
        }
    }

    // Send exit code
    unsigned char header[65];
    int hdr_len = build_job_header(current_job->job_id, header, sizeof(header));

    if(hdr_len >= 0){  // BUG FIX: Was checking > 0, should be >= 0
        size_t exit_payload_len = hdr_len + 4;
        unsigned char *exit_payload = malloc(exit_payload_len);
        if(exit_payload){
            memcpy(exit_payload, header, hdr_len);
            exit_payload[hdr_len + 0] = (exit_code >> 24) & 0xFF;
            exit_payload[hdr_len + 1] = (exit_code >> 16) & 0xFF;
            exit_payload[hdr_len + 2] = (exit_code >>  8) & 0xFF;
            exit_payload[hdr_len + 3] = (exit_code      ) & 0xFF;

            send_secure(server_fd, MSG_JOB_EXIT, exit_payload, 
                       (uint32_t)exit_payload_len, session_key);
            free(exit_payload);
        }
    }

    printf("[Agent] Job %s complete, exit code %d\n", current_job->job_id, exit_code);

    // Clean up job - this is the ONLY place where current_job should be freed
    free(current_job->output_buffer);
    free(current_job);
    current_job = NULL;
}

// ─── Main Agent Session ─── 
static int do_agent_session(int fd) {
    unsigned char session_key[32];

    // Handshake
    printf("[Agent] Performing handshake...\n");
    if(agent_handshake(fd, session_key) < 0){
        fprintf(stderr, "[Agent] Handshake failed\n");
        return -1;
    } 
    printf("[Agent] Handshake complete\n");

    // Authentication
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

    uint8_t type;
    unsigned char *resp = NULL;
    uint32_t resp_len = 0;
    
    if(recv_secure(fd, &type, &resp, &resp_len, session_key) < 0){
        fprintf(stderr, "[Agent] No auth response\n");
        return -1;
    }
    free(resp);

    if(type != MSG_AUTH_OK){
        fprintf(stderr, "[Agent] Auth rejected by server\n");
        return -1;
    }
    printf("[Agent] Authenticated as %s\n", AGENT_ID);

    // Start persistent shell
    global_shell = start_persistent_shell();
    if(!global_shell){
        fprintf(stderr, "[Agent] Failed to start persistent shell\n");
        return -1;
    }

    printf("[Agent] Entering job loop (persistent shell mode)\n");
    printf("[Agent] Commands like 'cd' will now persist across executions\n");

    // Main loop
    while(1){
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);

        int max_fd = fd;

        if(global_shell){
            FD_SET(global_shell->stdout_fd, &read_fds);
            FD_SET(global_shell->stderr_fd, &read_fds);

            if(global_shell->stdout_fd > max_fd)
                max_fd = global_shell->stdout_fd;
            if(global_shell->stderr_fd > max_fd)
                max_fd = global_shell->stderr_fd;
        }

        struct timeval timeout = {1, 0};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if(activity < 0){
            if(errno == EINTR)
                continue;
            perror("select");
            break;
        }

        // Check server socket
        if(FD_ISSET(fd, &read_fds)){
            unsigned char *payload = NULL;
            uint32_t payload_len = 0;

            if(recv_secure(fd, &type, &payload, &payload_len, session_key) < 0){
                fprintf(stderr, "[Agent] Lost connection to server\n");
                free(payload);
                break;
            }

            if(type == MSG_JOB_ASSIGN){
                char job_id[64] = {0};
                char command[MAX_PAYLOAD] = {0};

                if(parse_job_assign(payload, payload_len, job_id, command) == 0){
                    execute_in_shell(job_id, command);
                }else{
                    fprintf(stderr, "[Agent] Malformed MSG_JOB_ASSIGN\n");
                }
            }else if(type == MSG_ERROR){
                fprintf(stderr, "[Agent] Error from server\n");
                free(payload);
                break;
            }

            free(payload);
        }

        // Check shell output
        if(global_shell && (FD_ISSET(global_shell->stdout_fd, &read_fds) || 
                            FD_ISSET(global_shell->stderr_fd, &read_fds))){
            read_shell_output(fd, session_key);
        }
    }

    // Cleanup
    if(current_job){
        free(current_job->output_buffer);
        free(current_job);
        current_job = NULL;
    }

    if(global_shell){
        stop_persistent_shell(global_shell);
        global_shell = NULL;
    }

    return 0;
}

// ─── Connection Management ───  
static int connect_to_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    if(inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr) <= 0){
        fprintf(stderr, "Invalid server address\n");
        close(fd);
        return -1;
    }

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        close(fd);
        return -1;
    }

    return fd;
}

// ─── Main ─── 

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    printf("[Agent] Starting with persistent shell support\n");
    printf("[Agent] Will connect to %s:%d\n", SERVER_HOST, SERVER_PORT);

    while(1){
        int fd = connect_to_server();
        if(fd < 0){
            printf("[Agent] Cannot reach server. Retrying in %ds...\n", 
                   RECONNECT_DELAY_SEC);
            sleep(RECONNECT_DELAY_SEC);
            continue;
        }

        printf("[Agent] Connected to server\n");
        do_agent_session(fd);
        close(fd);

        printf("[Agent] Session ended. Reconnecting in %ds...\n", 
               RECONNECT_DELAY_SEC);
        sleep(RECONNECT_DELAY_SEC);
    }

    return 0;
}