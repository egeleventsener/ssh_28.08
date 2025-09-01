#include "delete_directory.h"
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <pthread.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef ssh_channel client_t;
static void handle_client(client_t client, struct sockaddr_in client_addr);

struct client_ctx {
    ssh_session s;
    ssh_channel ch;
    struct sockaddr_in addr;
};

static void* client_main(void *arg){
    struct client_ctx *ctx = (struct client_ctx*)arg;
    handle_client(ctx->ch, ctx->addr);

    ssh_channel_send_eof(ctx->ch);
    ssh_channel_close(ctx->ch);
    ssh_channel_free(ctx->ch);
    ssh_disconnect(ctx->s);
    ssh_free(ctx->s);
    free(ctx);
    return NULL;
}

static inline ssize_t io_read(client_t ch, void *buf, size_t n){ 
    return ssh_channel_read(ch, buf, n, 0); 
}

static inline ssize_t io_write(client_t ch, const void *buf, size_t n){ 
    return ssh_channel_write(ch, buf, n); 
}

static void io_dprintf(client_t ch, const char *fmt, ...){
    char tmp[8192]; 
    va_list ap; 
    va_start(ap, fmt);
    int k = vsnprintf(tmp, sizeof tmp, fmt, ap); 
    va_end(ap);
    if(k > 0) ssh_channel_write(ch, tmp, (size_t)k);
}

static void drain_n(client_t c, long long n){
    char b[4096];
    while(n > 0){
        size_t want = (size_t)(n > (long long)sizeof(b) ? sizeof(b) : n);
        ssize_t r = io_read(c, b, want);
        if(r <= 0) break;
        n -= r;
    }
}

static char BASE_DIR[PATH_MAX] = {0};
static char START_DIR[PATH_MAX] = {0};

// Signal handler to clean up zombie processes
static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        // Clean up zombies
    }
}

static int starts_with(const char* s, const char* p) {
    return strncmp(s, p, strlen(p)) == 0;
}

// Check if path is within our allowed base directory
static int secure_path_in_base(const char* path) {
    char canon[PATH_MAX];
    if (!realpath(path, canon)) return 0;
    size_t b = strlen(BASE_DIR);
    return (strncmp(canon, BASE_DIR, b) == 0) && (canon[b] == '/' || canon[b] == '\0');
}

// Check if parent directory is within base and create intermediate dirs if needed
static int validate_and_prepare_path(const char* path, char* resolved_path, size_t resolved_size) {
    char temp_path[PATH_MAX];
    strncpy(temp_path, path, sizeof(temp_path));
    temp_path[sizeof(temp_path)-1] = '\0';
    
    /* If path is relative, make it absolute */
    if (temp_path[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return 0;
        snprintf(resolved_path, resolved_size, "%s/%s", cwd, temp_path);
    } else {
        snprintf(resolved_path, resolved_size, "%s%s", BASE_DIR, temp_path);
    }
    
    /* Create parent directories if they don't exist */
    char parent[PATH_MAX];
    strncpy(parent, resolved_path, sizeof(parent));
    parent[sizeof(parent)-1] = '\0';
    
    char *last_slash = strrchr(parent, '/');
    if (last_slash && last_slash != parent) {
        *last_slash = '\0';
        
        /* Check if parent exists, create if not */
        struct stat st;
        if (stat(parent, &st) != 0) {
            char mkdir_cmd[PATH_MAX + 20];
            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\"", parent);
            if (system(mkdir_cmd) != 0) {
                return 0; /* Failed to create parent dirs */
            }
        }
    }
    
    return 1; /* Path is safe and parent dirs exist */
}

// Secure directory change
static int secure_cd(const char *target) {
    if (!target || !*target) return -1;
    
    char tmp[PATH_MAX];
    if (target[0] == '/') {
        /* Absolute path relative to BASE_DIR */
        snprintf(tmp, sizeof(tmp), "%s%s", BASE_DIR, target);
    } else {
        /* Relative path */
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return -1;
        snprintf(tmp, sizeof(tmp), "%s/%s", cwd, target);
    }

    char resolved[PATH_MAX];
    if (!realpath(tmp, resolved)) return -1;
    if (!secure_path_in_base(resolved)) return -1;
    return chdir(resolved);
}

// Send string to client
static void send_str(client_t c, const char *s){ 
    io_write(c, s, strlen(s)); 
}

// Receive line from client (end on \r or \n, no echo)
static int recv_line(client_t c, char *buf, size_t bufsz){
    size_t u = 0;
    for(;;){
        char ch;
        ssize_t r = io_read(c, &ch, 1);
        if(r <= 0) return -1;

        if(ch == '\r' || ch == '\n'){
            if(u < bufsz) buf[u] = '\0';
            return (int)u;
        }
        if(ch == 0x7f || ch == 0x08){   // backspace
            if(u > 0) u--;
            continue;
        }
        if(u + 1 < bufsz) buf[u++] = ch;
    }
}

// Receive exactly N bytes and save to file - FIXED VERSION
static int recv_n_to_file(client_t c, const char* fname, long long nbytes) {
    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s' for writing: %s\n", fname, strerror(errno));
        drain_n(c, nbytes);
        return -1;
    }

    char buf[4096];
    long long remaining = nbytes;
    long long received = 0;
    
    printf("[Session] Receiving %lld bytes to file '%s'\n", nbytes, fname);

    while (remaining > 0) {
        size_t want = (size_t)(remaining > (long long)sizeof(buf) ? sizeof(buf) : remaining);
        ssize_t got = io_read(c, buf, want);
        
        if (got <= 0) {
            fprintf(stderr, "Error: Premature end of data stream (got %lld of %lld bytes)\n", 
                    received, nbytes);
            fclose(fp);
            unlink(fname);
            return -1;
        }
        
        if (fwrite(buf, 1, (size_t)got, fp) != (size_t)got) {
            fprintf(stderr, "Error writing to file: %s\n", strerror(errno));
            fclose(fp);
            unlink(fname);
            drain_n(c, remaining - got);
            return -1;
        }
        
        remaining -= got;
        received += got;
        
        /* Progress for large files */
        if (nbytes > 1024*1024 && (received % (nbytes/10)) < got) {
            printf("[Session] Progress: %lld/%lld bytes (%.1f%%)\n", 
                   received, nbytes, (double)received*100/nbytes);
        }
    }
    
    fclose(fp);
    printf("[Session] File '%s' received successfully (%lld bytes)\n", fname, nbytes);
    return 0;
}

// Handle individual commands from client
static void handle_command(client_t client, char *cmdline) {
    printf("[Session] Executing: '%s'\n", cmdline);

    // spwd - show current working directory
    if (strcmp(cmdline, "spwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd))) {
            if (starts_with(cwd, BASE_DIR)) {
                const char *rel = cwd + strlen(BASE_DIR);
                if (*rel == '\0') rel = "/";
                io_dprintf(client, "Remote directory: %s\n", rel);
            } else {
                io_dprintf(client, "Remote directory: %s\n", cwd);
            }
        } else {
            send_str(client, "Error: Failed to get current directory\n");
        }
        send_str(client, "> ");
        return;
    }

    // scd <dir> - change directory
    if (strncmp(cmdline, "scd ", 4) == 0) {
        const char *target_dir = cmdline + 4;
        if (secure_cd(target_dir) == 0) {
            send_str(client, "Directory changed successfully\n");
        } else {
            send_str(client, "Error: Failed to change directory (access denied or not found)\n");
        }
        send_str(client, "> ");
        return;
    }

    // sls - list directory contents
    if (strcmp(cmdline, "sls") == 0) {
        DIR *dir = opendir(".");
        if (!dir) {
            send_str(client, "Error: Cannot open directory\n");
            send_str(client, "> ");
            return;
        }
        
        struct dirent *entry; 
        int file_count = 0;
        send_str(client, "Remote directory contents:\n");
        
        while ((entry = readdir(dir))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            
            /* Get file info for better listing */
            struct stat st;
            char type_char = '?';
            if (stat(entry->d_name, &st) == 0) {
                if (S_ISDIR(st.st_mode)) type_char = 'd';
                else if (S_ISREG(st.st_mode)) type_char = 'f';
                else if (S_ISLNK(st.st_mode)) type_char = 'l';
            }
            
            io_dprintf(client, "  %c %s\n", type_char, entry->d_name);
            file_count++;
        }
        closedir(dir);
        
        if (file_count == 0) {
            send_str(client, "  (directory is empty)\n");
        }
        send_str(client, "> ");
        return;
    }

    // smkdir <name> - create directory
    if (strncmp(cmdline, "smkdir ", 7) == 0) {
        const char *dir_name = cmdline + 7;
        if (mkdir(dir_name, 0755) == 0) {
            io_dprintf(client, "Directory '%s' created successfully\n", dir_name);
        } else {
            io_dprintf(client, "Error: Failed to create directory '%s': %s\n", 
                      dir_name, strerror(errno));
        }
        send_str(client, "> ");
        return;
    }

    // srm <path> - remove file or directory
    if (strncmp(cmdline, "srm ", 4) == 0) {
        const char *target_path = cmdline + 4;
        char canon[PATH_MAX];
        
        if (!realpath(target_path, canon)) {
            io_dprintf(client, "Error: Path '%s' not found\n", target_path);
            send_str(client, "> ");
            return;
        }
        
        if (!secure_path_in_base(canon)) {
            send_str(client, "Error: Access denied - path outside allowed area\n");
            send_str(client, "> ");
            return;
        }
        
        if (delete_directory(canon) == 0) {
            io_dprintf(client, "Successfully deleted '%s'\n", target_path);
        } else {
            io_dprintf(client, "Error: Failed to delete '%s': %s\n", 
                      target_path, strerror(errno));
        }
        send_str(client, "> ");
        return;
    }

    // srename <old> <new> - rename file or directory  
    if (strncmp(cmdline, "srename ", 8) == 0) {
        char tmp[PATH_MAX * 2 + 16];
        strncpy(tmp, cmdline + 8, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        
        char *old_name = strtok(tmp, " \t\r\n");
        char *new_name = strtok(NULL, " \t\r\n");
        
        if (!old_name || !new_name) {
            send_str(client, "Error: Invalid rename command format. Usage: srename <old> <new>\n");
            send_str(client, "> ");
            return;
        }

        /* For rename, we only need to check that old exists and both paths are safe */
        char old_canon[PATH_MAX];
        if (!realpath(old_name, old_canon)) {
            io_dprintf(client, "Error: Source '%s' not found\n", old_name);
            send_str(client, "> ");
            return;
        }
        
        if (!secure_path_in_base(old_canon)) {
            send_str(client, "Error: Access denied - source path outside allowed area\n");
            send_str(client, "> ");
            return;
        }

        /* For target, construct absolute path but don't require it to exist yet */
        char new_abs[PATH_MAX];
        if (new_name[0] == '/') {
            snprintf(new_abs, sizeof(new_abs), "%s%s", BASE_DIR, new_name);
        } else {
            char cwd[PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd))) {
                send_str(client, "Error: Cannot determine current directory\n");
                send_str(client, "> ");
                return;
            }
            snprintf(new_abs, sizeof(new_abs), "%s/%s", cwd, new_name);
        }

        /* Check that target path would be within base (without requiring existence) */
        char *temp_dir = strdup(new_abs);
        char *last_slash = strrchr(temp_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            char parent_canon[PATH_MAX];
            int parent_ok = (realpath(temp_dir, parent_canon) != NULL && 
                           secure_path_in_base(parent_canon));
            free(temp_dir);
            if (!parent_ok) {
                send_str(client, "Error: Access denied - target path outside allowed area\n");
                send_str(client, "> ");
                return;
            }
        } else {
            free(temp_dir);
        }

        if (rename(old_canon, new_abs) == 0) {
            io_dprintf(client, "Successfully renamed '%s' -> '%s'\n", old_name, new_name);
        } else {
            io_dprintf(client, "Error: Rename failed: %s\n", strerror(errno));
        }
        send_str(client, "> ");
        return;
    }

    // write_file - receive file from client
    if (strcmp(cmdline, "write_file") == 0) {
        char path[PATH_MAX];
        if (recv_line(client, path, sizeof(path)) < 0 || path[0] == '\0') {
            send_str(client, "Error: Could not receive filename\n");
            send_str(client, "> ");
            return;
        }

        char size_line[128];
        if (recv_line(client, size_line, sizeof(size_line)) < 0) {
            send_str(client, "Error: Could not receive file size\n");
            send_str(client, "> ");
            return;
        }

        long long nbytes = -1;
        if (sscanf(size_line, "SIZE %lld", &nbytes) != 1 || nbytes < 0) {
            send_str(client, "Error: Invalid file size format\n");
            send_str(client, "> ");
            return;
        }

        printf("[Session] File upload request: '%s' (%lld bytes)\n", path, nbytes);

        /* FIXED: Validate and prepare the full path */
        char resolved_path[PATH_MAX];
        if (!validate_and_prepare_path(path, resolved_path, sizeof(resolved_path))) {
            drain_n(client, nbytes);
            send_str(client, "Error: Access denied or invalid path\n");
            send_str(client, "> ");
            return;
        }

        /* Handle zero-byte files */
        if (nbytes == 0) {
            FILE *fp = fopen(resolved_path, "wb");
            if (!fp) {
                io_dprintf(client, "Error: Cannot create file '%s': %s\n", 
                          path, strerror(errno));
                send_str(client, "> ");
                return;
            }
            fclose(fp);
            io_dprintf(client, "File '%s' uploaded successfully (0 bytes)\n", path);
            send_str(client, "> ");
            return;
        }

        /* Receive file content */
        if (recv_n_to_file(client, resolved_path, nbytes) == 0) {
            io_dprintf(client, "File '%s' uploaded successfully (%lld bytes)\n", path, nbytes);
        } else {
            send_str(client, "Error: File upload failed\n");
        }
        send_str(client, "> ");
        return;
    }

    // Unknown command
    io_dprintf(client, "Error: Unknown command '%s'\n", cmdline);
    send_str(client, "Available commands: spwd, sls, scd, smkdir, srename, srm, write_file, exit\n");
    send_str(client, "> ");
}

// Handle a single client connection
static void handle_client(client_t client, struct sockaddr_in client_addr) {
    printf("[Session] New client connected from %s:%d (thread %lu)\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
           (unsigned long)pthread_self());

    /* Start in base directory for each client */
    if (chdir(BASE_DIR) != 0) {
        perror("chdir to base directory");
        send_str(client, "Server error: cannot access base directory\n");
        return;
    }

    /* Send welcome banner */
    send_str(client,
        "=== SSH File Server ===\n"
        "Connected successfully. Available commands:\n"
        "  spwd, sls, scd <dir>, smkdir <dir>, srename <old> <new>, srm <path>\n"
        "  write_file (use client's send_file command)\n"
        "  exit - disconnect\n\n");
    send_str(client, "> ");

    char command_line[2048];
    for (;;) {
        int result = recv_line(client, command_line, sizeof(command_line));
        if (result <= 0) {
            printf("[Session] Client disconnected (thread %lu)\n", 
                   (unsigned long)pthread_self());
            break;
        }

        /* Trim whitespace */
        size_t len = strlen(command_line);
        while (len > 0 && (command_line[len-1] == ' ' || command_line[len-1] == '\t')) {
            command_line[--len] = '\0';
        }

        if (command_line[0] == '\0') {
            send_str(client, "> ");
            continue;
        }

        if (strcmp(command_line, "exit") == 0) {
            send_str(client, "Goodbye!\n");
            printf("[Session] Client requested exit (thread %lu)\n", 
                   (unsigned long)pthread_self());
            return;
        }

        handle_command(client, command_line);
    }

    printf("[Session] Client handler finished (thread %lu)\n", 
           (unsigned long)pthread_self());
}

int main(void) {
    printf("=== Multi-Client SSH File Server ===\n");

    /* Initialize base directory */
    if (!getcwd(START_DIR, sizeof(START_DIR))) { 
        perror("getcwd"); 
        return 1; 
    }
    
    char canonical_path[PATH_MAX];
    if (realpath(START_DIR, canonical_path)) {
        strncpy(BASE_DIR, canonical_path, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    } else {
        strncpy(BASE_DIR, START_DIR, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    }
    
    printf("Server base directory: %s\n", BASE_DIR);
    printf("Listening on port 5000 for SSH connections...\n\n");

    /* Setup signal handler for child processes */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) { 
        perror("sigaction"); 
        return 1; 
    }

    /* Initialize libssh server */
    int port = 5000;
    ssh_bind sb = ssh_bind_new();
    if (!sb) { 
        fprintf(stderr, "Error: ssh_bind_new failed\n"); 
        return 1; 
    }

    /* Configure SSH server options */
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_BINDPORT, &port);
    
    /* Try to load host keys - graceful fallback if not available */
    if (ssh_bind_options_set(sb, SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key") != SSH_OK) {
        printf("Warning: Could not load RSA host key\n");
    }
    if (ssh_bind_options_set(sb, SSH_BIND_OPTIONS_ECDSAKEY, "/etc/ssh/ssh_host_ecdsa_key") != SSH_OK) {
        printf("Warning: Could not load ECDSA host key\n");
    }

    if (ssh_bind_listen(sb) != SSH_OK) {
        fprintf(stderr, "Error: Failed to bind to port %d: %s\n", port, ssh_get_error(sb));
        ssh_bind_free(sb);
        return 1;
    }
    
    printf("Server ready! Waiting for SSH clients...\n");
    printf("Connect with: ./client <server_ip> 5000 ege test\n\n");

    /* Main server loop - accept and handle clients */
    for (;;) {
        ssh_session s = ssh_new();
        if (!s) {
            fprintf(stderr, "Warning: Failed to create new SSH session\n");
            continue;
        }

        /* Accept new connection */
        if (ssh_bind_accept(sb, s) != SSH_OK) {
            printf("Warning: Failed to accept connection: %s\n", ssh_get_error(sb));
            ssh_free(s);
            continue;
        }

        /* Perform key exchange */
        if (ssh_handle_key_exchange(s) != SSH_OK) {
            printf("Warning: Key exchange failed: %s\n", ssh_get_error(s));
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        }

        printf("[Main] New SSH connection established, handling authentication...\n");

        /* Handle authentication */
        int authed = 0;
        ssh_message m;
        while ((m = ssh_message_get(s)) != NULL) {
            if (ssh_message_type(m) == SSH_REQUEST_AUTH) {
                if (ssh_message_subtype(m) == SSH_AUTH_METHOD_PASSWORD) {
                    const char *u = ssh_message_auth_user(m);
                    const char *p = ssh_message_auth_password(m);

                    printf("[Auth] Login attempt - user: '%s'\n", u ? u : "(null)");
                    
                    if (u && p && strcmp(u, "ege") == 0 && strcmp(p, "test") == 0) {
                        printf("[Auth] Authentication successful for user '%s'\n", u);
                        ssh_message_auth_reply_success(m, 0);
                        ssh_message_free(m);
                        authed = 1;
                        break;
                    } else {
                        printf("[Auth] Authentication failed for user '%s'\n", u ? u : "(null)");
                        ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(m);
                    }
                } else {
                    ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PASSWORD);
                    ssh_message_reply_default(m);
                }
            } else {
                ssh_message_reply_default(m);
            }
            ssh_message_free(m);
        }

        if (!authed) {
            printf("[Auth] Authentication failed, closing connection\n");
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        }

        /* Handle channel open request */
        ssh_channel ch = NULL;
        while ((m = ssh_message_get(s)) != NULL) {
            if (ssh_message_type(m) == SSH_REQUEST_CHANNEL_OPEN &&
                ssh_message_subtype(m) == SSH_CHANNEL_SESSION) {
                ch = ssh_message_channel_request_open_reply_accept(m);
                ssh_message_free(m);
                break;
            }
            ssh_message_reply_default(m);
            ssh_message_free(m);
        }
        
        if (!ch) {
            printf("[Channel] Failed to open session channel\n");
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        }

        /* Handle PTY and shell requests */
        while ((m = ssh_message_get(s)) != NULL) {
            if (ssh_message_type(m) == SSH_REQUEST_CHANNEL) {
                if (ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(m);
                } else if (ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_SHELL) {
                    ssh_message_channel_request_reply_success(m);
                    ssh_message_free(m);
                    break;
                } else {
                    ssh_message_reply_default(m);
                }
            } else {
                ssh_message_reply_default(m);
            }
            ssh_message_free(m);
        }

        /* Get client address info */
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        
        socket_t sock = ssh_get_fd(s);
        if (sock >= 0) {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            if (getpeername(sock, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
                client_addr = peer_addr;
            } else {
                /* Fallback to localhost if we can't get peer info */
                client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                client_addr.sin_port = htons(0);
            }
        }

        /* Create context for client thread */
        struct client_ctx *ctx = malloc(sizeof(*ctx));
        if (!ctx) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        }
        
        ctx->s = s;
        ctx->ch = ch;
        ctx->addr = client_addr;

        /* Launch client handler thread */
        pthread_t th;
        if (pthread_create(&th, NULL, client_main, ctx) != 0) {
            fprintf(stderr, "Error: Failed to create client thread\n");
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            ssh_disconnect(s);
            ssh_free(s);
            free(ctx);
            continue;
        }
        pthread_detach(th);
        
        printf("[Main] Client handler thread created successfully\n");
    }

    /* Cleanup (never reached in this server) */
    ssh_bind_free(sb);
    return 0;
}
