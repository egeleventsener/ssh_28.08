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

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef ssh_channel client_t;

static inline ssize_t io_read(client_t ch, void *buf, size_t n){ return ssh_channel_read(ch, buf, n, 0); }
static inline ssize_t io_write(client_t ch, const void *buf, size_t n){ return ssh_channel_write(ch, buf, n); }
static void io_dprintf(client_t ch, const char *fmt, ...){
    char tmp[8192]; va_list ap; va_start(ap, fmt);
    int k = vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
    if(k>0) ssh_channel_write(ch, tmp, (size_t)k);
}

static char BASE_DIR[PATH_MAX] = {0};
static char START_DIR[PATH_MAX] = {0};

// Signal handler to clean up zombie processes (child processes that finished)
static void sigchld_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    // Clean up all finished child processes
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        // Just cleaning up zombies, no action needed
    }
}

static int starts_with(const char* s, const char* p) {
    return strncmp(s, p, strlen(p)) == 0;
}

// Check if path is within our allowed base directory (security measure)
static int secure_path_in_base(const char* path) {
    char canon[PATH_MAX];
    if (!realpath(path, canon)) return 0;
    size_t b = strlen(BASE_DIR);
    return (strncmp(canon, BASE_DIR, b) == 0) && (canon[b] == '/' || canon[b] == '\0');
}

// Secure directory change - prevents escaping from base directory
static int secure_cd(const char *target) {
    if (!target || !*target) return -1;
    char tmp[PATH_MAX];
    
    if (target[0] == '/') {
        // Absolute path - prepend base directory
        snprintf(tmp, sizeof(tmp), "%s%s", BASE_DIR, target);
    } else {
        // Relative path - append to current directory
        if (!getcwd(tmp, sizeof(tmp))) return -1;
        size_t len = strlen(tmp);
        if (len + 1 < sizeof(tmp)) {
            tmp[len] = '/';
            tmp[len+1] = '\0';
        }
        strncat(tmp, target, sizeof(tmp) - strlen(tmp) - 1);
    }
    
    // Resolve to canonical path and check security
    char canon[PATH_MAX];
    if (!realpath(tmp, canon)) return -1;
    if (!secure_path_in_base(canon)) return -1;
    if (chdir(canon) != 0) return -1;
    return 0;
}

// Send string to client
static void send_str(client_t c, const char *s){ 
    io_write(c, s, strlen(s)); 
}

// Receive a line from client (handles both \n and \r\n)
static int recv_line(client_t c, char *buf, size_t bufsz) {
    size_t u = 0;
    while (u + 1 < bufsz) {
        char ch;
        ssize_t r = io_read(c, &ch, 1);
        if (r <= 0) return -1;
        if (ch == '\n') { buf[u] = '\0'; return (int)u; }
        if (ch != '\r') buf[u++] = ch;
    }
    buf[bufsz - 1] = '\0';
    return (int)u;
}

// Receive exactly N bytes and save to file
static int recv_n_to_file(client_t c, const char* fname, long long nbytes) {
    FILE *fp = fopen(fname, "wb");
    if (!fp) { perror("fopen for writing"); return -1; }

    char buf[4096];
    long long remaining = nbytes;

    while (remaining > 0) {
        size_t want = (remaining > (long long)sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        ssize_t got = io_read(c, buf, want);
        if (got <= 0) {
            fprintf(stderr, "[Child %d] Receive error during file transfer\n", getpid());
            fclose(fp);
            unlink(fname);
            return -1;
        }
        if (fwrite(buf, 1, (size_t)got, fp) != (size_t)got) {
            fprintf(stderr, "[Child %d] Write error during file transfer\n", getpid());
            fclose(fp);
            unlink(fname);
            return -1;
        }
        remaining -= got;
    }

    fclose(fp);
    printf("[Child %d] File '%s' received successfully (%lld bytes)\n",
           getpid(), fname, nbytes);
    return 0;
}

// Handle individual commands from client
static void handle_command(client_t client, char *cmdline) {
    printf("[Child %d] Handling command: '%s'\n", getpid(), cmdline);

    if (strcmp(cmdline, "spwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd))) {
            if (starts_with(cwd, BASE_DIR)) {
                const char *rel = cwd + strlen(BASE_DIR);
                if (*rel == '\0') rel = "/";
                io_dprintf(client, "Current directory: %s\n", rel);
            } else {
                io_dprintf(client, "Current directory: %s\n", cwd);
            }
        } else {
            send_str(client, "Failed to get current directory\n");
        }
        return;
    }

    if (strncmp(cmdline, "scd ", 4) == 0) {
        const char *target_dir = cmdline + 4;
        if (secure_cd(target_dir) == 0) send_str(client, "Directory changed successfully\n");
        else send_str(client, "Failed to change directory (access denied or not found)\n");
        return;
    }

    if (strcmp(cmdline, "sls") == 0) {
        DIR *dir = opendir(".");
        if (!dir) { send_str(client, "Cannot open directory\n"); return; }
        struct dirent *entry; int file_count = 0;
        while ((entry = readdir(dir))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            io_dprintf(client, "%s\n", entry->d_name);
            file_count++;
        }
        closedir(dir);
        if (file_count == 0) send_str(client, "(directory is empty)\n");
        return;
    }

    if (strncmp(cmdline, "smkdir ", 7) == 0) {
        const char *dir_name = cmdline + 7;
        if (mkdir(dir_name, 0755) == 0) send_str(client, "Directory created successfully\n");
        else send_str(client, "Failed to create directory\n");
        return;
    }

    if (strncmp(cmdline, "srm ", 4) == 0) {
        const char *target_path = cmdline + 4;
        char canon[PATH_MAX];
        if (!realpath(target_path, canon) || !secure_path_in_base(canon)) {
            send_str(client, "Access denied - path outside allowed area\n");
            return;
        }
        if (delete_directory(canon) == 0) send_str(client, "Successfully deleted\n");
        else send_str(client, "Failed to delete\n");
        return;
    }

    if (strncmp(cmdline, "srename ", 8) == 0) {
        char tmp[PATH_MAX * 2 + 16];
        strncpy(tmp, cmdline + 8, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
        char *old_name = strtok(tmp, " \t\r\n");
        char *new_name = strtok(NULL, " \t\r\n");
        if (old_name && new_name) {
            char old_canon[PATH_MAX], new_canon[PATH_MAX];
            if (realpath(old_name, old_canon) && realpath(new_name, new_canon) &&
                secure_path_in_base(old_canon) && secure_path_in_base(new_canon) &&
                rename(old_canon, new_canon) == 0) {
                send_str(client, "Successfully renamed\n");
            } else send_str(client, "Rename failed (check permissions and paths)\n");
        } else send_str(client, "Invalid rename command format\n");
        return;
    }

    if (strcmp(cmdline, "write_file") == 0) {
        char filename[PATH_MAX];
        if (recv_line(client, filename, sizeof(filename)) < 0 || filename[0] == '\0') {
            send_str(client, "Error: Could not receive filename\n"); return;
        }
        char size_line[128];
        if (recv_line(client, size_line, sizeof(size_line)) < 0) {
            send_str(client, "Error: Could not receive file size\n"); return;
        }
        long long file_size = -1;
        if (sscanf(size_line, "SIZE %lld", &file_size) != 1 || file_size < 0) {
            send_str(client, "Error: Invalid file size format\n"); return;
        }
        printf("[Child %d] Receiving file '%s' of size %lld bytes\n",
               getpid(), filename, file_size);
        if (recv_n_to_file(client, filename, file_size) == 0)
            send_str(client, "File uploaded successfully\n");
        else
            send_str(client, "File upload failed\n");
        return;
    }

    send_str(client, "Unknown command\n");
}

// Handle a single client connection (runs in child process)
static void handle_client(client_t client, struct sockaddr_in client_addr) {
    printf("[Child %d] Handling client %s:%d\n",
           getpid(), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    if (chdir(BASE_DIR) != 0) {
        perror("chdir to base directory");
        exit(1);
    }

    char command_line[2048];
    for (;;) {
        int result = recv_line(client, command_line, sizeof(command_line));
        if (result <= 0) {
            printf("[Child %d] Client disconnected\n", getpid());
            break;
        }
        if (command_line[0] == '\0') {
            send_str(client, "Empty command received\n");
            continue;
        }
        handle_command(client, command_line);
    }

    printf("[Child %d] Client handler finished\n", getpid());
    exit(0);
}

int main(void) {
    printf("=== Multi-Client File Server (SSH) ===\n");

    /* base dir setup */
    if (!getcwd(START_DIR, sizeof(START_DIR))) { perror("getcwd"); return 1; }
    char canonical_path[PATH_MAX];
    if (realpath(START_DIR, canonical_path)) {
        strncpy(BASE_DIR, canonical_path, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    } else {
        strncpy(BASE_DIR, START_DIR, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    }
    printf("Base directory: %s\n", BASE_DIR);
    printf("Server will accept SSH connections on port 5000\n");

    /* SIGCHLD handler */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    /* --- libssh server setup --- */
    int port = 5000;
    ssh_bind sb = ssh_bind_new();
    if (!sb) { fprintf(stderr, "ssh_bind_new failed\n"); return 1; }

    /* Configure SSH options - remove ED25519 key to fix compatibility */
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key");
    ssh_bind_options_set(sb, SSH_BIND_OPTIONS_ECDSAKEY, "/etc/ssh/ssh_host_ecdsa_key");
    /* Removed ED25519 key - not supported in older libssh versions */

    if (ssh_bind_listen(sb) != SSH_OK) {
        fprintf(stderr, "listen: %s\n", ssh_get_error(sb));
        ssh_bind_free(sb);
        return 1;
    }
    printf("Server listening and ready for multiple SSH clients...\n\n");

    for (;;) {
        ssh_session s = ssh_new();
        if (ssh_bind_accept(sb, s) != SSH_OK) { ssh_free(s); continue; }
        if (ssh_handle_key_exchange(s) != SSH_OK) { ssh_disconnect(s); ssh_free(s); continue; }

        /* password auth */
        int authed = 0;
        for (ssh_message m; (m = ssh_message_get(s)) != NULL; ) {
            if (ssh_message_type(m) == SSH_REQUEST_AUTH &&
                ssh_message_subtype(m) == SSH_AUTH_METHOD_PASSWORD) {
                const char *u = ssh_message_auth_user(m);
                /* Use newer API to avoid deprecation warning */
                ssh_string pass_str = ssh_message_auth_password(s);
                const char *p = pass_str ? ssh_string_to_char(pass_str) : NULL;
                
                if (u && p && strcmp(u, "ege") == 0 && strcmp(p, "test") == 0) {
                    ssh_message_auth_reply_success(m, 0);
                    authed = 1;
                    if (p) ssh_string_free_char((char*)p);
                    if (pass_str) ssh_string_free(pass_str);
                    ssh_message_free(m);
                    break;
                }
                if (p) ssh_string_free_char((char*)p);
                if (pass_str) ssh_string_free(pass_str);
                ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(m);
            } else {
                ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(m);
            }
            ssh_message_free(m);
        }
        if (!authed) { ssh_disconnect(s); ssh_free(s); continue; }

        /* open session channel */
        ssh_channel ch = NULL;
        for (ssh_message m; (m = ssh_message_get(s)) != NULL; ) {
            if (ssh_message_type(m) == SSH_REQUEST_CHANNEL_OPEN &&
                ssh_message_subtype(m) == SSH_CHANNEL_SESSION) {
                ch = ssh_message_channel_request_open_reply_accept(m);
                ssh_message_free(m);
                break;
            }
            ssh_message_reply_default(m);
            ssh_message_free(m);
        }
        if (!ch) { ssh_disconnect(s); ssh_free(s); continue; }

        /* optional PTY + SHELL */
        for (ssh_message m; (m = ssh_message_get(s)) != NULL; ) {
            if (ssh_message_type(m) == SSH_REQUEST_CHANNEL &&
                ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_PTY) {
                ssh_message_channel_request_reply_success(m);
            } else if (ssh_message_type(m) == SSH_REQUEST_CHANNEL &&
                       ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_SHELL) {
                ssh_message_channel_request_reply_success(m);
                ssh_message_free(m);
                break;
            } else {
                ssh_message_reply_default(m);
            }
            ssh_message_free(m);
        }

        /* build client_addr - use socket info instead of unavailable functions */
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        
        /* Get socket from session and extract peer address */
        socket_t sock = ssh_get_fd(s);
        if (sock >= 0) {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            if (getpeername(sock, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
                client_addr = peer_addr;
            }
        }

        /* fork per client */
        pid_t child_pid = fork();
        if (child_pid == 0) {
            /* child */
            handle_client(ch, client_addr);

            /* cleanups if handle_client returns */
            ssh_channel_send_eof(ch);
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            ssh_disconnect(s);
            ssh_free(s);
            _exit(0);
        } else if (child_pid > 0) {
            /* parent */
            printf("[Main] Forked child process %d for client\n", child_pid);
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        } else {
            perror("fork");
            ssh_channel_close(ch);
            ssh_channel_free(ch);
            ssh_disconnect(s);
            ssh_free(s);
            continue;
        }
    }
}