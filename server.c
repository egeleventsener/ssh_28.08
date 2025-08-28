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
#include "delete_directory.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

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
static void send_str(int client_fd, const char* s) {
    send(client_fd, s, strlen(s), 0);
}

// Receive a line from client (handles both \n and \r\n)
static int recv_line(int client_fd, char *buf, size_t bufsz) {
    size_t pos = 0;
    while (pos + 1 < bufsz) {
        char ch;
        ssize_t result = recv(client_fd, &ch, 1, 0);
        if (result <= 0) {
            return -1; // Connection closed or error
        }
        if (ch == '\n') {
            buf[pos] = '\0';
            return (int)pos;
        }
        if (ch != '\r') { // Skip carriage return
            buf[pos++] = ch;
        }
    }
    buf[bufsz-1] = '\0';
    return (int)pos;
}

// Receive exactly N bytes and save to file
static int recv_n_to_file(int client_fd, const char* fname, long long nbytes) {
    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        perror("fopen for writing");
        return -1;
    }
    
    char buf[4096];
    long long remaining = nbytes;
    
    while (remaining > 0) {
        // Don't try to receive more than buffer size
        size_t to_recv = (remaining > (long long)sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        
        ssize_t received = recv(client_fd, buf, to_recv, 0);
        if (received <= 0) {
            fprintf(stderr, "[Child %d] Receive error during file transfer\n", getpid());
            fclose(fp);
            unlink(fname); // Delete partial file
            return -1;
        }
        
        // Write received data to file
        if (fwrite(buf, 1, (size_t)received, fp) != (size_t)received) {
            fprintf(stderr, "[Child %d] Write error during file transfer\n", getpid());
            fclose(fp);
            unlink(fname); // Delete partial file
            return -1;
        }
        
        remaining -= received;
    }
    
    fclose(fp);
    printf("[Child %d] File '%s' received successfully (%lld bytes)\n", getpid(), fname, nbytes);
    return 0;
}

// Handle individual commands from client
static void handle_command(int client_fd, char *cmdline) {
    printf("[Child %d] Handling command: '%s'\n", getpid(), cmdline);
    
    // Server PWD - show current directory relative to base
    if (strcmp(cmdline, "spwd") == 0) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd))) {
            if (starts_with(cwd, BASE_DIR)) {
                const char *rel = cwd + strlen(BASE_DIR);
                if (*rel == '\0') rel = "/";
                dprintf(client_fd, "Current directory: %s\n", rel);
            } else {
                dprintf(client_fd, "Current directory: %s\n", cwd);
            }
        } else {
            send_str(client_fd, "Failed to get current directory\n");
        }
        return;
    }
    
    // Server CD - change directory securely
    if (strncmp(cmdline, "scd ", 4) == 0) {
        const char *target_dir = cmdline + 4;
        if (secure_cd(target_dir) == 0) {
            send_str(client_fd, "Directory changed successfully\n");
        } else {
            send_str(client_fd, "Failed to change directory (access denied or not found)\n");
        }
        return;
    }
    
    // Server LS - list files in current directory
    if (strcmp(cmdline, "sls") == 0) {
        DIR *dir = opendir(".");
        if (!dir) {
            send_str(client_fd, "Cannot open directory\n");
            return;
        }
        
        struct dirent *entry;
        int file_count = 0;
        while ((entry = readdir(dir))) {
            // Skip . and .. entries
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            dprintf(client_fd, "%s\n", entry->d_name);
            file_count++;
        }
        closedir(dir);
        
        if (file_count == 0) {
            send_str(client_fd, "(directory is empty)\n");
        }
        return;
    }
    
    // Server MKDIR - create directory
    if (strncmp(cmdline, "smkdir ", 7) == 0) {
        const char *dir_name = cmdline + 7;
        if (mkdir(dir_name, 0755) == 0) {
            send_str(client_fd, "Directory created successfully\n");
        } else {
            send_str(client_fd, "Failed to create directory\n");
        }
        return;
    }
    
    // Server RM - remove file or directory
    if (strncmp(cmdline, "srm ", 4) == 0) {
        const char *target_path = cmdline + 4;
        char canon[PATH_MAX];
        
        // Security check - must be within base directory
        if (!realpath(target_path, canon) || !secure_path_in_base(canon)) {
            send_str(client_fd, "Access denied - path outside allowed area\n");
            return;
        }
        
        if (delete_directory(canon) == 0) {
            send_str(client_fd, "Successfully deleted\n");
        } else {
            send_str(client_fd, "Failed to delete\n");
        }
        return;
    }
    
    // Server RENAME - rename file or directory
    if (strncmp(cmdline, "srename ", 8) == 0) {
        char tmp[PATH_MAX * 2 + 16];
        strncpy(tmp, cmdline + 8, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        
        char *old_name = strtok(tmp, " \t\r\n");
        char *new_name = strtok(NULL, " \t\r\n");
        
        if (old_name && new_name) {
            char old_canon[PATH_MAX], new_canon[PATH_MAX];
            
            // Both paths must exist and be within base directory
            if (realpath(old_name, old_canon) && realpath(new_name, new_canon) &&
                secure_path_in_base(old_canon) && secure_path_in_base(new_canon) &&
                rename(old_canon, new_canon) == 0) {
                send_str(client_fd, "Successfully renamed\n");
            } else {
                send_str(client_fd, "Rename failed (check permissions and paths)\n");
            }
        } else {
            send_str(client_fd, "Invalid rename command format\n");
        }
        return;
    }
    
    // WRITE_FILE - receive file from client
    if (strcmp(cmdline, "write_file") == 0) {
        char filename[PATH_MAX];
        
        // First, receive the filename
        if (recv_line(client_fd, filename, sizeof(filename)) < 0 || filename[0] == '\0') {
            send_str(client_fd, "Error: Could not receive filename\n");
            return;
        }
        
        // Then receive the SIZE line
        char size_line[128];
        if (recv_line(client_fd, size_line, sizeof(size_line)) < 0) {
            send_str(client_fd, "Error: Could not receive file size\n");
            return;
        }
        
        // Parse file size
        long long file_size = -1;
        if (sscanf(size_line, "SIZE %lld", &file_size) != 1 || file_size < 0) {
            send_str(client_fd, "Error: Invalid file size format\n");
            return;
        }
        
        printf("[Child %d] Receiving file '%s' of size %lld bytes\n", getpid(), filename, file_size);
        
        // Receive file data
        if (recv_n_to_file(client_fd, filename, file_size) == 0) {
            send_str(client_fd, "File uploaded successfully\n");
        } else {
            send_str(client_fd, "File upload failed\n");
        }
        return;
    }

    // Unknown command
    send_str(client_fd, "Unknown command\n");
}

// Handle a single client connection (runs in child process)
static void handle_client(int client_fd, struct sockaddr_in client_addr) {
    printf("[Child %d] Handling client %s:%d\n", 
           getpid(), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    // Each client starts in the base directory
    if (chdir(BASE_DIR) != 0) {
        perror("chdir to base directory");
        close(client_fd);
        exit(1);
    }
    
    char command_line[2048];
    while (1) {
        // Receive command from client
        int result = recv_line(client_fd, command_line, sizeof(command_line));
        if (result <= 0) {
            printf("[Child %d] Client disconnected\n", getpid());
            break;
        }
        
        // Skip empty commands
        if (command_line[0] == '\0') {
            send_str(client_fd, "Empty command received\n");
            continue;
        }
        
        // Process the command
        handle_command(client_fd, command_line);
    }
    
    close(client_fd);
    printf("[Child %d] Client handler finished\n", getpid());
    exit(0); // Child process exits
}

int main(void) {
    printf("=== Multi-Client File Server ===\n");
    
    // Get current directory as base directory for security
    if (!getcwd(START_DIR, sizeof(START_DIR))) {
        perror("getcwd");
        return 1;
    }
    
    // Resolve to canonical path
    char canonical_path[PATH_MAX];
    if (realpath(START_DIR, canonical_path)) {
        strncpy(BASE_DIR, canonical_path, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    } else {
        strncpy(BASE_DIR, START_DIR, sizeof(BASE_DIR)-1);
        BASE_DIR[sizeof(BASE_DIR)-1] = '\0';
    }
    
    printf("Base directory: %s\n", BASE_DIR);
    printf("Server will accept connections on port 5000\n");
    
    // Set up signal handler to clean up zombie processes
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart system calls if interrupted
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }
    
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    
    // Allow socket reuse (prevents "Address already in use" error)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(server_fd);
        return 1;
    }
    
    // Bind to all interfaces on port 5000
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    server_addr.sin_port = htons(5000);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    
    // Listen for connections (backlog of 10)
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }
    
    printf("Server listening and ready for multiple clients...\n\n");
    
    // Main server loop - accept connections and fork for each client
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept incoming connection
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                // Interrupted by signal (probably SIGCHLD), continue
                continue;
            }
            perror("accept");
            continue;
        }
        
        printf("[Main] New client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Fork a child process to handle this client
        pid_t child_pid = fork();
        
        if (child_pid == 0) {
            // Child process - handle the client
            close(server_fd); // Child doesn't need the listening socket
            handle_client(client_fd, client_addr);
            // Child exits after handling client (never reaches here)
            
        } else if (child_pid > 0) {
            // Parent process - continue accepting new connections
            close(client_fd); // Parent doesn't need the client socket
            printf("[Main] Forked child process %d for client\n", child_pid);
            
        } else {
            // Fork failed
            perror("fork");
            close(client_fd);
            continue;
        }
    }
    
    close(server_fd);
    return 0;
}