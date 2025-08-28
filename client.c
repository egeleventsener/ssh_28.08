#include "delete_directory.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <libssh2.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define BUF_SIZE 1024

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #define CLOSESOCK closesocket
#else
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #define CLOSESOCK close
#endif

// Global SSH connection state
static int tcp_socket = -1;
static LIBSSH2_SESSION *ssh_session = NULL;
static LIBSSH2_CHANNEL *ssh_channel = NULL;

// Step 1: Initialize networking (Windows needs this)
static int init_networking(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }
#endif
    return 0;
}

// Step 2: Create TCP connection to SSH server (port 22)
static int create_tcp_connection(const char *hostname, int port) {
    printf("[SSH] Step 1: Creating TCP connection to %s:%d\n", hostname, port);
    
    tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", hostname);
        CLOSESOCK(tcp_socket);
        tcp_socket = -1;
        return -1;
    }

    if (connect(tcp_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect to SSH server");
        CLOSESOCK(tcp_socket);
        tcp_socket = -1;
        return -1;
    }

    printf("[SSH] Step 1: TCP connection established\n");
    return 0;
}

// Step 3: Initialize SSH session and do handshake
static int init_ssh_session(void) {
    printf("[SSH] Step 2: Initializing SSH session\n");
    
    // Initialize libssh2
    if (libssh2_init(0) != 0) {
        fprintf(stderr, "Failed to initialize libssh2\n");
        return -1;
    }

    // Create SSH session
    ssh_session = libssh2_session_init();
    if (!ssh_session) {
        fprintf(stderr, "Failed to create SSH session\n");
        return -1;
    }

    // Set to blocking mode (easier to understand)
    libssh2_session_set_blocking(ssh_session, 1);

    // Perform SSH handshake over the TCP connection
    if (libssh2_session_handshake(ssh_session, tcp_socket) != 0) {
        fprintf(stderr, "SSH handshake failed\n");
        return -1;
    }

    printf("[SSH] Step 2: SSH handshake completed\n");
    return 0;
}

// Step 4: Check server's host key (security check)
static int verify_host_key(void) {
    printf("[SSH] Step 3: Verifying host key\n");
    
    const char *fingerprint = libssh2_hostkey_hash(ssh_session, LIBSSH2_HOSTKEY_HASH_SHA1);
    if (!fingerprint) {
        fprintf(stderr, "Failed to get host key fingerprint\n");
        return -1;
    }

    printf("[SSH] Host key fingerprint (SHA1): ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", (unsigned char)fingerprint[i]);
        if (i < 19) printf(":");
    }
    printf("\n");

    // SECURITY NOTE: In production, you should compare this fingerprint 
    // with a known good one stored securely. This prevents man-in-the-middle attacks.
    // For this tutorial, we'll accept any fingerprint.
    printf("[SSH] Step 3: Host key accepted (WARNING: not verified in this example)\n");
    printf("[SSH] In production, you should verify this fingerprint!\n");
    return 0;
}

// Step 5: Authenticate with username and password
static int authenticate_ssh(const char *username, const char *password) {
    printf("[SSH] Step 4: Authenticating user '%s'\n", username);
    
    // Try password authentication
    if (libssh2_userauth_password(ssh_session, username, password) != 0) {
        fprintf(stderr, "SSH authentication failed for user '%s'\n", username);
        
        // Get error message
        char *err_msg;
        int err_len;
        libssh2_session_last_error(ssh_session, &err_msg, &err_len, 0);
        fprintf(stderr, "Error: %s\n", err_msg);
        
        return -1;
    }

    printf("[SSH] Step 4: Authentication successful\n");
    return 0;
}

// Step 6: Create SSH tunnel (port forwarding)
static int create_ssh_tunnel(const char *remote_host, int remote_port) {
    printf("[SSH] Step 5: Creating SSH tunnel to %s:%d\n", remote_host, remote_port);
    
    // Create a "direct-tcpip" channel - this forwards TCP connections
    ssh_channel = libssh2_channel_direct_tcpip_ex(
        ssh_session,          // SSH session
        remote_host,          // Target host (usually "127.0.0.1" or "localhost")
        remote_port,          // Target port (5000 for our server)
        "127.0.0.1",         // Source host (our client)
        0                     // Source port (0 = any)
    );
    
    if (!ssh_channel) {
        fprintf(stderr, "Failed to create SSH tunnel\n");
        
        // Get error details
        char *err_msg;
        int err_len;
        libssh2_session_last_error(ssh_session, &err_msg, &err_len, 0);
        fprintf(stderr, "Error: %s\n", err_msg);
        
        return -1;
    }

    printf("[SSH] Step 5: SSH tunnel created successfully\n");
    printf("[SSH] Now all data will be encrypted and forwarded through SSH\n");
    return 0;
}

// Function to send data through SSH tunnel
static int ssh_send_all(const void *data, size_t len) {
    const char *ptr = (const char*)data;
    size_t sent = 0;
    
    while (sent < len) {
        ssize_t result = libssh2_channel_write(ssh_channel, ptr + sent, len - sent);
        if (result < 0) {
            fprintf(stderr, "SSH send error: %ld\n", (long)result);
            return -1;
        }
        sent += result;
    }
    return 0;
}

// Function to receive data through SSH tunnel
static ssize_t ssh_receive(void *buffer, size_t len) {
    ssize_t result = libssh2_channel_read(ssh_channel, (char*)buffer, len);
    if (result < 0) {
        fprintf(stderr, "SSH receive error: %ld\n", (long)result);
        return -1;
    }
    return result;
}

// Receive a line through SSH
static int ssh_recv_line(char *buf, size_t buf_size) {
    size_t pos = 0;
    while (pos < buf_size - 1) {
        char c;
        ssize_t result = ssh_receive(&c, 1);
        if (result <= 0) {
            return -1;
        }
        
        if (c == '\n') {
            buf[pos] = '\0';
            return pos;
        }
        if (c != '\r') {
            buf[pos++] = c;
        }
    }
    buf[buf_size - 1] = '\0';
    return pos;
}

// Send file through SSH tunnel
static int ssh_send_file(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Send size header
    char size_header[64];
    int len = snprintf(size_header, sizeof(size_header), "SIZE %ld\n", file_size);
    if (ssh_send_all(size_header, len) < 0) {
        fclose(fp);
        return -1;
    }

    // Send file data
    char buffer[BUF_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (ssh_send_all(buffer, bytes_read) < 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

// Get basename of path
static const char* get_basename(const char* path) {
    const char *basename = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }
    return basename;
}

// Local file operations (same as before)
static void local_pwd(void) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("%s\n", cwd);
    } else {
        perror("pwd");
    }
}

static void local_cd(const char *path) {
    if (!path || !*path) {
        fprintf(stderr, "cd: missing path\n");
        return;
    }
    if (chdir(path) != 0) {
        perror("cd");
    }
}

static void local_ls(void) {
    DIR *d = opendir(".");
    if (!d) {
        perror("ls");
        return;
    }
    
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(d))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        printf("%s\n", entry->d_name);
        count++;
    }
    
    if (count == 0) {
        printf("(empty)\n");
    }
    closedir(d);
}

static void local_mkdir(const char *name) {
    if (!name || !*name) {
        fprintf(stderr, "mkdir: missing name\n");
        return;
    }
#ifdef _WIN32
    if (mkdir(name) != 0) {
#else
    if (mkdir(name, 0777) != 0) {
#endif
        perror("mkdir");
    }
}

static void local_rm(const char *path) {
    if (!path || !*path) {
        fprintf(stderr, "rm: missing path\n");
        return;
    }
    if (strcmp(path, "/") == 0) {
        fprintf(stderr, "rm: refusing to delete '/'\n");
        return;
    }
    if (delete_directory(path) != 0) {
        fprintf(stderr, "rm: failed\n");
    }
}

// Cleanup SSH connection
static void cleanup_ssh(void) {
    printf("[SSH] Cleaning up SSH connection\n");
    
    if (ssh_channel) {
        libssh2_channel_close(ssh_channel);
        libssh2_channel_free(ssh_channel);
        ssh_channel = NULL;
    }
    
    if (ssh_session) {
        libssh2_session_disconnect(ssh_session, "Client disconnecting");
        libssh2_session_free(ssh_session);
        ssh_session = NULL;
    }
    
    if (tcp_socket >= 0) {
        CLOSESOCK(tcp_socket);
        tcp_socket = -1;
    }
    
    libssh2_exit();
    
#ifdef _WIN32
    WSACleanup();
#endif
}

int main() {
    // SSH connection parameters
    const char *ssh_host = "192.168.0.172";  // SSH server IP
    int ssh_port = 22;                       // SSH port
    const char *username = "ege";            // SSH username
    const char *password = "211221";         // SSH password
    const char *target_host = "127.0.0.1";   // Target host (through tunnel)
    int target_port = 5000;                  // Target port (your server)

    printf("=== SSH Client Tutorial ===\n");
    printf("This client will:\n");
    printf("1. Connect to SSH server at %s:%d\n", ssh_host, ssh_port);
    printf("2. Authenticate as user '%s'\n", username);
    printf("3. Create tunnel to %s:%d (your server)\n", target_host, target_port);
    printf("4. Send commands through encrypted SSH tunnel\n");
    printf("5. Support multiple concurrent connections\n\n");
    
    printf("IMPORTANT NOTES:\n");
    printf("- Make sure SSH server is running: sudo systemctl start ssh\n");
    printf("- Make sure your server is running on port 5000\n");
    printf("- Test SSH manually first: ssh %s@%s\n\n", username, ssh_host);

    // Step 1: Initialize networking
    if (init_networking() < 0) {
        return 1;
    }

    // Step 2: Create TCP connection to SSH server
    if (create_tcp_connection(ssh_host, ssh_port) < 0) {
        cleanup_ssh();
        return 1;
    }

    // Step 3: Initialize SSH session
    if (init_ssh_session() < 0) {
        cleanup_ssh();
        return 1;
    }

    // Step 4: Verify host key
    if (verify_host_key() < 0) {
        cleanup_ssh();
        return 1;
    }

    // Step 5: Authenticate
    if (authenticate_ssh(username, password) < 0) {
        cleanup_ssh();
        return 1;
    }

    // Step 6: Create SSH tunnel
    if (create_ssh_tunnel(target_host, target_port) < 0) {
        cleanup_ssh();
        return 1;
    }

    printf("\n=== SSH Connection Established ===\n");
    printf("You can now send commands. They will be encrypted and forwarded.\n\n");

    // Main command loop
    char buffer[1000];
    while (1) {
        printf("Enter command: ");
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            break;
        }
        
        // Remove newline
        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "exit") == 0) {
            printf("Closing SSH connection...\n");
            break;
        }

        // Handle local commands
        if (strcmp(buffer, "pwd") == 0) {
            local_pwd();
            continue;
        }
        if (strncmp(buffer, "cd ", 3) == 0) {
            local_cd(buffer + 3);
            continue;
        }
        if (strcmp(buffer, "ls") == 0) {
            local_ls();
            continue;
        }
        if (strncmp(buffer, "mkdir ", 6) == 0) {
            local_mkdir(buffer + 6);
            continue;
        }
        if (strncmp(buffer, "rm ", 3) == 0) {
            local_rm(buffer + 3);
            continue;
        }

        // Handle file upload
        if (strncmp(buffer, "send_file", 9) == 0) {
            char filepath[PATH_MAX];
            char dest_dir[PATH_MAX];
            
            // Get file path
            if (buffer[9] == ' ' && buffer[10] != '\0') {
                strncpy(filepath, buffer + 10, sizeof(filepath) - 1);
                filepath[sizeof(filepath) - 1] = '\0';
            } else {
                printf("Enter file path: ");
                if (!fgets(filepath, sizeof(filepath), stdin)) {
                    continue;
                }
                filepath[strcspn(filepath, "\n")] = 0;
            }
            
            // Get destination directory
            printf("Enter server destination directory: ");
            if (!fgets(dest_dir, sizeof(dest_dir), stdin)) {
                continue;
            }
            dest_dir[strcspn(dest_dir, "\n")] = 0;

            // Change server directory if needed
            if (dest_dir[0] && !(dest_dir[0] == '.' && dest_dir[1] == '\0')) {
                char scd_cmd[PATH_MAX + 8];
                snprintf(scd_cmd, sizeof(scd_cmd), "scd %s\n", dest_dir);
                if (ssh_send_all(scd_cmd, strlen(scd_cmd)) < 0) {
                    printf("Failed to send scd command\n");
                    continue;
                }
                
                char response[256];
                if (ssh_recv_line(response, sizeof(response)) <= 0) {
                    printf("No response to scd command\n");
                    continue;
                }
                printf("Server: %s\n", response);
            }

            // Send write_file command
            if (ssh_send_all("write_file\n", 11) < 0) {
                printf("Failed to send write_file command\n");
                continue;
            }

            // Send filename
            const char *filename = get_basename(filepath);
            char filename_line[PATH_MAX + 2];
            snprintf(filename_line, sizeof(filename_line), "%s\n", filename);
            if (ssh_send_all(filename_line, strlen(filename_line)) < 0) {
                printf("Failed to send filename\n");
                continue;
            }

            // Send file content
            printf("Sending file through SSH tunnel...\n");
            if (ssh_send_file(filepath) < 0) {
                printf("Failed to send file content\n");
                continue;
            }

            // Get response
            char response[256];
            if (ssh_recv_line(response, sizeof(response)) > 0) {
                printf("Server: %s\n", response);
            }
            continue;
        }

        // Send other commands to server through SSH tunnel
        char command_line[1024];
        snprintf(command_line, sizeof(command_line), "%s\n", buffer);
        if (ssh_send_all(command_line, strlen(command_line)) < 0) {
            printf("Failed to send command through SSH\n");
            continue;
        }

        // Receive response through SSH tunnel
        char response[BUF_SIZE];
        if (ssh_recv_line(response, sizeof(response)) > 0) {
            printf("Server: %s\n", response);
        }
    }

    cleanup_ssh();
    return 0;
}