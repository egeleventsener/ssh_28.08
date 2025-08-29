// client.c – cross-platform libssh2 client with local+remote commands
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>   // _getcwd, _mkdir
#include <io.h>       // _unlink
/* no pragmas for MinGW */
#define close      closesocket
#define unlink     _unlink
#define getcwd     _getcwd
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <dirent.h>
#include <sys/stat.h>

#include <libssh2.h>

static void die(const char* msg){
    fprintf(stderr,"ERROR: %s\n", msg);
    exit(1);
}

/* ---------- socket helpers ---------- */
static int tcp_connect(const char* host, int port){
#ifdef _WIN32
    WSADATA wsa; 
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) die("WSAStartup failed");
#endif
    char portstr[16]; snprintf(portstr,sizeof portstr,"%d",port);
    struct addrinfo hints={0}, *res=0,*rp=0; 
    hints.ai_socktype=SOCK_STREAM; 
    hints.ai_family=AF_UNSPEC;
    
    if(getaddrinfo(host, portstr, &hints, &res)!=0) die("getaddrinfo");
    int s=-1;
    for(rp=res; rp; rp=rp->ai_next){
        s=(int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(s<0) continue;
        if(connect(s, rp->ai_addr, (int)rp->ai_addrlen)==0) break;
        close(s);
        s=-1;
    }
    freeaddrinfo(res);
    if(s<0) die("connect");
    return s;
}

/* libssh2 wait helper for nonblocking reads */
static int waitsocket(int socket_fd, LIBSSH2_SESSION *session, int timeout_ms){
    struct timeval tv; 
    fd_set fds; 
    fd_set fds_err;
    tv.tv_sec  = timeout_ms/1000;
    tv.tv_usec = (timeout_ms%1000)*1000;

    FD_ZERO(&fds); 
    FD_ZERO(&fds_err);
    FD_SET(socket_fd, &fds); 
    FD_SET(socket_fd, &fds_err);

    int dir = libssh2_session_block_directions(session);
    int ret = select(socket_fd+1,
                     (dir & LIBSSH2_SESSION_BLOCK_INBOUND ) ? &fds : NULL,
                     (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) ? &fds : NULL,
                     &fds_err, &tv);
    return ret;
}

/* write all to channel with retry logic */
static int chan_write_all(LIBSSH2_CHANNEL* ch, const char* buf, size_t len){
    size_t written = 0;
    while(written < len){
        ssize_t n = libssh2_channel_write(ch, buf + written, len - written);
        if(n == LIBSSH2_ERROR_EAGAIN) {
            continue; // retry
        }
        if(n < 0) {
            fprintf(stderr, "Channel write error: %ld\n", (long)n);
            return (int)n;
        }
        written += n;
    }
    return 0;
}

/* read and print any pending data until we see a prompt */
static void chan_read_until_prompt(int sock, LIBSSH2_SESSION* sess, LIBSSH2_CHANNEL* ch, int timeout_ms){
    char buf[4096];
    char tail[256]; 
    size_t tlen = 0;
    int idle = 0;
    
    for(;;){
        ssize_t n = libssh2_channel_read(ch, buf, sizeof(buf));
        if(n > 0){
            fwrite(buf,1,(size_t)n,stdout); 
            fflush(stdout);
            
            /* keep last up to 255 bytes and check for prompts */
            size_t keep = (tlen + (size_t)n > sizeof(tail)-1) ? sizeof(tail)-1 : tlen + (size_t)n;
            if(keep < (size_t)n){ /* new chunk longer than window */
                memcpy(tail, buf + (n - (ssize_t)keep), keep);
            } else {
                size_t shift = keep - (size_t)n;
                if(shift > 0) memmove(tail, tail + (tlen - shift), shift);
                memcpy(tail + shift, buf, (size_t)n);
            }
            tlen = keep; 
            tail[tlen] = '\0';

            /* look for various prompt patterns */
            if (strstr(tail, "> ") || strstr(tail, "Enter command:")) {
                return;
            }
            idle = 0;
            continue;
        }
        if(n == LIBSSH2_ERROR_EAGAIN){
            if(waitsocket(sock, sess, 50) <= 0) {
                idle += 50;
                if(idle >= timeout_ms) return;
            }
            continue;
        }
        if(n == 0 || n < 0) return; /* EOF or error */
    }
}

/* ---------- local filesystem commands (client-side) ---------- */
static void l_pwd(void){
    char cwd[4096];
    if(!getcwd(cwd,sizeof cwd)) { 
        perror("getcwd"); 
        return; 
    }
    printf("Local directory: %s\n", cwd);
}

static void l_ls(void){
    DIR* d = opendir(".");
    if(!d){ 
        perror("opendir"); 
        return; 
    }
    printf("Local directory contents:\n");
    struct dirent* e;
    int count = 0;
    while((e = readdir(d))){
        if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")) {
            printf("  %s\n", e->d_name);
            count++;
        }
    }
    if(count == 0) printf("  (empty)\n");
    closedir(d);
}

/* local cd */
static void l_cd(const char* dir){
    if(!dir||!*dir){ 
        fprintf(stderr,"Usage: lcd <directory>\n"); 
        return; 
    }
    if(chdir(dir)==0) {
        printf("Changed to local directory: %s\n", dir);
    } else {
        perror("lcd");
    }
}

/* local mkdir */
#ifdef _WIN32
#define MKDIR(p) _mkdir(p)
#else
#define MKDIR(p) mkdir(p,0755)
#endif

static void l_mkdir(const char* d){
    if(!d||!*d){ 
        fprintf(stderr,"Usage: lmkdir <directory>\n"); 
        return; 
    }
    if(MKDIR(d)==0) {
        printf("Created local directory: %s\n", d);
    } else {
        perror("lmkdir");
    }
}

static void l_rename(const char* a, const char* b){
    if(!a||!b){ 
        fprintf(stderr,"Usage: lrename <old_name> <new_name>\n"); 
        return; 
    }
    if(rename(a,b)==0) {
        printf("Renamed %s -> %s\n", a, b);
    } else {
        perror("lrename");
    }
}

static void l_rm(const char* p){
    if(!p||!*p){ 
        fprintf(stderr,"Usage: lrm <path>\n"); 
        return; 
    }
    if(remove(p)==0) {
        printf("Deleted local file: %s\n", p);
    } else {
        perror("lrm");
    }
}

/* Enhanced file send with better error handling and progress */
static int send_file_protocol(int sock, LIBSSH2_SESSION* sess, LIBSSH2_CHANNEL* ch,
                              const char* local_path, const char* remote_path)
{
    if (!local_path || !*local_path) { 
        fprintf(stderr,"Error: Missing local file path\n"); 
        return -1; 
    }

    /* Check if local file exists and is readable */
    FILE* f = fopen(local_path, "rb");
    if (!f) { 
        fprintf(stderr, "Error: Cannot open local file '%s': %s\n", local_path, strerror(errno));
        return -1; 
    }

    /* get exact size using portable method */
    long long sz = -1;
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(local_path, &st) == 0) {
        sz = (long long)st.st_size;
    }
#else
    struct stat st;
    if (stat(local_path, &st) == 0) {
        sz = (long long)st.st_size;
    }
#endif

    if (sz < 0) { 
        fclose(f); 
        fprintf(stderr,"Error: Cannot determine file size\n"); 
        return -1; 
    }

    /* Extract basename for auto-naming */
    const char *base = strrchr(local_path, '\\');
    if (!base) base = strrchr(local_path, '/');
    base = base ? base + 1 : local_path;

    /* Determine final remote path */
    char remote_fixed[4096];
    if (!remote_path || !*remote_path) {
        snprintf(remote_fixed, sizeof remote_fixed, "%s", base);
    } else {
        size_t rlen = strlen(remote_path);
        int ends_with_sep = (remote_path[rlen-1] == '/' || remote_path[rlen-1] == '\\');
        
        /* Check if it looks like a directory (no extension after last slash) */
        const char *last_sl = remote_path + rlen;
        while (last_sl > remote_path && last_sl[-1] != '/' && last_sl[-1] != '\\') last_sl--;
        int has_dot = strchr(last_sl, '.') != NULL;
        
        if (ends_with_sep || !has_dot) {
            /* Treat as directory, append basename */
            snprintf(remote_fixed, sizeof remote_fixed, "%s%s%s",
                     remote_path, ends_with_sep ? "" : "/", base);
        } else {
            /* Use as exact filename */
            snprintf(remote_fixed, sizeof remote_fixed, "%s", remote_path);
        }
    }

    printf("Uploading: %s -> %s (%lld bytes)\n", local_path, remote_fixed, sz);

    /* Send protocol header */
    char hdr[4096];
    int hdr_len = snprintf(hdr, sizeof hdr, "write_file\n%s\nSIZE %lld\n", remote_fixed, sz);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) { 
        fclose(f); 
        fprintf(stderr,"Error: Header too long\n"); 
        return -1; 
    }
    
    if (chan_write_all(ch, hdr, (size_t)hdr_len) != 0) { 
        fclose(f); 
        fprintf(stderr,"Error: Failed to send header\n"); 
        return -1; 
    }

    /* Stream file content with progress indication */
    char buf[65536];
    long long sent = 0;
    long long last_progress = 0;
    
    while (sent < sz) {
        size_t want = (size_t)((sz - sent) > (long long)sizeof(buf) ? sizeof(buf) : (sz - sent));
        size_t r = fread(buf, 1, want, f);
        if (r == 0) { 
            if (ferror(f)) {
                perror("fread"); 
            } else {
                fprintf(stderr, "Unexpected EOF in local file\n");
            }
            fclose(f); 
            return -1; 
        }
        
        if (chan_write_all(ch, buf, r) != 0) { 
            fclose(f); 
            fprintf(stderr,"Error: Failed to send file data\n"); 
            return -1; 
        }
        
        sent += r;
        
        /* Progress indication for larger files */
        if (sz > 1024*1024 && (sent - last_progress) > sz/20) { // every 5%
            printf("Progress: %lld/%lld bytes (%.1f%%)\n", sent, sz, (double)sent*100/sz);
            last_progress = sent;
        }
    }
    fclose(f);

    if (sz > 1024*1024) {
        printf("Upload complete: %lld bytes sent\n", sent);
    }

    /* Wait for server response */
    chan_read_until_prompt(sock, sess, ch, 5000);
    return 0;
}

/* ---------- main ---------- */
static void usage(const char* prog){
    printf("Usage: %s <host> <port> <user> <pass>\n\n", prog);
    printf("Remote (server) commands:\n");
    printf("  spwd                    - show remote working directory\n");
    printf("  sls                     - list remote directory contents\n");
    printf("  scd <dir>               - change remote directory\n");
    printf("  smkdir <dir>            - create remote directory\n");
    printf("  srename <old> <new>     - rename remote file/directory\n");
    printf("  srm <path>              - delete remote file/directory\n");
    printf("  send_file <local> [remote] - upload file to server\n");
    printf("\nLocal (client) commands:\n");
    printf("  lpwd                    - show local working directory\n");
    printf("  lls                     - list local directory contents\n");
    printf("  lcd <dir>               - change local directory\n");
    printf("  lmkdir <dir>            - create local directory\n");
    printf("  lrename <old> <new>     - rename local file/directory\n");
    printf("  lrm <path>              - delete local file\n");
    printf("\nShortcut commands (remote):\n");
    printf("  pwd, ls, cd, mkdir, rm, rename - same as s* versions\n");
    printf("  exit, quit              - disconnect from server\n");
}

int main(int argc, char** argv){
    if(argc<5){ 
        usage(argv[0]); 
        return 1; 
    }
    
    const char* host=argv[1];
    int   port=atoi(argv[2]);
    const char* user=argv[3];
    const char* pass=argv[4];

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Error: Invalid port number\n");
        return 1;
    }

    printf("Connecting to %s:%d as user '%s'...\n", host, port, user);
    int sock = tcp_connect(host, port);
    printf("TCP connection established.\n");

    if(libssh2_init(0)!=0) die("libssh2_init");
    LIBSSH2_SESSION* sess = libssh2_session_init();
    if(!sess) die("session_init");
    libssh2_session_set_blocking(sess, 1);

    printf("Starting SSH handshake...\n");
    if(libssh2_session_handshake(sess, sock)) die("handshake");
    
    printf("Authenticating...\n");
    if(libssh2_userauth_password(sess, user, pass)){
        fprintf(stderr,"Authentication failed for user '%s'\n", user);
        libssh2_session_free(sess);
        close(sock);
        return 1;
    }
    printf("Authentication successful.\n");

    LIBSSH2_CHANNEL* ch = libssh2_channel_open_session(sess);
    if(!ch) die("channel_open_session");
    if (libssh2_channel_shell(ch)) die("shell");
    
    printf("Shell session opened. Waiting for server prompt...\n");
    chan_read_until_prompt(sock, sess, ch, 3000);

    char line[8192];
    printf("\nReady! Type 'help' for commands, 'quit' to exit.\n");
    
    for(;;){
        printf("client> "); 
        fflush(stdout);
        if(!fgets(line, sizeof line, stdin)) break;

        // trim whitespace
        size_t L = strlen(line);
        while(L && (line[L-1]=='\n' || line[L-1]=='\r' || line[L-1]==' ' || line[L-1]=='\t')) {
            line[--L]=0;
        }

        if(L==0) continue;
        if(strcmp(line,"quit")==0) break;
        if(strcmp(line,"help")==0) {
            usage(argv[0]);
            continue;
        }

        // parse command
        char line_copy[8192];
        strncpy(line_copy, line, sizeof(line_copy));
        line_copy[sizeof(line_copy)-1] = '\0';
        
        char *cmd = strtok(line_copy," \t");
        char *a1  = strtok(NULL," \t");
        char *a2  = strtok(NULL," \t");
        if (!cmd) continue;

        /* local commands */
        if(strcmp(cmd,"lpwd")==0){ l_pwd(); continue; }
        if(strcmp(cmd,"lls")==0){ l_ls(); continue; }
        if(strcmp(cmd,"lcd")==0){ l_cd(a1); continue; }
        if(strcmp(cmd,"lmkdir")==0){ l_mkdir(a1); continue; }
        if(strcmp(cmd,"lrename")==0){ l_rename(a1,a2); continue; }
        if(strcmp(cmd,"lrm")==0){ l_rm(a1); continue; }

        /* file upload */
        if(strcmp(cmd,"send_file")==0){
            if(!a1){ 
                fprintf(stderr,"Usage: send_file <local_file> [remote_path]\n"); 
                continue; 
            }
            printf("Starting file upload...\n");
            if(send_file_protocol(sock, sess, ch, a1, a2)==0) {
                printf("File upload completed successfully.\n");
            } else {
                fprintf(stderr,"File upload failed.\n");
            }
            continue;
        }

        /* convenient aliases: translate normal cmds -> server cmds */
        if(strcmp(cmd,"pwd")==0){
            const char *out = "spwd\n";
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if(strcmp(cmd,"ls")==0){
            const char *out = "sls\n";
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if(strcmp(cmd,"cd")==0){
            if(!a1){ 
                fprintf(stderr,"Usage: cd <directory>\n"); 
                continue; 
            }
            char out[4096]; 
            snprintf(out,sizeof out,"scd %s\n", a1);
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if(strcmp(cmd,"mkdir")==0){
            if(!a1){ 
                fprintf(stderr,"Usage: mkdir <directory>\n"); 
                continue; 
            }
            char out[4096]; 
            snprintf(out,sizeof out,"smkdir %s\n", a1);
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if(strcmp(cmd,"rm")==0){
            if(!a1){ 
                fprintf(stderr,"Usage: rm <path>\n"); 
                continue; 
            }
            char out[4096]; 
            snprintf(out,sizeof out,"srm %s\n", a1);
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if(strcmp(cmd,"rename")==0){
            if(!a1||!a2){ 
                fprintf(stderr,"Usage: rename <old_name> <new_name>\n"); 
                continue; 
            }
            char out[4096]; 
            snprintf(out,sizeof out,"srename %s %s\n", a1, a2);
            if(chan_write_all(ch, out, strlen(out))!=0){ 
                fprintf(stderr,"Communication error\n"); 
                break; 
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }
        if (strcmp(cmd, "exit") == 0) {
            const char *out = "exit\n";
            chan_write_all(ch, out, strlen(out));
            chan_read_until_prompt(sock, sess, ch, 1000);
            break;
        }

        /* raw pass-through to server for s* commands */
        if(cmd[0]=='s'){
            if(chan_write_all(ch, line, strlen(line))!=0){
                fprintf(stderr,"Communication error\n"); 
                break;
            }
            if(chan_write_all(ch, "\n", 1)!=0){
                fprintf(stderr,"Communication error\n"); 
                break;
            }
            chan_read_until_prompt(sock, sess, ch, 2000);
            continue;
        }

        fprintf(stderr,"Unknown command '%s'. Type 'help' for available commands.\n", cmd);
    }

    printf("Closing connection...\n");
    libssh2_channel_send_eof(ch);
    libssh2_channel_close(ch);
    libssh2_channel_free(ch);
    libssh2_session_disconnect(sess,"Client disconnecting");
    libssh2_session_free(sess);
    libssh2_exit();

    close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    printf("Disconnected.\n");
    return 0;
}