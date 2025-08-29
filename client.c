// client.c — cross-platform libssh2 client with local+remote commands
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
#pragma comment(lib,"ws2_32.lib")
static void msleep(int ms){ Sleep(ms); }
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
static void msleep(int ms){ usleep(ms*1000); }
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
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    char portstr[16]; snprintf(portstr,sizeof portstr,"%d",port);
    struct addrinfo hints={0}, *res=0,*rp=0; hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
    if(getaddrinfo(host, portstr, &hints, &res)!=0) die("getaddrinfo");
    int s=-1;
    for(rp=res; rp; rp=rp->ai_next){
        s=(int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(s<0) continue;
        if(connect(s, rp->ai_addr, (int)rp->ai_addrlen)==0) break;
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        s=-1;
    }
    freeaddrinfo(res);
    if(s<0) die("connect");
    return s;
}

/* libssh2 wait helper for nonblocking reads */
static int waitsocket(int socket_fd, LIBSSH2_SESSION *session, int timeout_ms){
    struct timeval tv; fd_set fds; fd_set fds_err;
    tv.tv_sec  = timeout_ms/1000;
    tv.tv_usec = (timeout_ms%1000)*1000;

    FD_ZERO(&fds); FD_ZERO(&fds_err);
    FD_SET(socket_fd, &fds); FD_SET(socket_fd, &fds_err);

    int dir = libssh2_session_block_directions(session);
    int ret = select(socket_fd+1,
                     (dir & LIBSSH2_SESSION_BLOCK_INBOUND ) ? &fds : NULL,
                     (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) ? &fds : NULL,
                     &fds_err, &tv);
    return ret;
}

/* write all to channel */
static int chan_write_all(LIBSSH2_CHANNEL* ch, const char* buf, size_t len){
    while(len){
        ssize_t n = libssh2_channel_write(ch, buf, (unsigned)len);
        if(n<0) return (int)n;
        buf += n; len -= n;
    }
    return 0;
}

/* read and print any pending data for idle_window_ms without new bytes */
static void chan_drain_print(int sock, LIBSSH2_SESSION* sess, LIBSSH2_CHANNEL* ch, int idle_window_ms){
    char buf[8192];
    int idle=0;
    for(;;){
        ssize_t n = libssh2_channel_read(ch, buf, sizeof(buf));
        if(n>0){
            fwrite(buf,1,(size_t)n,stdout); fflush(stdout);
            idle=0;                      // got data; reset idle timer
            continue;
        }
        if(n==LIBSSH2_ERROR_EAGAIN){
            waitsocket(sock, sess, 50);
            idle+=50;
            if(idle>=idle_window_ms) break;
            continue;
        }
        // n==0 no data and channel open; treat as idle
        if(n==0){
            waitsocket(sock, sess, 50);
            idle+=50;
            if(idle>=idle_window_ms) break;
            continue;
        }
        // n<0 fatal
        break;
    }
}

/* ---------- local filesystem commands (client-side) ---------- */
static void l_pwd(void){
    char cwd[4096];
#ifdef _WIN32
    if(!_getcwd(cwd,sizeof cwd)) { perror("getcwd"); return; }
#else
    if(!getcwd(cwd,sizeof cwd)) { perror("getcwd"); return; }
#endif
    printf("%s\n", cwd);
}
static void l_ls(void){
    DIR* d = opendir(".");
    if(!d){ perror("opendir"); return; }
    struct dirent* e;
    while((e = readdir(d))){
        if(strcmp(e->d_name,".") && strcmp(e->d_name,".."))
            printf("%s\n", e->d_name);
    }
    closedir(d);
}
static void l_cd(const char* dir){
    if(!dir||!*dir){ fprintf(stderr,"lcd <dir>\n"); return; }
#ifdef _WIN32
    if(_chdir(dir)!=0) perror("lcd");
#else
    if(chdir(dir)!=0) perror("lcd");
#endif
}
static void l_mkdir(const char* d){
    if(!d||!*d){ fprintf(stderr,"lmkdir <dir>\n"); return; }
#ifdef _WIN32
    if(_mkdir(d)!=0) perror("lmkdir");
#else
    if(mkdir(d,0755)!=0) perror("lmkdir");
#endif
}
static void l_rename(const char* a, const char* b){
    if(!a||!b){ fprintf(stderr,"lrename <old> <new>\n"); return; }
    if(rename(a,b)!=0) perror("lrename");
}
static void l_rm(const char* p){
    if(!p||!*p){ fprintf(stderr,"lrm <path>\n"); return; }
#ifdef _WIN32
    if(_unlink(p)!=0) perror("lrm");
#else
    if(remove(p)!=0) perror("lrm");
#endif
}

/* send local file to server using server's write_file protocol */
static int send_file_protocol(int sock, LIBSSH2_SESSION* sess, LIBSSH2_CHANNEL* ch,
                              const char* local_path, const char* remote_path){
    FILE* f = fopen(local_path,"rb");
    if(!f){ perror("open local"); return -1; }
    if(!remote_path) remote_path = local_path;

    // get size
    if(fseek(f,0,SEEK_END)!=0){ perror("fseek"); fclose(f); return -1; }
    long long sz = ftell(f);
    if(sz<0){ perror("ftell"); fclose(f); return -1; }
    fseek(f,0,SEEK_SET);

    char hdr[4096];
    snprintf(hdr,sizeof hdr,"write_file\n%s\nSIZE %lld\n", remote_path, sz);

    if(chan_write_all(ch, hdr, strlen(hdr))!=0){ fclose(f); return -1; }

    // stream file
    char buf[65536];
    long long left = sz;
    while(left>0){
        size_t n = (size_t)((left>(long long)sizeof(buf))? sizeof(buf) : left);
        size_t r = fread(buf,1,n,f);
        if(r==0){ fclose(f); return -1; }
        if(chan_write_all(ch, buf, r)!=0){ fclose(f); return -1; }
        left -= (long long)r;
    }
    fclose(f);

    // read server response
    chan_drain_print(sock, sess, ch, 300);
    return 0;
}

/* ---------- main ---------- */
static void usage(const char* prog){
    printf("Usage: %s <host> <port> <user> <pass>\n", prog);
    printf("\nRemote (server) commands:\n");
    printf("  spwd | sls | scd <dir> | smkdir <d> | srename <a> <b> | srm <p>\n");
    printf("  send_file <local> [remote]\n");
    printf("\nLocal (client) commands:\n");
    printf("  lpwd | lls | lcd <dir> | lmkdir <d> | lrename <a> <b> | lrm <p>\n");
    printf("  quit\n");
}

int main(int argc, char** argv){
    if(argc<5){ usage(argv[0]); return 1; }
    const char* host=argv[1];
    int   port=atoi(argv[2]);
    const char* user=argv[3];
    const char* pass=argv[4];

    int sock = tcp_connect(host, port);

    if(libssh2_init(0)!=0) die("libssh2_init");
    LIBSSH2_SESSION* sess = libssh2_session_init();
    if(!sess) die("session_init");
    libssh2_session_set_blocking(sess, 0);

    if(libssh2_session_handshake(sess, sock)) die("handshake");
    if(libssh2_userauth_password(sess, user, pass)){
        fprintf(stderr,"auth failed\n"); return 1;
    }

    LIBSSH2_CHANNEL* ch = libssh2_channel_open_session(sess);
    if(!ch) die("channel_open_session");
    // no PTY; plain line protocol
    // If your server required PTY+SHELL, uncomment:
    // libssh2_channel_request_pty(ch, "vt100");
    // libssh2_channel_shell(ch);

    // interactive loop
    char line[8192];
    for(;;){
        printf("client> "); fflush(stdout);
        if(!fgets(line, sizeof line, stdin)) break;

        // trim
        size_t L = strlen(line);
        while(L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L]=0;

        if(L==0) continue;
        if(strcmp(line,"quit")==0) break;

        // parse
        char *cmd = strtok(line," \t");
        char *a1  = strtok(NULL," \t");
        char *a2  = strtok(NULL," \t");

        /* local commands */
        if(strcmp(cmd,"lpwd")==0){ l_pwd(); continue; }
        if(strcmp(cmd,"lls")==0){ l_ls(); continue; }
        if(strcmp(cmd,"lcd")==0){ l_cd(a1); continue; }
        if(strcmp(cmd,"lmkdir")==0){ l_mkdir(a1); continue; }
        if(strcmp(cmd,"lrename")==0){ l_rename(a1,a2); continue; }
        if(strcmp(cmd,"lrm")==0){ l_rm(a1); continue; }

        /* client convenience -> server protocol */
        if(strcmp(cmd,"send_file")==0){
            if(!a1){ fprintf(stderr,"send_file <local> [remote]\n"); continue; }
            if(send_file_protocol(sock, sess, ch, a1, a2)!=0)
                fprintf(stderr,"send_file failed\n");
            continue;
        }

        /* raw pass-through to server for s* commands */
        if(cmd[0]=='s'){                 // spwd, sls, scd, smkdir, srename, srm, write_file (manual)
            // reconstruct original line with args and newline
            char out[8192];
            if(a1 && a2) snprintf(out,sizeof out,"%s %s %s\n",cmd,a1,a2);
            else if(a1) snprintf(out,sizeof out,"%s %s\n",cmd,a1);
            else snprintf(out,sizeof out,"%s\n",cmd);
            if(chan_write_all(ch, out, strlen(out))!=0){
                fprintf(stderr,"write failed\n"); break;
            }
            chan_drain_print(sock, sess, ch, 300);
            continue;
        }

        fprintf(stderr,"Unknown command. Type s* for server or l* for local.\n");
    }

    libssh2_channel_send_eof(ch);
    libssh2_channel_close(ch);
    libssh2_channel_free(ch);
    libssh2_session_disconnect(sess,"bye");
    libssh2_session_free(sess);
    libssh2_exit();

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return 0;
}
