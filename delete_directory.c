#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <stdio.h>
#include <string.h>

static int remove_entry(const char *path){
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return -1;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY){
        WIN32_FIND_DATAA ffd;
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\*", path);
        HANDLE h = FindFirstFileA(pattern, &ffd);
        if (h == INVALID_HANDLE_VALUE) return -1;
        do{
            if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
            char child[MAX_PATH];
            snprintf(child, sizeof(child), "%s\\%s", path, ffd.cFileName);
            remove_entry(child);
        } while (FindNextFileA(h, &ffd));
        FindClose(h);
        return _rmdir(path);
    } else {
        return _unlink(path);
    }
}
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int remove_entry(const char *path){
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)){
        DIR *d = opendir(path);
        if (!d) return -1;
        struct dirent *e;
        char child[PATH_MAX];
        int ret = 0;
        while ((e = readdir(d))){
            if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (remove_entry(child) != 0) { ret = -1; break; }
        }
        closedir(d);
        if (ret == 0) ret = rmdir(path);
        return ret;
    } else {
        return unlink(path);
    }
}
#endif

int delete_directory(const char *path){
    if (!path || !*path) return -1;
#ifdef _WIN32
    if (strcmp(path, "\\") == 0) return -1;
    if (strlen(path) == 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) return -1;
#else
    if (strcmp(path, "/") == 0) return -1;
#endif
    return remove_entry(path);
}