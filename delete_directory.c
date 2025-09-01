#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <stdio.h>
#include <string.h>

static int remove_entry(const char *path){
    if (!path || !*path) return -1;
    
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Cannot access path: %s\n", path);
        return -1;
    }
    
    if (attrs & FILE_ATTRIBUTE_DIRECTORY){
        /* Remove directory contents first */
        WIN32_FIND_DATAA ffd;
        char pattern[MAX_PATH];
        int ret = snprintf(pattern, sizeof(pattern), "%s\\*", path);
        if (ret < 0 || ret >= sizeof(pattern)) return -1;
        
        HANDLE h = FindFirstFileA(pattern, &ffd);
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Cannot list directory: %s\n", path);
            return -1;
        }
        
        int success = 1;
        do {
            if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) 
                continue;
                
            char child[MAX_PATH];
            ret = snprintf(child, sizeof(child), "%s\\%s", path, ffd.cFileName);
            if (ret < 0 || ret >= sizeof(child)) {
                success = 0;
                break;
            }
            
            if (remove_entry(child) != 0) {
                success = 0;
                break;
            }
        } while (FindNextFileA(h, &ffd));
        
        FindClose(h);
        if (!success) return -1;
        
        /* Remove the directory itself */
        if (_rmdir(path) != 0) {
            fprintf(stderr, "Cannot remove directory: %s\n", path);
            return -1;
        }
    } else {
        /* Remove file */
        if (_unlink(path) != 0) {
            fprintf(stderr, "Cannot remove file: %s\n", path);
            return -1;
        }
    }
    return 0;
}

#else

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int remove_entry(const char *path){
    if (!path || !*path) return -1;
    
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "Cannot stat path '%s': %s\n", path, strerror(errno));
        return -1;
    }
    
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)){
        /* Remove directory contents first */
        DIR *d = opendir(path);
        if (!d) {
            fprintf(stderr, "Cannot open directory '%s': %s\n", path, strerror(errno));
            return -1;
        }
        
        struct dirent *e;
        char child[PATH_MAX];
        int success = 1;
        
        while ((e = readdir(d)) && success) {
            if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) 
                continue;
                
            int ret = snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (ret < 0 || ret >= sizeof(child)) {
                success = 0;
                break;
            }
            
            if (remove_entry(child) != 0) {
                success = 0;
                break;
            }
        }
        closedir(d);
        
        if (!success) return -1;
        
        /* Remove the directory itself */
        if (rmdir(path) != 0) {
            fprintf(stderr, "Cannot remove directory '%s': %s\n", path, strerror(errno));
            return -1;
        }
    } else {
        /* Remove file or symlink */
        if (unlink(path) != 0) {
            fprintf(stderr, "Cannot remove file '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

#endif

int delete_directory(const char *path){
    if (!path || !*path) {
        fprintf(stderr, "Error: Empty path provided\n");
        return -1;
    }
    
    /* Safety check against deleting critical system directories */
#ifdef _WIN32
    if (strcmp(path, "\\") == 0) {
        fprintf(stderr, "Error: Cannot delete root directory\n");
        return -1;
    }
    if (strlen(path) == 3 && path[1] == ':' && 
        (path[2] == '\\' || path[2] == '/')) {
        fprintf(stderr, "Error: Cannot delete drive root\n");
        return -1;
    }
#else
    if (strcmp(path, "/") == 0) {
        fprintf(stderr, "Error: Cannot delete root directory\n");
        return -1;
    }
#endif

    printf("Deleting: %s\n", path);
    return remove_entry(path);
}
