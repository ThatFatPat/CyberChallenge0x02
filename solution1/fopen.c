#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>


FILE* fopen ( const char * filename, const char * mode ){
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE* ret;
    int cmp = strcmp(filename, "/dev/random");
    if (!cmp){
        ret = (*original_fopen)("./random_chars", "rb");
    }
    else {
        ret = (*original_fopen)(filename, mode);
    }
    return ret;
}
