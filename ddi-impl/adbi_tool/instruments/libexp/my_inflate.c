/*
 * =====================================================================================
 *
 *       Filename:  my_inflate.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  11/07/2016 02:10:23 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <zlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log
#define log(...) {\
    FILE* fp = fopen("/data/local/tmp/zlibexample.log","a+");\
    if(fp) {\
        fprintf(fp,__VA_ARGS__);\
        fclose(fp);\
    }\
}

static struct hook_t eph;

static void my_log(char* msg){
    log("%s",msg);
}

extern int ZEXPORT my_inflate_arm OF((z_streamp strm, int flush));

int ZEXPORT my_inflate OF((z_streamp strm, int flush)){
    log("%s", "zlib.so inflate hooked\n");
    int (*orig_inflate) OF((z_streamp strm,int flush));
    orig_inflate = (void*)eph.orig;
    hook_precall(&eph);

    size_t out_available = strm->avail_out;
    size_t out_size;
    size_t have;

    //call original inflate
    int res = orig_inflate(strm,flush);

    out_size = strm->avail_out;
    have = out_available - out_size;
    char* out = malloc(sizeof(char) * have + 1);

    memset(out,'\0', have + 1);
    memcpy(out,strm->next_out, have);

    log("%zu: %s\n",have,out);
    free(out);

    hook_postcall(&eph);
    log("inflate call\n");
    return res;
}

void __attribute__ ((constructor)) my_init(void);

void my_init(void){
    log("%s started\n",__FILE__);
    set_logfunction(my_log);
    hook(&eph,getpid(),"libz.","inflate",my_inflate_arm, my_inflate);
}
