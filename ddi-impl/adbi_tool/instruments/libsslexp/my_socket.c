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
#include <sys/socket.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log
#define log(...) {\
    FILE* fp = fopen("/data/local/tmp/socket.log","a+");\
    if(fp) {\
        fprintf(fp,__VA_ARGS__);\
        fclose(fp);\
    }\
}

static struct hook_t eph;

static void my_log(char* msg){
    log("%s",msg);
}

extern int my_socket_arm(int domain,int type, int protocol);
int my_socket(int domain, int type, int protocol){
    log("%s","socket hooked\n");

    int (*orig_socket)(int domain, int type, int protocol);
    orig_socket = (void*) eph.orig;
    hook_precall(&eph);
    log("domain %d type %d, protocol %d\n",domain,type, protocol);
    int ret = orig_socket(domain,type, protocol);
    hook_postcall(&eph);
    return ret;
}

extern int my_sendto_arm(int fd, const void* buf,size_t len, int flag,
        const struct sockaddr *dest_addr,socklen_t addrlen);

int my_sendto(int fd, const void* buf,size_t len, int flag,
        const struct sockaddr *dest_addr,socklen_t addrlen){

    log("%s","sendto hooked\n");
    int (*orig_sendto)(int fd, const void* buf,size_t len, int flag, const struct sockaddr *dest_addr,socklen_t addrlen);
    orig_sendto = (void*) eph.orig;
    hook_precall(&eph);
    int ret = orig_sendto(fd,buf,len,flag,dest_addr,addrlen);
    hook_postcall(&eph);
    return ret;

}
void __attribute__ ((constructor)) my_init(void);

void my_init(void){
    log("%s started\n",__FILE__);
    set_logfunction(my_log);
    hook(&eph,getpid(),"libc.","socket",my_socket_arm, my_socket);
    hook(&eph,getpid(),"libc.","sendto", my_sendto_arm, my_socket);
}
