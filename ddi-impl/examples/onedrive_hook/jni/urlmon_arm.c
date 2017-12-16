/*
 * =====================================================================================
 *
 *       Filename:  urlmon_arm.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  11/09/2016 12:01:40 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */
#include <stdlib.h>

extern int my_open(const char* path_name, int flags);
extern int my_write(int fd, const void* buf,size_t count);
int my_write_arm(int fd, const void* buf,size_t count){
    my_write(fd,buf, count);
}
int my_open_arm(const char* path_name, int flags){
    my_open(path_name,flags);
}

