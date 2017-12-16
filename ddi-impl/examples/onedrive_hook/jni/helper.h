/*
 * =====================================================================================
 *
 *       Filename:  helper.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  11/23/2016 11:58:13 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __HELPER__H__
#define __HELPER__H__
#include "state.h"
#include "log.h"
#include "helpfnc.h"
enum UPLOADMODEL{
    UNKNOWN = -1,
    CREATESESSION = 1,
    CREATESESSION_START,
    CREATESESSION_FINISH,
    FRAGMENT,
    FRAGMENT_START,
    FRAGMENT_FINISH,
    FRAGMENT_CONT,
    CLOSESESSION
};

struct stt_response{
    int len;
    int bytes_send;
    char* content;
    int free;
};
struct context{
    char* hostname;
    int local_port;
    int upload_model;
    struct stt_response response;
    struct item * item_ref;
    int used;
};


int process_request(const char* buf,int offset, int len,const char* hostname, int local_port);
char* process_response(const char* hostname,int local_port);
void set_context_response(const char* hostname, int local_port,char* response,int size, int free);
struct context* get_context(const char * hostname, int local_port);
char* malloc_copy_string(const char* string,int offset, int len);// not include '\0'
char* malloc_copy_data(const void* data, int offset,int len); //len include '\0'

char *od_get_content_response(char* location/*, char* filename*/);
int sync_analyze_request(const char* buf, const char* hostname, int local_port);
#endif
