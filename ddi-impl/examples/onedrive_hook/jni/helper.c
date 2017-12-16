/*
 * =====================================================================================
 *
 *       Filename:  helper.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  11/22/2016 04:15:18 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <string.h>
#include "helper.h"
#include "format.h"


/* struct global_context{
 *     int size;
 *     int index;
 *     struct upload_context* contexts;
 * }; */
#define GLOBAL_CONTEXT_SIZE 2000
struct context contexts[GLOBAL_CONTEXT_SIZE] = {0};

/* struct global_context gcontext = {GLOBAL_CONTEXT_SIZE,0,contexts}; */

char* malloc_copy_string(const char* string,int offset, int len)// not include '\0'
{
    char* tmp = malloc(sizeof(char) * len + 1);
    memset(tmp,'\0', len + 1);
    memcpy(tmp,string + offset,len);
    return tmp;
}

char* malloc_copy_data(const void* data, int offset,int len) //len include '\0'
{

    char* tmp = malloc(sizeof(char) * len);
    memset(tmp, '\0', len);
    memcpy(tmp, data +  offset, len);
    return tmp;
}

int check_upload_model(const char* hostname, int local_port)
{

    int i;
    for(i = 0; i < GLOBAL_CONTEXT_SIZE;++i){
        if(contexts[i].used == 1){
           if( (hostname == NULL ||strcmp(hostname, contexts[i].hostname) == 0) && local_port == contexts[i].local_port)
               return contexts[i].upload_model;
        }
    }
    return -1;
}

int search_existed_context(const char* hostname,int local_port)
{
    int i;
    for(i = 0; i < GLOBAL_CONTEXT_SIZE;++i){
        if(contexts[i].used == 1){
            if( (hostname == NULL || contexts[i].hostname != NULL&&strcmp(hostname, contexts[i].hostname) == 0 )&& local_port == contexts[i].local_port)
               return i;
        }
    }
    return -1;
}

struct context* get_context(const char * hostname, int local_port)
{
    int index = search_existed_context(hostname,local_port);
    if(index != -1)
        return &contexts[index];
    return NULL;
}

int search_empty_context(){
    int i;
    for(i = 0; i < GLOBAL_CONTEXT_SIZE;++i){
        if(contexts[i].used == 0){
               return i;
        }
    }
//    log("search finished\n");
    return -1;
}


int set_context_unknown(const char* hostname, int local_port, int upload_model){
    int index;
    if(upload_model == UNKNOWN){
        if((index = search_empty_context()) != -1){
            if(hostname != NULL)
                contexts[index].hostname = malloc_copy_string(hostname,0, strlen(hostname));
            else
                hostname = NULL;
            contexts[index].local_port = local_port;
            contexts[index].upload_model = upload_model;
            contexts[index].used = 1;
        }else{
            log("Out of Memeory\n");
        }
    }else /*  if(upload_model == FRAGMENT || upload_model == CLOSESESSION|| upload_model == CREATESESSION_FINISH || upload_model == FRAGMENT_FINISH)*/{
        index = search_existed_context(hostname, local_port);
        if (index != -1 ){
            contexts[index].upload_model = upload_model;
        }else{
            log("Error: Can not find corresponding context\n");
        }
    }
    return 1;
}

//copy hostname
int set_context(const char* hostname, int local_port, int upload_model){
    int index;
    if(upload_model == CREATESESSION){
        if((index = search_empty_context()) != -1){
            if(hostname != NULL)
                contexts[index].hostname = malloc_copy_string(hostname,0, strlen(hostname));
            else
                contexts[index].hostname = NULL;
            contexts[index].local_port = local_port;
            contexts[index].upload_model = upload_model;
            contexts[index].used = 1;
        }else{
            log("Out of Memeory\n");
        }
    }else /*  if(upload_model == FRAGMENT || upload_model == CLOSESESSION|| upload_model == CREATESESSION_FINISH || upload_model == FRAGMENT_FINISH)*/{
        index = search_existed_context(hostname, local_port);
        if (index != -1 ){
            contexts[index].upload_model = upload_model;
        }else{
            log("Error: Can not find corresponding context\n");
        }
    }
    return 1;
}

void set_context_cache(const char* hostname, int local_port, struct item* it){
        int index = search_existed_context(hostname, local_port);
        if (index != -1 ){
            contexts[index].item_ref = it;
        }else{
            log("Error: Can not find corresponding context\n");
        }
}


void set_context_response(const char* hostname, int local_port, char *response, int size,int free){
        int index = search_existed_context(hostname, local_port);
        log("index %d\n",index);
        if (index != -1 ){
            //TODO: free response
            contexts[index].response.content = response;
            contexts[index].response.len = size;
            contexts[index].response.bytes_send = 0;
            contexts[index].response.free = free;
        }else{
            index = search_empty_context();
            contexts[index].hostname = NULL;
            contexts[index].local_port = local_port;
            contexts[index].upload_model = UNKNOWN;
            contexts[index].used = 1;
            contexts[index].response.content = response;
            contexts[index].response.len = size;
            contexts[index].response.bytes_send = 0;
            contexts[index].response.free = free;
            log("Error: Can not find corresponding qcontext-response %d\n",index);
        }
}
/*
 * return value:
 *  1 upload session
 *  2 download session
 *  0 other
 * */

int process_request(const char* buf, int offset,int size, const char * hostname, int local_port)
{
    char* p;
    if((p = strstr(buf,fmtreq1))){
        //TODO: Save Request to Global Buffer,set upload_context;
        set_context(hostname, local_port, CREATESESSION);
        log(" =>Request: Create-Session\n");
    }else if ((p = strstr(buf,fmtreq2))){
        //TODO: Save Request to Global Buffer
        set_context(hostname, local_port, FRAGMENT);
        log(" =>Request: Fragment\n");
    }else if ((p = strstr(buf,fmtreq3))){
        //TODO: Save Request to Global Buffer
        set_context(hostname, local_port, CLOSESESSION);
        log(" =>Request: Close-Session\n");
    }else if((p = strstr(buf, "GET /v5.0/folder.42a638c59aa1eaa8")) || (p = strstr(buf, "GET /v5.0/file.42a638c59aa1eaa8"))){
//            log("get file matched\n");
            int rv;
            char* method, *id,*query ,*type;
            rv = parse_request(buf,&method,&id,&query,&type);

            //download file
//            log("return value %d\n",rv);
            if(rv == 1){
//                log("hostname %s, port %d\n",hostname,local_port);
                set_context_unknown(hostname,local_port,UNKNOWN);
                return 2;
            }else {
                return 0;
            }
    }else if((p = strstr(buf, "files.1drv.com"))){
			char *location_s = strstr(buf,"/");
			location_s += 1;
			char *location_e = strstr(location_s," HTTP/1.1");
			char* fl = malloc(location_e - location_s + 1);
			memset(fl, '\0', location_e - location_s + 1);
			memcpy(fl,location_s, location_e - location_s);
			state_lock();
			struct item * rv = check_filelocation(fl);
			state_unlock();

			if(rv){
                //hit
                set_context_response(hostname,local_port,rv->cache,rv->cache_size,0);
                return 3;
            }
            set_context_response(hostname,local_port,NULL,0,0);
            return 0;
    }else{
        if(search_existed_context(hostname,local_port) == -1){
            return 0;
        }
       //TODO: Data
       //do nothing
       log(" => Data\n");
    }
    return 1;
}

char* process_response(const char * hostname, int local_port)
{
    int model;

    model = check_upload_model(hostname, local_port);
    switch(model){
        case CREATESESSION:
            log(" =>Create-Session\n");
            set_context( hostname,local_port,CREATESESSION_START);
//            return "H";
        case CREATESESSION_START:
            set_context( hostname,local_port,CREATESESSION_FINISH);
            return response1;
        case FRAGMENT:
            log(" =>Fragment\n");
            set_context( hostname,local_port,FRAGMENT_START);
//            return response2;
        case FRAGMENT_START:
            set_context( hostname,local_port,FRAGMENT_FINISH);
            return response2;
        case CLOSESESSION:
            log(" =>Close-Session\n");
            int index = search_existed_context(hostname,local_port);
            contexts[index].upload_model = CREATESESSION;
            return response3;
        case CREATESESSION_FINISH:
            log(" =>Create-Session Done\n");
        case FRAGMENT_FINISH:
            log(" =>FRAGMENT Done\n");
            return (char*) 1;
        default:
            return NULL;

    }
}

int sync_analyze_request(const char* buf, const char* hostname, int local_port)
{

    char* p = NULL;
	if(( p = strstr(buf, "GET /v5.0/me/skydrive/files" /* ?suppress_response_codes=true&suppress_redirects=true HTTP/1.1" */))){
	    //TODO: setup hostname
	    set_context(hostname,local_port,CREATESESSION);
	    return 2;// issue delta request
    }else if((p = strstr(buf, "GET /v5.0/folder.42a638c59aa1eaa8"))){
        int rv;
        char *method, *id, *query, *type;
        rv = parse_request(buf, &method, &id, &query, &type);
        if(rv == 0){

            char* meta = generate_metadata(id);
            size_t meta_size = strlen(meta);
#if 0
            size_t o_size = 0;
            char* compressed_meta = gzip_compress(meta,meta_size,&o_size);
            meta_size = o_size;
#endif
            //				fprintf(stderr,"compressed_meta size %zu\n",o_size);

            /* Calculate Size of Response Body*/
            char str[15];
            memset(str,'\0',15);
           // sprintf(str,"%zu",meta_size);

            char* rsp = malloc(strlen(onesync_rsp3) + strlen(str) +meta_size + 1);
            char* r_pos = rsp;
            memset(rsp,'\0', strlen(onesync_rsp3)  + strlen(str) + meta_size + 1);

            char* p = strstr(onesync_rsp3,"olength");
            memcpy(r_pos, onesync_rsp3, p - onesync_rsp3);
            r_pos += p - onesync_rsp3;

            memcpy(r_pos, str,strlen(str));
            r_pos += strlen(str);

            memcpy(r_pos, p + strlen("olength"), strlen(onesync_rsp3)
                    - (p - onesync_rsp3 + strlen("olength")));
            r_pos += strlen(onesync_rsp3) - (p - onesync_rsp3 + strlen("olength"));

            memcpy(r_pos, meta, meta_size);
            set_context_response(hostname,local_port,rsp,strlen(rsp),1);
            free(meta);
            return 1;//metadata response set
        }
    }else if((p = strstr(buf,"GET /v5.0/me?suppress_response_codes=true&suppress_redirects=true HTTP/1.1"))){
        set_context_response(hostname,local_port,onesync_rsp1,strlen(onesync_rsp1),0);
        return 1;
    }else if(( p = strstr(buf, "GET /v5.0/me/skydrive/quota?"))){
        set_context_response(hostname,local_port,onesync_rsp2,strlen(onesync_rsp2),0);
        return 1;
    }
    return 0;
}


 char*
od_get_content_response(char* location/*, char* filename*/){
	size_t lsize = strlen(location);
//	size_t fsize = strlen(filename);
	size_t p1size = strlen(onesync_content_rsp1);
	size_t p2size = strlen(onesync_content_rsp2);
	size_t size = lsize /*+ fsize */ + p1size + p2size;
	char* rsp = malloc(size + 1 + 2);

	memset(rsp, '\0', size + 1 + 2);
	memcpy(rsp, onesync_content_rsp1, p1size);
	memcpy(rsp + p1size, location,lsize);
	memcpy(rsp + p1size + lsize, "\r\n",2);
	memcpy(rsp + lsize + p1size + 2, onesync_content_rsp2,p2size);
//	fprintf(stderr,"content %s %s\n",location,rsp);
	return rsp;
}
