
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "state.h"
#include "jsmn.h"

struct state* delta_stat;

#if 0
const char* delta_request_part1 = "GET /v1.0/drive/items/42A638C59AA1EAA8!593/view.delta?select=id%2Cname%2Cdeleted%2Clastmodifieddatetime HTTP/1.1\r\n"
#endif
const char* delta_request_part1 = "GET /v1.0/drive/items/42A638C59AA1EAA8!103/view.delta HTTP/1.1\r\n"
"X-RequestStats: SDK-Version=Android-v1.1.5\r\n"
"Authorization: bearer ";
const char* delta_request_part2 =
"\r\nUser-Agent: Dalvik/1.6.0 (Linux; U; Android 4.4.4; GT-I9500 Build/KTU84Q)\r\n"
"Host: api.onedrive.com\r\n"
"Connection: Keep-Alive\r\n"
"Accept-Encoding: gzip\r\n\r\n";

int stat_init()
{
    delta_stat = malloc(sizeof(struct state));
    delta_stat->delta_token = NULL;
    delta_stat->size = 0;
    size_t i;
    for(i = 0; i < ITEM_NUM; ++i){
        delta_stat->items[i].present = 0;
        delta_stat->items[i].file_id = NULL;
        delta_stat->items[i].file_name = NULL;
        delta_stat->items[i].modified_time = NULL;
        delta_stat->items[i].etag = NULL;
        delta_stat->items[i].cache = NULL;
    }
    pthread_mutex_init(&delta_stat->lock,NULL);
    return 0;
}

struct item* update_item(char* file_id, char* file_name, char* modified_time, char* size,
        char* created_time, char* parent_id,file_type type /*, char* etag*/)
{
    pthread_mutex_lock(&delta_stat->lock);
    int i;
    int found = 0;
    for(i = 0; i < ITEM_NUM; ++i){
        if(delta_stat->items[i].present == 1 && !strcmp(delta_stat->items[i].file_id,file_id)){
            found = 1;
            if(strcmp(delta_stat->items[i].file_name,file_name)){
                free(delta_stat->items[i].file_name);
                delta_stat->items[i].file_name = file_name;
            }
            if(strcmp(delta_stat->items[i].modified_time,modified_time)){
                free(delta_stat->items[i].modified_time);
                delta_stat->items[i].modified_time = modified_time;
            }
            if(strcmp(delta_stat->items[i].created_time, created_time)){
                free(delta_stat->items[i].created_time);
                delta_stat->items[i].created_time = created_time;
            }
            if(strcmp(delta_stat->items[i].size, size)){
                free(delta_stat->items[i].size);
                delta_stat->items[i].size = size;
            }/*if(strcmp(delta_stat->items[i].etag, etag)){
                free(delta_stat->items[i].etag);
                delta_stat->items[i].etag = etag;
                free(delta_stat->items[i].cache);
                delta_stat->items[i].cache = NULL;
            }*/
            break;
        }
    }

    if(found == 0){
       for(i = 0; i < ITEM_NUM; ++i){
            if(delta_stat->items[i].present == 0){
                delta_stat->items[i].present = 1;
                delta_stat->size++;
                delta_stat->items[i].file_id = file_id;
                delta_stat->items[i].file_name = file_name;
                delta_stat->items[i].modified_time= modified_time;
                delta_stat->items[i].size = size;
                delta_stat->items[i].created_time = created_time;
                delta_stat->items[i].parent_id = parent_id;
                delta_stat->items[i].type = type;
//                delta_stat->items[i].etag = etag;
                delta_stat->items[i].cache = NULL;
                delta_stat->items[i].recv_size = 0;
                delta_stat->items[i].cache_size =0;
                delta_stat->items[i].body_size =0;
                break;
            }
       }
    }
    pthread_mutex_unlock(&delta_stat->lock);
    return &delta_stat->items[i];
}

int save_delta_string(char* delta)
{
    pthread_mutex_lock(&delta_stat->lock);
    if(delta_stat->delta_token != NULL){
        free(delta_stat->delta_token);
    }
    delta_stat->delta_token = delta;
    pthread_mutex_unlock(&delta_stat->lock);
    return 0;
}

//mutex lock hanlder by caller
int compare_delta(char* delta)
{
    if(delta_stat->delta_token == NULL)
        return -1;
    return strcmp(delta,delta_stat->delta_token);
}




char* generate_more_delta_request(char* token,size_t size, char* next_token)
{

    char *delta_part1_1 = "GET ";
    size_t part1_1_size = strlen(delta_part1_1);

    char* p = strstr(next_token, "/v1.0/drive");
    size_t part1_2_size = strlen(next_token) - (p - next_token);
//    fprintf(stderr,"more delta %zu %s %s\n",size, token, next_token);

    char *delta_part1_3 = " HTTP/1.1\r\n"
        "X-RequestStats: SDK-Version=Android-v1.1.5\r\n"
        "Authorization: bearer ";
    size_t part1_3_size = strlen(delta_part1_3);

    size_t total_size = part1_1_size + part1_2_size + part1_3_size +
        size + strlen(delta_request_part2) + 1;
//    delta_part2 = mallo(part2_size);
//    memset(delta_part2, '\0', part2_size);
//    fprintf(stderr,"more delta 2%zu %s %s\n",size, token, next_token);
    char* delta_request = malloc(total_size);
//    fprintf(stderr,"more delta 3%zu %s %s\n",size, token, next_token);
    memset(delta_request,'\0', total_size);

    size_t pos = 0;
    /* Get */
    memcpy(delta_request,delta_part1_1,part1_1_size);
    pos += part1_1_size;

    /* request body */
    memcpy(delta_request + pos, p, part1_2_size);
    pos += part1_2_size;

    /* request body */
    memcpy(delta_request + pos, delta_part1_3, part1_3_size);
    pos += part1_3_size;

    /* bearer token part*/
    memcpy(delta_request + pos, token, size);
    pos += size;

    /* rest part of request */
    memcpy(delta_request + pos, delta_request_part2, strlen(delta_request_part2));
    pos += strlen(delta_request_part2);

    return delta_request;
}

char* generate_delta_request(char* token,size_t size)
{
    size_t req_part1, req_part2;
    req_part1 = strlen(delta_request_part1);
    req_part2 = strlen(delta_request_part2);
    char* request;
//    fprintf(stderr,"delta_token: %s\n", delta_stat->delta_token);
    if(delta_stat->delta_token != NULL){
#if 1
        char* header = "/v1.0/drive/items/42A638C59AA1EAA8!103/view.delta?token=";
        char* next_token = malloc(strlen(delta_stat->delta_token) + strlen(header) + 1);
        char* p = next_token;
        memset(next_token,'\0',strlen(delta_stat->delta_token) + strlen(header) + 1);

        memcpy(next_token, header, strlen(header));
        memcpy(next_token + strlen(p), delta_stat->delta_token,strlen(delta_stat->delta_token));
        request = generate_more_delta_request(token,size, next_token);
#endif

    }else{
        request = malloc(req_part1 + req_part2 + size +  1);
        memset(request,'\0',req_part1 + req_part2 + size + 1);
        memcpy(request, delta_request_part1,strlen(delta_request_part1));
        memcpy(request + strlen(delta_request_part1), token,size);
        memcpy(request + strlen(delta_request_part1) + size, delta_request_part2,
                strlen(delta_request_part2));
    }
//    free(token);
    return request;
}

//id at deep 4
int get_deep(jsmntok_t* ts, int index)
{
    int deep = 0;
    int tmp = index;

    while(ts[tmp].parent != -1){
        tmp = ts[tmp].parent;
        deep++;
    }
    return deep;
}
static int jsoneq(const char* json, jsmntok_t* tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0){
        return 0;
    }
    return -1;
}

char * get_token_info(char* response, jsmntok_t* ts, size_t size, char* str, int deep)
{
    size_t i;
    for(i = 0; i < size; ++i){

//        fprintf(stderr,"token %d\n",jsoneq(response, &ts[i],str/*"@delta.token"*/));
        if(get_deep(ts,i) == deep && jsoneq(response, &ts[i],str/*"@delta.token"*/) == 0){
           char* info = malloc(ts[i+1].end - ts[i+1].start + 1);
           memset(info, '\0', ts[i+1].end - ts[i+1].start + 1);
           snprintf(info, ts[i+1].end - ts[i+1].start + 1, "%s", response + ts[i+1].start);
           return info;
        }
    }
    return NULL;
}

char ** get_info(char* response, jsmntok_t* ts, size_t size, char* str, size_t* o_size, int deep)
{
    size_t i;
    size_t count = 0;
    char** info = malloc(sizeof(char*) * 1000);
    for(i = 0; i < size; ++i){
        if(get_deep(ts,i) == deep && jsoneq(response, &ts[i],str) == 0){
            if(strcmp(str,"parentReference") == 0){
                char* tmp, *p, *end;
                size_t size;
                tmp = malloc(ts[i+1].end - ts[i+1].start + 1);
                memset(tmp, '\0', ts[i+1].end - ts[i+1].start + 1);
                memcpy(tmp,response+ts[i+1].start, ts[i+1].end - ts[i+1].start);
//                snprintf(tmp, ts[i+1].end - ts[i+1].start + 1, "%s", response + ts[i+1].start);

                p = strstr(tmp,"id\":\"");
                p += strlen("id\":\"");
                end = strstr(p,"\"");

                size = end - p;
                info[count] = malloc(size + 1);

                memset(info[count], '\0', size + 1);
                memcpy(info[count],p,size);

                free(tmp);
                count++;
            }else{
                info[count] = malloc(ts[i+1].end - ts[i+1].start + 1);
                memset(info[count], '\0', ts[i+1].end - ts[i+1].start + 1);
                memcpy(info[count],response+ts[i+1].start, ts[i+1].end - ts[i+1].start);
//                snprintf(info[count], ts[i+1].end - ts[i+1].start +1, "%s", response + ts[i+1].start);
                count++;
            }
        }
    }
    *o_size = count;
    return info;
}

file_type * get_info_type(const char* response, jsmntok_t* ts, size_t size, size_t* o_size)
{
    size_t i;
    size_t count = 0;
    file_type* info = malloc(sizeof(file_type) * 1000);
    for(i = 0; i < size; ++i){
        if(get_deep(ts,i) == 4 && ((jsoneq(response, &ts[i],"folder") == 0)
                ||(jsoneq(response,&ts[i],"file") == 0))){
           info[count] = jsoneq(response,&ts[i],"file") == 0 ? META_FILE : META_FOLDER;
           count++;
        }
    }
    *o_size = count;
    return info;
}

/* TODO */

struct item * check_filelocation(char* fl)
{
    size_t i ;
    char* p;
    for(i = 0; i < delta_stat->size; ++i){
        if((p = strstr(delta_stat->items[i].file_location, fl))){
            if(delta_stat->items[i].cache != NULL && delta_stat->items[i].cache_size > 0)
                return &delta_stat->items[i];
        }
    }
    return NULL;
}

int analyze_delta_response(char* response, char** id, char** lasttime,char **next_token,
        int save_metadata,struct item** ref)
{
    int r;
    jsmn_parser p;
    jsmntok_t *t = malloc(sizeof(jsmntok_t) * 100000);

    jsmn_init(&p);

    r = jsmn_parse(&p, response, strlen(response),t, 100000);
//    fprintf(stderr,"jsmn_parse %d\n", r);


    if(r < 0){
        printf("Failed to parse JSON: %d\n",r);
        return -1;
    }

    if (r < 1 || t[0].type != JSMN_OBJECT){
        printf("Object expected\n");
        return -1;
    }


    char* token =  get_token_info(response,t,r,"@delta.token",1);
//    fprintf(stderr,"delta_token %s\n", token);

    *next_token =  get_token_info(response,t,r,"@odata.nextLink",1);
    if(token == NULL){
        char **ids, **lasttimes,**file_name, **created_time, **parent_id,
             **size/*, ** etag*/;

        file_type * type;
        size_t id_size, name_size, time_size,create_size,type_size,parent_size, s_size, e_size;

        ids= get_info(response,t,r,"id",&id_size,1);
        lasttimes = get_info(response,t,r,"lastModifiedDateTime",&time_size,1);
        file_name = get_info(response,t, r,"name",&name_size,1);
        created_time = get_info(response,t, r,"createddatetime",&create_size,4);
        size = get_info(response,t, r,"size",&s_size,1);
        parent_id = get_info(response,t, r,"parentReference",&parent_size,1);
//        etag = get_info(response, t, r, "etag", &e_size,4);
        type = get_info_type(response,t, r,&type_size);
//        fprintf(stderr, "after get info %s %s\n",ids[0],lasttimes[0]);
//        fprintf(stderr, "after get info %p %p\n",(void*)id,(void*)lasttime);
        *id = ids[0];
        *lasttime = lasttimes[0];
//        fprintf(stderr, "after get info2 %zu\n",id_size);
//        fprintf(stderr, "id %s, lasttime %s\n", *id, *lasttime);
        if(save_metadata){
            assert(id_size == 1);
            size_t i;
            for(i = 0; i < id_size; ++i){
//                fprintf(stderr, "%s \n",ids[i]);
                *ref = update_item(ids[i], file_name[i], lasttimes[i],size[i],
                        created_time[i],parent_id[i],type[i]/*,etag[i] */);
//                fprintf(stderr, "after update\n");
            }
        }
//        fprintf(stderr, "after get info2\n");
        return 1;
    }

    if(compare_delta(token) != 0){
        char **id, **file_name, **modified_time, **created_time, **parent_id,
             **size/*, ** etag*/;
        file_type * type;
        size_t id_size, name_size, time_size,create_size,type_size,parent_size, s_size, e_size;

        save_delta_string(token);

        id = get_info(response,t, r,"id",&id_size,4);
        file_name = get_info(response,t, r,"name",&name_size,4);
        modified_time = get_info(response,t, r,"lastModifiedDateTime",&time_size,4);
        created_time = get_info(response,t, r,"createdDateTime",&create_size,4);
        size = get_info(response,t, r,"size",&s_size,4);
        parent_id = get_info(response,t, r,"parentReference",&parent_size,4);
//        etag = get_info(response, t, r, "etag", &e_size,4);
        type = get_info_type(response,t, r,&type_size);

        size_t i;
//        fprintf(stderr,"%zu %zu %zu %zu %zu %zu %zu\n", id_size, name_size,time_size,create_size,s_size,parent_size, type_size);
        for(i = 0; i < id_size; ++i){
            update_item(id[i], file_name[i], modified_time[i],size[i],
                    created_time[i],parent_id[i],type[i]/*,etag[i] */);
        }
        size_t j = 0;
#if 0
//        fprintf(stderr,"delta_size %zu\n", delta_stat->size);
        for(;j < delta_stat->size;++j){
        printf("%s %s %s %s %s %d %s\n",delta_stat->items[j].file_id,
                delta_stat->items[j].file_name,
                delta_stat->items[j].modified_time,
                delta_stat->items[j].size,
                delta_stat->items[j].created_time,
                (int)delta_stat->items[j].type,
                delta_stat->items[j].parent_id);
        }
#endif
#if 0
        free(id);
        free(file_name);
        free(modified_time);
        free(parent_id);
        free(size);
        free(created_time);
        free(type);
#endif
    }
#if 0
    char *file_id, *file_name, *modified_time;
    file_id = get_file_id(response);
    file_name = get_file_name(response);
    modified_time = get_modified(response);

    update_item(file_id, file_name, modified_time);
#endif
    return 0;
}
int save_metadata(char* response,struct item** ref)
{

    char* id = NULL,  *lasttime = NULL, *next_token = NULL;
    int rv = analyze_delta_response(response,&id,&lasttime,&next_token,1,ref);
//    fprintf(stderr,"save_metadata \n");
    return rv;
}

const char* start_part =
"{\r   \"data\": [\r      ";
const char* end_part =
"\r   ],\r   \"paging\": {\r      \r   }\r}";

const char* item_metadata_start =
"{\r";

const char* item_metadata_id = "         \"id\": \"";

const char* item_metadata_from =
    "         \"from\": {\r"
    "            \"name\": \"mos wang\", \r"
    "            \"id\": \"42a638c59aa1eaa8\"\r"
    "         }, \r";

const char* item_metadata_name =
    "         \"name\": \"";

const char* item_metadata_description = "         \"description\": \"\", \r";

const char* item_metadata_p_id = "         \"parent_id\": \"folder.42a638c59aa1eaa8.";

const char* item_metadata_size = "         \"size\": ";
const char* item_metadata_upload = "         \"upload_location\": \"https://apis.live.net/v5.0/folder.43a638c59aa1eaa8.";
const char* item_metadata_comments =
"         \"comments_count\": 0, \r"
"         \"comments_enabled\": false, \r"
"         \"is_embeddable\": true, \r";
const char* item_metadata_count = "         \"count\": ";
const char* item_metadata_link =
"         \"link\": \"https://onedrive.live.com/redir.aspx?cid=42a638c59aa1eaa8&page=browse&resid=";
const char* item_metadata_type = "         \"type\": \"";
const char* item_metadata_shared =
"         \"shared_with\": {\r"
"            \"access\": \"Just me\"\r"
"         }, \r";
const char* item_metadata_c_time = "         \"created_time\": \"";
const char* item_metadata_u_time = "         \"updated_time\": \"";
const char* item_metadata_cu_time = "         \"client_updated_time\": \"2016-04-04T04:03:54+0000\"\r      }";


size_t get_folder_count(char* file_id)
{
    size_t i;
    size_t count = 0;
    for(i = 0; i < delta_stat->size; ++i){
        if(strcmp(file_id,delta_stat->items[i].parent_id) == 0){
            count++;
        }
    }
    return count;
}

char *generate_file_metadata(struct item *i)
{
    char *metadata, *p;

    char* posfix = "\", \r";
    metadata = malloc(6000);
    p = metadata;
    memset(metadata,'\0',6000);

    memcpy(metadata,item_metadata_start,strlen(item_metadata_start));
    metadata += strlen(item_metadata_start);

//    printf("metadata %zu, %s\n",strlen(item_metadata_start),item_metadata_start);
    //generate id;
    memcpy(metadata,item_metadata_id,strlen(item_metadata_id));
    metadata += strlen(item_metadata_id);
    char *format;
    if(i->type == META_FOLDER){
        format = "folder.42a638c59aa1eaa8.";
    }else {
        format = "file.42a638c59aa1eaa8.";
    }
    memcpy(metadata, format,strlen(format));
    metadata += strlen(format);
    memcpy(metadata,i->file_id,strlen(i->file_id));
    metadata += strlen(i->file_id);
    memcpy(metadata, "\", \r",strlen("\", \r"));
    metadata += strlen("\", \r");

//    printf("metadata from %zu, %s\n",strlen(item_metadata_start),item_metadata_start);
    //from
    memcpy(metadata,item_metadata_from,strlen(item_metadata_from));
    metadata +=  strlen(item_metadata_from);

    //name
    memcpy(metadata, item_metadata_name,strlen(item_metadata_name));
    metadata += strlen(item_metadata_name);

    memcpy(metadata, i->file_name, strlen(i->file_name));
    metadata +=  strlen(i->file_name);

    memcpy(metadata, posfix,strlen(posfix));
    metadata += strlen(posfix);

    //description
    memcpy(metadata, item_metadata_description,strlen(item_metadata_description));
    metadata += strlen(item_metadata_description);
    //parent+id
    if(strcmp(i->parent_id,"42A638C59AA1EAA8!103") == 0){
        memcpy(metadata, item_metadata_p_id,strlen(item_metadata_p_id) - 1);
        metadata += strlen(item_metadata_p_id) - 1;
        memcpy(metadata, posfix,strlen(posfix));
        metadata += strlen(posfix);
    }else {
        memcpy(metadata, item_metadata_p_id,strlen(item_metadata_p_id));
        metadata += strlen(item_metadata_p_id);
        memcpy(metadata, i->parent_id,strlen(i->parent_id));
        metadata += strlen(i->parent_id);
        memcpy(metadata, posfix,strlen(posfix));
        metadata += strlen(posfix);
    }
    //size
    memcpy(metadata, item_metadata_size,strlen(item_metadata_size));
    metadata += strlen(item_metadata_size);
    memcpy(metadata, i->size,strlen(i->size));
    metadata += strlen(i->size);
    memcpy(metadata, ",\r",strlen(",\r"));
    metadata += strlen(",\r");

    //loaction
    memcpy(metadata, item_metadata_upload,strlen(item_metadata_upload));
    metadata += strlen(item_metadata_upload);
    memcpy(metadata, i->file_id,strlen(i->file_id));
    metadata += strlen(i->file_id);
    if(i->type == META_FOLDER){
        memcpy(metadata, "/files/\", \r",strlen("/files/\", \r"));
        metadata += strlen("/files/\", \r");
    }else {
        memcpy(metadata, "/content/\", \r",strlen("/content/\", \r"));
        metadata += strlen("/content/\", \r");
    }

    //comments
    memcpy(metadata, item_metadata_comments,strlen(item_metadata_comments));
    metadata += strlen(item_metadata_comments);

    //count
    if(i->type == META_FOLDER){
        memcpy(metadata, item_metadata_count,strlen(item_metadata_count));
        metadata += strlen(item_metadata_count);
        size_t count = get_folder_count(i->file_id);
        char str[15];
        memset(str,'\0',15);
        sprintf(str,"%zu",count);
        memcpy(metadata,str,strlen(str));
        metadata += strlen(str);
        memcpy(metadata, posfix,strlen(posfix));
        metadata += strlen(posfix);
    }else{
        const char* str = "      \"source\": \"https://n2wzjq-bn1306.files.1drv.com/y3m1tFhjiVX8digKUT9aH9QbbW3WT-3vgEYpTbbuI8SYBndmm9yNETzi2soSEC4u6m08BunNTEhGBQL_yo2tJ3G2t7OyAlA8dcn9dQy8Ah8Tj94DwRhvpodrMoeduC4UVvVILONA9WbPURA8jR75K5vSU8LyOmH4A-x-oE1fHdELT0/1.txt?psid=1\", \r";
        memcpy(metadata, str,strlen(str));
        metadata += strlen(str);
    }

    //link
    memcpy(metadata, item_metadata_link,strlen(item_metadata_link));
    metadata += strlen(item_metadata_link);
    memcpy(metadata,i->file_id, strlen(i->file_id));
    metadata += strlen(i->file_id);
    memcpy(metadata,"&parId=",strlen("&parId"));
    metadata += strlen("&parId");
    memcpy(metadata,i->parent_id,strlen(i->parent_id));
    metadata += strlen(i->parent_id);
    memcpy(metadata, posfix,strlen(posfix));
    metadata += strlen(posfix);

    //type
    memcpy(metadata, item_metadata_type,strlen(item_metadata_type));
    metadata += strlen(item_metadata_type);
    if(i->type == META_FOLDER){
        memcpy(metadata, "folder\", \r",strlen("folder\", \r"));
        metadata += strlen("folder\", \r");
    }else {
        memcpy(metadata, "file\", \r",strlen("file\", \r"));
        metadata += strlen("file\", \r");
    }

    //shared
    memcpy(metadata, item_metadata_shared,strlen(item_metadata_shared));
    metadata += strlen(item_metadata_shared);
    //create time

    memcpy(metadata, item_metadata_c_time,strlen(item_metadata_c_time));
    metadata += strlen(item_metadata_c_time);
    memcpy(metadata, i->created_time,19);
    metadata += 19;
    memcpy(metadata, "+0000\", \r",strlen("+0000\", \r"));
    metadata += strlen("+0000\", \r");

    memcpy(metadata, item_metadata_u_time,strlen(item_metadata_u_time));
    metadata += strlen(item_metadata_u_time);
    memcpy(metadata, i->modified_time,19);
    metadata += 19;
    memcpy(metadata, "+0000\", \r",strlen("+0000\", \r"));
    metadata += strlen("+0000\", \r");

    memcpy(metadata, item_metadata_cu_time,strlen(item_metadata_cu_time));
    metadata += strlen(item_metadata_cu_time);
    return p;
}

char *generate_metadata(char *folder_id)
{
    size_t count = get_folder_count(folder_id);

//    char** metadata_array = malloc(sizeof(char*) * count);
    char* file_meta;
    char* p;
    char* metadata = malloc(390000);
    p = metadata;
    memset(metadata,'\0',390000);
    memcpy(metadata,start_part,strlen(start_part));
//    fprintf(stderr,"metadata count %zu\n",delta_stat->size);
    metadata += strlen(start_part);
    size_t i,j;
//    fprintf(stderr,"metadata %zu\n",delta_stat->size);
    for(i = 0, j = 0; i < delta_stat->size; ++i){
#if 1
        if(strcmp(folder_id,delta_stat->items[i].parent_id) == 0){
           file_meta = generate_file_metadata(&delta_stat->items[i]);
//           printf("metadata_array %zu %zu\n",j,strlen(file_meta));
           memcpy(metadata,file_meta, strlen(file_meta));
           metadata += strlen(file_meta);
           j++;
           if(j != count){
               memcpy(metadata,", ",2);
               metadata += 2;
           }else{
               memcpy(metadata,end_part,strlen(end_part));
               metadata += strlen(end_part);
           }
           free(file_meta);
        }
#endif
    }
    return p;

}

int save_cache(char* id, char *data,size_t cur_size, size_t head_size, size_t body_size)
{
    /* /
    it->cache = data;
    it->cache_size = size;
    return 0;
    */
    size_t i;
    for(i = 0; i < delta_stat->size; ++i){
//       fprintf(stderr, "save_cache it_filelocation: %s\n",delta_stat->items[i].file_location);
//        fprintf(stderr, "save_cache filelocation: %s\n",file_location);
        if(strcmp(delta_stat->items[i].file_id,id) == 0){
            struct item* it = &delta_stat->items[i];
            if(it->cache != NULL && head_size!= 0){
                free(it ->cache);
                it->cache = NULL;
                it->cache_size = 0;
                it->recv_size = 0;
                it->body_size = 0;
            }else if(head_size == 0){
                memcpy(it->cache + it->recv_size,data,cur_size);
                it->recv_size += cur_size;
                return i;
            }
            /* fprintf(stderr,"cache saved %zu\n",i); */
            delta_stat->items[i].cache = (char*)malloc(head_size + body_size);
            memcpy(delta_stat->items[i].cache + delta_stat->items[i].recv_size,data,cur_size);
            delta_stat->items[i].cache_size = head_size + body_size;
            delta_stat->items[i].body_size = body_size;
            delta_stat->items[i].recv_size = cur_size;
            /* fprintf(stderr,"in save_cache 2 %s %zu,%p \n",delta_stat->items[i].file_id,  delta_stat->items[i].cache_size,delta_stat->items[i].cache); */
            return i;
        }
    }
    return -1;
}

int get_cache(char *id, char **data, size_t *size)
{
    size_t i;
    for(i = 0; i < delta_stat->size; ++i){
        if(!strcmp(delta_stat->items[i].file_id,id) && delta_stat->items[i].cache != NULL){
//            fprintf(stderr,"in get_cache 1 %s %zu,%s \n",delta_stat->items[i].file_id,  delta_stat->items[i].cache_size,delta_stat->items[i].cache);
            *data = malloc(delta_stat->items[i].cache_size);
            memcpy(*data, delta_stat->items[i].cache,
                    delta_stat->items[i].cache_size);
            *size = delta_stat->items[i].cache_size;
            return 0;
        }
    }
    return -1;
}


const char* md_request =
"GET /v1.0/drive/items/?expand=children(expand%3Dthumbnails)%2Cthumbnails HTTP/1.1\r\n"
"X-RequestStats: SDK-Version=Android-v1.1.5\r\n"
"Authorization: bearer \r\n"
"User-Agent: Dalvik/1.6.0 (Linux; U; Android 4.4.4; GT-I9500 Build/KTU84Q)\r\n"
"Host: api.onedrive.com\r\n"
"Connection: Keep-Alive\r\n"
"Accept-Encoding: gzip\r\n\r\n";

char*
generate_md_request(char* id, char* bearer_token,size_t s)
{
    char* request;
    size_t size, pos;
    size = strlen(id) + strlen(bearer_token) + strlen(md_request) + 1;
    request = malloc(size);

    memset(request,'\0', size);

    char* p = strstr(md_request,"items/");
    p += strlen("items/");

    memcpy(request, md_request, p - md_request);
    pos = p - md_request;

    memcpy(request + pos, id, strlen(id));

    pos += strlen(id);

    char* q = strstr(md_request,"bearer ");
    q += strlen("bearer ");
    memcpy(request + pos, p, q - p);
    pos += (q - p);

    memcpy(request + pos, bearer_token,s);

    pos += s;
    memcpy(request + pos, q, strlen(q));
    return request;
}

struct item * check_metadata(char* id, char* lasttime)
{
    size_t i;
    for(i = 0; i < delta_stat->size; ++i){
        if(!strcmp(delta_stat->items[i].file_id,id) && !strcmp(delta_stat->items[i].modified_time,lasttime)){
            return &delta_stat->items[i];
        }
    }
    return NULL;
}

void state_lock()
{
    pthread_mutex_lock(&delta_stat->lock);
}
void state_unlock()
{
    pthread_mutex_unlock(&delta_stat->lock);
}
