#ifndef __STATE__
#define __STATE__
#include <pthread.h>
#define ITEM_NUM 1000

typedef enum{
    META_FOLDER = 0,
    META_FILE = 1
}file_type;

struct item{
    int present;
    char* file_id;
    char* file_name;
    char* modified_time;
    char* created_time;
    char* parent_id;
    file_type type;
    char* size;
    char* etag;
    char* cache;
    char* file_location;
    size_t cache_size;
    size_t body_size;
    size_t recv_size;
};

struct state{
    pthread_mutex_t lock;
    char *delta_token;
    struct item items[ITEM_NUM];
    size_t size;
};


int stat_init();

//int update_item(char* file_id, char* file_name,char* modified_time);
//int save_delta_string(char* delta);
//int compare_delta(char* delta);

char* generate_delta_request(char* token,size_t size);
char* generate_more_delta_request(char* toekn,size_t size, char* next_token);

int analyze_delta_response(char* response,char** id, char** lasttime,char** next_token,
        int save_metadata, struct item ** ref);
char* generate_metadata(char* file_id);
int save_cache(char* id, char *data, size_t cur_recv, size_t header_size,size_t body_size);
int get_cache(char* id,char** data, size_t* size );
char* generate_md_request(char* id, char* bearer_token,size_t size);
struct item*  check_metadata(char* id, char* lasstime);
void state_lock();
void state_unlock();
struct item * check_filelocation(char* start);
int save_metadata(char * response, struct item ** ref);
#endif
