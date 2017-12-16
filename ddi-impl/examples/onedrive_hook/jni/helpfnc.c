/*
 * =====================================================================================
 *
 *       Filename:  helpfnc.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  04/25/2016 05:10:54 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */
#include "helpfnc.h"
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <string.h>
#include <assert.h>
#include "log.h"

char* search_character(char* data,size_t len)
{
    size_t i = 0;
    while(i < len - 1){
        if(data[i] == '\r' && data[i+1] =='\n'){
            return data + i;
        }
        i++;
    }
    return NULL;
}

char* chunked_decode(char* data,size_t len,size_t* o_size)
{
    size_t pos_index;
    int flag;

    char* pos,*prev;

    char* size_str = malloc(sizeof(char) * 20);
    int size = 0;
    int total_size = 0;
    memset(size_str,'\0',20);
    char* result = malloc(sizeof(char) * 200);
    memset(result,'\0',100);

    prev = pos = data;

    pos_index = 0;
    flag = 0;

    while(pos_index < len){
        if((pos = search_character(prev,len - pos_index))){
            if(flag == 0){
                flag = 1;
                memcpy(size_str,prev,pos - prev);
                size = strtoul(size_str,NULL,16);
                prev = pos + 2;
                memset(size_str,'\0',20);
                pos_index = prev - data;
            }else{
                if(size == 0){
                    flag = 0;
                    pos_index += 2;
                    prev = pos + 2;
                    continue;
                }else{
//                    printf("data prev[0]:%02x ",(unsigned char)prev[0]);
                    memcpy(result + total_size, prev, size);
                    total_size += size;
                    prev = pos + 2;
                    pos_index += size + 2;
                    flag = 0;
//                    printf("pos_index %d total_size %d\n",pos_index,total_size);
                }
            }
        }
    }
    *o_size = total_size;
    return result;
}

char*
chunked_encode(char* data, size_t len, size_t* o_size)
{
    char *encoded_result;
    encoded_result = malloc(400);
    memset(encoded_result,'\0',400);

    char prefex_size[] = {48,48,48,48,48,48,48,49,13,10};
    char data_posfix[] = {13,10};
    char end_tail[] = {48,13,10,13,10};

    size_t i = 0;
    size_t input_index = 0;
    size_t pos_index = 0;

    for(i = 0; i < 12; ++i){
        memcpy(encoded_result + pos_index, prefex_size, sizeof prefex_size);
        pos_index += sizeof prefex_size;
        memcpy(encoded_result + pos_index, data + input_index,1);
        input_index += 1;
        pos_index += 1;
        memcpy(encoded_result + pos_index, data_posfix, 2);
        pos_index += 2;
    }

    unsigned int rest_data_size = len - input_index;
    char hex[5];
    memset(hex,'\0',5);
    sprintf(&hex[0],"%04x",rest_data_size);

    memcpy(encoded_result + pos_index, hex,4);
    pos_index += 4;
    memcpy(encoded_result + pos_index, data_posfix,2);
    pos_index += 2;

    memcpy(encoded_result + pos_index, data + input_index, rest_data_size);
    pos_index += rest_data_size;
    input_index += rest_data_size;
    assert(input_index == len );
    memcpy(encoded_result + pos_index, data_posfix, sizeof data_posfix);
    pos_index += sizeof data_posfix;
    memcpy(encoded_result + pos_index, end_tail, sizeof end_tail);
    pos_index += sizeof end_tail;
    *o_size = pos_index ;
    return encoded_result;
}


char*
gzip_compress(void* input_data, size_t i_size, size_t* o_size)
{
    char *b = malloc(100000);
    memset(b,'\0',100000);

    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;

    defstream.avail_in = (uInt)i_size;
    defstream.next_in = (Bytef* )input_data;
    defstream.avail_out = (uInt)190000;
    defstream.next_out = (Bytef *)b;
    if(deflateInit2(&defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY)){

    }

    deflate(&defstream,Z_FINISH);
    deflateEnd(&defstream);


    *o_size = defstream.total_out;

    return b;
}

char*
gzip_uncompress(void* input_data, size_t i_size, size_t* o_size)
{
    int err;
    char* c = malloc(700000);
    memset(c,'\0',700000);
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    // setup "b" as the input and "c" as the compressed output
    infstream.avail_in = (uInt)i_size;//(uInt)((char*)defstream.next_out - compressed_data); // size of input
    infstream.next_in = (Bytef *)input_data; // input char array
    infstream.avail_out = (uInt)700000; // size of output
    infstream.next_out = (Bytef *)c; // output char array

    // the actual DE-compression work.
    if(inflateInit2(&infstream,16+MAX_WBITS) == Z_OK){
//        printf("3 Uncompressed size is: %lu\n", infstream.total_out);
    }

    err = inflate(&infstream, Z_NO_FLUSH);
    if(err != Z_STREAM_END){
///        printf("4 Uncompressed size is: %d\n", err);
    }
    inflateEnd(&infstream);

    *o_size = infstream.total_out;
    return c;
}

char *
compress_and_chunkedEncoding(char* input_data, size_t i_size, size_t * o_size)
{
    char *compressed;
    char *result;
    size_t compressed_size;
    compressed = gzip_compress(input_data,i_size,&compressed_size);
    result = chunked_encode(compressed,compressed_size,o_size);
    return result;
}

char*
decompress_and_chunkedDecoding(char* input_data,size_t i_size,size_t * o_size)
{
    char *decode;
    char *result;
    size_t decode_size;

    decode = chunked_decode(input_data,i_size,&decode_size);
    result = gzip_uncompress(decode,decode_size,o_size);
    return result;

}


char*
get_method(const char* s)
{
    char * method;
    method = malloc(8);
    memset(method,'\0',8);
    size_t i = 0;
    while(s[i] != ' '){
        method[i] = s[i];

        ++i;
    }
//    printf("%zu\n",i);
    return method;
#if 0
    if(strstr(s,"GET")){
        memcpy(method,"GET",3);
    }else if(strstr(s,"PUT")){
        memcpy(method,"GET",3);
    }
#endif
}

int
get_id_type(const char* s,char **id, char **type)
{
    char *p;
    if((p = strstr(s,"42a638c59aa1eaa8."))){
        p += strlen("42a638c59aa1eaa8.");

        size_t i = 0;
        while(p[i] != '/' && p[i] != '\0'){
            ++i;
        }

        *id = malloc(i + 1);
        memset(*id, '\0', i + 1);
        memcpy(*id, p, i);

        p = p + i + 1;

        i = 0;
        while(p[i] != '?' && p[i] != ' ') i++;

        *type = malloc(i + 1);
        memset(*type, '\0', i + 1);
        memcpy(*type, p, i);

        return 0;
    }
    return -1;
}

char*
get_query(const char* s)
{
    size_t i = 0;
    size_t j = 0;
    size_t size;
    char* query;

    while(s[i] != '?' && s[i] != '\0')
        ++i;

    j = i;
    while(s[i] != ' ' && s[i] != '\0')
        ++i;

    if(i == j)  return NULL;

    size = i - j - 1;

    query = malloc(size + 1);
    memset(query,'\0',size + 1);
    memcpy(query,s + j + 1, size);

    return query;
}


int parse_request(const char * request, char** method, char** id, char** query, char** type)
{
    *method = get_method(request);
    *query = get_query(request);

    int rv = get_id_type(request, id, type);
//    log("method %s type : %s\n",*method, *type);
    //fprintf(stderr, "method %s, type %s\n",*method,*type);
    if(strcmp(*method, "GET") == 0 && strcmp(*type,"files") == 0)
        return 0;
    else if(strcmp(*method, "GET") == 0 && strcmp(*type,"content") == 0)
        return 1;
    return -1;
}

int multi_free(int num, ...)
{
    va_list args;
    int i;
    va_start(args, num);
    for(i = 0; i < num; i++){
        int *tmp = va_arg(args,void*);
        free(tmp);
    }
    va_end(args);
    return 0;
}
