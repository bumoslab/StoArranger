#ifndef __HELPFNC__
#define __HELPFNC__
#include <stdio.h>
#include <stdarg.h>
//#define TRACE_DEBUG
#ifdef TRACE_DEBUG
#define client_to_server_print(request)\
{\
		fprintf(stderr,"\n");\
		fprintf(stderr,"###############################################\n");\
		fprintf(stderr,"##          Client to Server Request         ##\n");\
		fprintf(stderr,"%s\n",request);\
		fprintf(stderr,"##        Client to Server Request END       ##\n");\
		fprintf(stderr,"###############################################\n");\
}
#else
#define client_to_server_print(request)
#endif


#ifdef TRACE_DEBUG
#define server_to_client_print(response)\
{\
		fprintf(stderr,"\n");\
		fprintf(stderr,"###############################################\n");\
		fprintf(stderr,"##          Server to Client Response        ##\n");\
		fprintf(stderr,"%s\n",response);\
		fprintf(stderr,"##        Server to Client Response END      ##\n");\
		fprintf(stderr,"###############################################\n");\
}
#else
#define server_to_client_print(response)
#endif


#ifdef TRACE_DEBUG
#define client_to_proxy_print(request)\
{\
	fprintf(stderr,"\n");\
	fprintf(stderr,"##############################################\n");\
	fprintf(stderr,"##          Client to Proxy Request         ##\n");\
	fprintf(stderr,"%s\n",request);\
	fprintf(stderr,"##        Client to Proxy Request END       ##\n");\
	fprintf(stderr,"###############################################\n");\
}
#else
#define client_to_proxy_print(request)
#endif

#ifdef TRACE_DEBUG
#define proxy_to_client_print(response)\
{\
	fprintf(stderr,"\n");\
	fprintf(stderr,"##############################################\n");\
	fprintf(stderr,"##          Proxy to Client Response        ##\n");\
	fprintf(stderr,"%s\n",response);\
	fprintf(stderr,"##        Proxy to Client Respnse END       ##\n");\
	fprintf(stderr,"###############################################\n");\
}
#else
#define proxy_to_client_print(response)
#endif

#ifdef TRACE_DEBUG
#define proxy_to_server_print(request)\
{\
\
	fprintf(stderr,"\n");\
	fprintf(stderr,"###############################################\n");\
	fprintf(stderr,"##          Proxy to Server Request          ##\n");\
	fprintf(stderr,"%s\n",request);\
	fprintf(stderr,"##        Proxy to Server Request END        ##\n");\
	fprintf(stderr,"###############################################\n");\
}
#else
#define proxy_to_server_print(request)
#endif

#ifdef TRACE_DEBUG
#define server_to_proxy_print(response)\
{\
	fprintf(stderr,"\n");\
	fprintf(stderr,"###############################################\n");\
	fprintf(stderr,"##          Server to Proxy Response         ##\n");\
	fprintf(stderr,"%s\n",response);\
	fprintf(stderr,"##        Server to Proxy Response END       ##\n");\
	fprintf(stderr,"###############################################\n");\
}
#else
#define server_to_proxy_print(response)
#endif
char *
compress_and_chunkedEncoding(char* input_data, size_t i_size, size_t * o_size);
char*
decompress_and_chunkedDecoding(char* input_data,size_t i_size,size_t * o_size);
char*
gzip_compress(void* input_data,size_t i_size, size_t* o_size);
char*
gzip_uncompress(void* input_data,size_t i_size,size_t* o_size);
int
parse_request(char * request, char** method, char** id, char** query, char** type);

int multi_free(int num, ...);
#endif/* __HELPFNC__*/
