#include <sys/types.h>
#include <sys/socket.h>


extern int my_socket(int domain, int type, int protocol);
int my_socket_arm (int domain, int type, int protocol){
    my_socket(domain, type, protocol);
}



extern int my_sendto(int fd, const void* buf,size_t len, int flag,
        const struct sockaddr *dest_addr,socklen_t addrlen);
int my_sendto_arm(int fd, const void* buf,size_t len, int flag,
        const struct sockaddr *dest_addr,socklen_t addrlen){
   my_sendto(fd,buf,len,flag,dest_addr,addrlen);
}
