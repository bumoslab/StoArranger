#include <sys/types.h>
#include <zlib.h>


extern int ZEXPORT my_inflate OF((z_streamp strm, int flush));
extern int ZEXPORT my_inflate_arm OF((z_streamp strm, int flush)){
    return my_inflate(strm,flush);
}
