#include <sys/types.h>
#include <string.h>
#include <cstdlib>
#include <stdio.h>
#include <unistd.h>

inline u_int8_t gettype(u_char* buf)
{
    return buf[8];
}

inline u_int8_t getsubtype(u_char* buf)
{
    return buf[9];
}

inline u_int32_t getseq(u_char* buf)
{
    u_int32_t ret;
    memcpy(&ret, buf+10, 4);
    return ret;
}

inline u_int64_t getsrcaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+16, 8);
    ret &= 0xffffffffffffffLL;
    return ret;
}

inline u_int64_t getdstaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+24, 8);
    return ret;
}

inline u_int64_t getnhaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+32, 8);
    return ret;
}

inline u_int8_t getttl(u_char* buf)
{
    return buf[16];
}

inline u_int32_t getradiotaplen(u_char* buf)
{
    return (u_int32_t)buf[2]+((u_int32_t)buf[3]<<8);
}