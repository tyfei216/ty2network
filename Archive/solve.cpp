#include "ty2.h"
#include "solve.h"
#include "route.h"
#include "send.h"
#include "init.h"

u_char radiotap_template[] = { 0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00};

u_int8_t gettype(u_char* buf)
{
    return buf[8];
}

u_int8_t getsubtype(u_char* buf)
{
    return buf[9];
}

u_int32_t getseq(u_char* buf)
{
    u_int32_t ret;
    memcpy(&ret, buf+10, 4);
    return ret;
}

u_int64_t getsrcaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+16, 8);
    ret &= 0xffffffffffffffLL;
    return ret;
}

u_int64_t getdstaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+24, 8);
    return ret;
}

u_int64_t getnhaddr(u_char* buf)
{
    u_int64_t ret;
    memcpy(&ret, buf+32, 8);
    return ret;
}

u_int8_t getttl(u_char* buf)
{
    return buf[16];
}

u_int32_t getradiotaplen(u_char* buf)
{
    return (u_int32_t)buf[2]+((u_int32_t)buf[3]<<8);
}



u_char* getdata(u_char *buf)
{
    return buf + 40;
}

u_int32_t getdatalenth(u_char* buf)
{
    return *((uint32_t *) (buf + 40));
}


u_int32_t datachecksum(u_int32_t * buf)
{
    u_int32_t ret = 0, lenth = buf[0] >> 2;
    for (int i = 0; i < lenth; ++i)
        ret ^= buf[i];
    return ret;
}

u_int64_t getCurrentTime()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void putradiotap(u_char *buf)
{
    memcpy(buf, radiotap_template, RadioTaplen);
    return;
}
