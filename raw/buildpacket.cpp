#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <cstring>
// u_char radiotap_template[] = { 0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x91, 0xcd, 0x67, 0x0b, 0x00, 0x00, 0x00, 0x00,
//     0x12, 0x24, 0xad, 0x16, 0x40, 0x01, 0xab, 0xa6, 0x01 };

static u_char radiotap_template[] = { 0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00};

u_int32_t seq = 0;

#define RadioTaplen (sizeof(radiotap_template))

#define DotTYlen 40

#define MAXlength 512

#define TYID 0x0818000054592a32LL

#define BUILD 0
#define CONTROL 1
#define DATA 2

#define B_HERE 0
#define B_UPDATE 1
#define B_LEAVE 2
#define boardcast 0xffffffffffffffLL

#define C_ACK 0

#define D_UDP 0
#define D_TCP 1


void putradiotap(u_char *buf)
{
    memcpy(buf, radiotap_template, RadioTaplen);
    return;
}

u_int32_t get_seq()
{
    return seq++;
}

u_int16_t checksum(u_int16_t* buf)
{
    u_int16_t ret = 0;
    for (int i = 0; i < 20; ++i)
        ret ^= buf[i];
    return ret;
}


void buildDotTY(u_char *buf, u_char type, u_char subtype, u_int64_t addr1, u_int64_t addr2, u_int64_t addr3)
{
    u_int32_t now = get_seq();
    u_int64_t ID = TYID;
    memcpy(buf, &ID, 8);
    *(buf+8) = type;
    *(buf+9) = subtype;
    memcpy(buf+10, &now, 4);
    addr1 &= 0xffffffffffffffLL;
    memcpy(buf+16,&addr1,8);
    addr2 &= 0xffffffffffffffLL;
    memcpy(buf+24,&addr2,8);
    addr3 &= 0xffffffffffffffLL;
    memcpy(buf+32,&addr3,8);
    u_int16_t check = checksum((u_int16_t*)buf);
    memcpy(buf+14, &check, 2);
}



u_int32_t datachecksum(u_int32_t * buf)
{
    u_int32_t ret = 0, lenth = buf[0] >> 2;
    for (int i = 0; i < lenth; ++i)
        ret ^= buf[i];
    return ret;
}


u_char* buildrawpackage(u_char* input, u_int32_t length)
{
    u_int32_t reallength = ((length+3)&0xfffffffc)+8;
    if (reallength>MAXlength)
        return NULL;
    u_char* newbuf = (u_char*)malloc(reallength+DotTYlen);
    memset(newbuf,0,reallength+DotTYlen);
    memcpy(newbuf+DotTYlen,&reallength,4);
    memcpy(newbuf+DotTYlen+4, input, length);
    u_int32_t check = datachecksum((u_int32_t*)(newbuf+DotTYlen));
    memcpy(newbuf+DotTYlen+4,&check,4);
    return newbuf;
}

