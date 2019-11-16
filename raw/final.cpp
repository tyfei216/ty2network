
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include <deque>
#include <pthread.h>
#include <map>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pthread.h>
#include <ctime>
#include <sys/time.h>

using namespace std;

static u_char radiotap_template[] = { 0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00};

u_int32_t seq = 0;

#define RadioTaplen (sizeof(radiotap_template))

#define DotTYlen 40

#define MAXlength 512

//#define TYID 0x0818000054592a32LL
#define TYID 0x322a595400001808LL
#define IDTY 0x322a5954

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


struct TY_TAG
{
    u_int64_t stamp;
    u_int64_t nexthop;
    u_int8_t ttl;
};

//THis is route table
pthread_mutex_t Rp;
map<u_int64_t, TY_TAG> routelist;

#define INTERVAL 3000
#define MAXTTL 32

int sendfd, listenfd;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025


typedef pair<u_char*, u_int32_t> pp;
#define HERE_DELAY 500

u_int64_t MYADDR;

pthread_mutex_t Bp;
deque<pp> Bpackages;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025

typedef pair<u_char*, u_int32_t> pp;

struct sockaddr_ll sll;
socklen_t len = sizeof(sll);

pthread_mutex_t Tp;
deque<pp> Tpackages;

pthread_mutex_t Mp;
deque<pp> Mpackages;

u_char mybuf[10000];
u_int64_t sendaddr;


static u_char buf[6000];

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



inline u_char* getdata(u_char *buf)
{
    return buf + 40;
}

inline u_int32_t getdatalenth(u_char* buf)
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

void updatelist()
{
    pthread_mutex_lock(&Rp);
    u_int64_t now = getCurrentTime();
    map<u_int64_t, TY_TAG>::iterator it, temp;
    for (it = routelist.begin();it!=routelist.end();)
    {
        if (it->second.stamp+INTERVAL<now)
        {
            temp = it;
            ++it;
            routelist.erase(temp);
        }
        else
            ++it;
    }
    pthread_mutex_unlock(&Rp);
}


void updatekey(u_int64_t key, u_int64_t addr, u_int64_t now)
{
    //printf("receive update\n");
    u_int64_t addr1 = key & 0xffffffffffffffLL;
    u_int8_t ttl = ((key >> 56) & 0xff)+1;
    if (ttl>MAXTTL) return;
    //printf("update %llx %llx %llx\n", key, addr, now);
    pthread_mutex_lock(&Rp);
    map<u_int64_t, TY_TAG>::iterator it = routelist.find(addr1);
    if (it == routelist.end())
    {
        TY_TAG TY;
        TY.stamp = now;
        TY.nexthop = addr;
        TY.ttl = ttl;
        routelist.insert(make_pair(addr1, TY));
    }
    else
    {
        if (it->second.ttl >= ttl)
            it->second.stamp = now;
        if (it->second.ttl>ttl)
        {
            it->second.ttl = ttl;
            it->second.nexthop = addr;
        }
    }
    pthread_mutex_unlock(&Rp);
    return;
}

void updatepacket(u_int64_t* buf, u_int32_t len, u_int64_t addr)
{
//    u_int64_t now = getCurrentTime();
    //printf("update package\n");
    for (int i = 0; i < len; ++i) updatekey(buf[i], addr, getCurrentTime());
}

u_int64_t getaddr(u_int64_t addr)
{
    printf("called\n");
    pthread_mutex_lock(&Rp);
    map<u_int64_t, TY_TAG>::iterator it = routelist.find(addr);
    printf("%llx\n", routelist.begin()->first);
    
    u_int64_t ans = (it == routelist.end()) ? -1 : it -> second.nexthop;
    pthread_mutex_unlock(&Rp);
    return ans;
    
//    if (it == routelist.end())
//        return -1;
//    return it->second.nexthop;
}

u_int64_t tablepacket(u_char *buf)
{

    pthread_mutex_lock(&Rp);
    u_int32_t len = routelist.size() * sizeof(long long)+8;
    memcpy(buf, &len, 4);

    map<u_int64_t, TY_TAG>::iterator it = routelist.begin();
    u_int64_t *ptr = (u_int64_t *) (buf);
    
    ptr = ptr + 1;

    while(it != routelist.end())
    {
        uint64_t ttl = (it -> second).ttl;
        *ptr = (ttl << 56) | (it -> second).nexthop;
        ++it; ++ptr;
    }
    u_int32_t cs = datachecksum((u_int32_t *) buf);
    memcpy(buf + 4, &cs, 4);
    pthread_mutex_unlock(&Rp);
    return len;
}

void showpackage(u_char* buf, u_int32_t len)
{
    printf("send a packet of len %d\n", len);
    int cnt = 1;
    for (int i=0;i<len;++i)
    {
        printf("0x%02x  ", buf[i]);
        if (cnt % 16==0)
            printf("\n");
        cnt++;
    }
    printf("\n");
}


pthread_mutex_t sp;


int sendp(u_char* buf, u_int32_t len)
{  
    // pthread_mutex_lock(&sp);
    //printf("called send packet\n");
    len += RadioTaplen;
    u_char* newbuf = (u_char*)malloc(len);
    /*minus!*/
    memcpy(newbuf+RadioTaplen, buf, len-RadioTaplen);
    free(buf);
    putradiotap(newbuf);
    //showpackage(newbuf, len);
    int ret = send(sendfd, newbuf, len, 0);
    // for (int i=0;i<5;++i)
    // {
    //     int ret = send(sendfd, newbuf, len, 0);
    //     if (ret == len)
    //         return 0;
    //     usleep(100);
    // }
    //printf("OK send\n");
    free(newbuf);
    // pthread_mutex_unlock(&sp);
    return 1;
}

int sendpraw(u_char* buf, u_int32_t len)
{
    printf("called\n");
    for (int i=0;i<5;++i)
    {
        int ret = send(sendfd, buf, len, 0);
        if (ret == len)
            return 0;
        usleep(100);
    }
    return 1;
}

void route_init()
{
    pthread_mutex_init(&sp, NULL);
    pthread_mutex_init(&Rp, NULL);
}




u_int32_t get_seq()
{
    return seq++;
}

u_int16_t checksum(u_char* buf)
{
    u_char ret1,ret2 = 0;
    for (int i = 2; i < DotTYlen/2; ++i)
        ret1 ^= buf[i*2], ret2^=buf[i*2+1];
    return ((u_int16_t)(ret2)<<8)|ret1;
}


void buildDotTY(u_char *buf, u_char type, u_char subtype, u_int64_t addr1, u_int64_t addr2, u_int64_t addr3)
{
    memset(buf,0,DotTYlen);
    u_int32_t now = get_seq();
    u_int64_t ID = TYID;
    memcpy(buf, &ID, 8);
    buf[8] = type;
    buf[9] = subtype;
    memcpy(buf+10, &now, 4);
    memcpy(buf+16,&addr1,8);
    addr2 &= 0xffffffffffffffLL;
    memcpy(buf+24,&addr2,8);
    addr3 &= 0xffffffffffffffLL;
    memcpy(buf+32,&addr3,8);
    u_int16_t check = checksum(buf);
    memcpy(buf+14, &check, 2);
}

u_char* buildrawpackage(u_char* input, u_int32_t length)
{
    u_int32_t reallength = ((length+3)&0xfffffffc)+8;
    if (reallength>MAXlength)
        return NULL;
    u_char* newbuf = (u_char*)malloc(reallength+DotTYlen);
    memset(newbuf,0,reallength+DotTYlen);
    memcpy(newbuf+DotTYlen,&reallength,4);
    memcpy(newbuf+DotTYlen+8, input, length);
    u_int32_t check = datachecksum((u_int32_t*)(newbuf+DotTYlen));
    memcpy(newbuf+DotTYlen+4,&check,4);
    return newbuf;
}

void* listening(void *arg)
{
    while(1)
    {
        int ret = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *) &sll, &len);
        int radlen = getradiotaplen(buf);
        //printf("radiotap length %d\n", radlen);
        if (radlen>ret-10)
            continue;
        unsigned code;
        memcpy(&code, buf+radlen+4,4);
        //printf("receive code %x\n", code);
        if (code==IDTY)
        {
            u_int16_t check = checksum(buf+radlen);
            //printf("%llx %llx\n", MYADDR, getsrcaddr(buf+radlen));
            //printf("%d\n", check);
            if (check==0 || MYADDR == getsrcaddr(buf+radlen))
                continue;
            //printf("receive a package\n");
            //printf("showing it\n");
            //showpackage(buf, ret);
            if (BUILD == gettype(buf+radlen))
            {
                u_char*t = (u_char*)malloc(ret - radlen);
                memcpy(t,buf + radlen,ret - radlen);
                pthread_mutex_lock(&Bp);
                Bpackages.push_back(make_pair(t, ret));
                pthread_mutex_unlock(&Bp);
            }
            if (MYADDR == getnhaddr(buf+radlen))
            {
                if (MYADDR != getdstaddr(buf+radlen))
                {
                    u_char*t = (u_char*)malloc(ret);
                    memcpy(t,buf,ret);
                    pthread_mutex_lock(&Tp);
                    Tpackages.push_back(make_pair(t, ret));
                    pthread_mutex_unlock(&Tp);
                }
                else
                {
                    u_char*t = (u_char*)malloc(ret - radlen);
                    memcpy(t,buf + radlen,ret - radlen);
                    pthread_mutex_lock(&Mp);
                    Mpackages.push_back(make_pair(t, ret - radlen));
                    pthread_mutex_unlock(&Mp);
                }
                
            }
        }
    }
}

void* retransmit(void *arg)
{
    while(1)
    {
        while (Tpackages.empty())
            pthread_yield();
        if (!Tpackages.empty())
        {
            
            while (!Tpackages.empty())
            {
                pthread_mutex_lock(&Tp);
                u_int32_t len = getradiotaplen(Tpackages[0].first);
                u_int8_t ttl = getttl(Tpackages[0].first+len);
                u_int64_t dst = getdstaddr(Tpackages[0].first+len);
                u_int64_t nh = getaddr(dst);
                if (ttl>0 && nh != -1)
                {
                    buildDotTY(Tpackages[0].first+len,gettype(Tpackages[0].first+len),getsubtype(Tpackages[0].first+len),((u_int64_t)(ttl-1)<<56)|getsrcaddr(Tpackages[0].first+len),dst,nh);
                    if (sendpraw(Tpackages[0].first,Tpackages[0].second))
                        perror("resend error\n");
                }
                free(Tpackages[0].first);
                Tpackages.pop_front();
                pthread_mutex_unlock(&Tp);
            }
        }
    }
}


int interface_init(char *iface, int len)
{
    Tpackages.clear();
    pthread_mutex_init(&Tp, NULL);
    sendfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == sendfd)
    {
        perror("open socket error!\n");
        return 1;
    }
    int ret;
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, iface, len);
    ret=ioctl(sendfd,SIOCGIFINDEX,&req);
    if (0 > ret)
    {
        perror("ioctl failed\n");
        return 1;
    }
    
    memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = req.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_80211_RAW);
    if (bind(sendfd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
	{
		perror("bind(ETH_P_ALL) failed");
		return (1);
	}

    listenfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == listenfd)
    {
        perror("open socket error!\n");
        return 1;
    }
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name,"mon0", 4);
    ret=ioctl(listenfd,SIOCGIFINDEX,&req);
    if (0 > ret)
    {
        perror("ioctl failed\n");
        return 1;
    }
    memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = req.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_80211_RAW);
    pthread_t tid;
    int status = pthread_create(&tid, NULL, listening, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return 1;
    }
    pthread_detach(tid);
    status = pthread_create(&tid, NULL, retransmit, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return 1;
    }
    pthread_detach(tid);
}


u_char* builddatapackage(u_char* buf, u_int32_t len, u_int64_t dst)
{
    u_char* newbuf = buildrawpackage(buf,len);
    u_int64_t nh = getaddr(dst);
    if (nh == -1)
    {
        perror("NO HOP\n");
        return NULL;
    }
    buildDotTY(newbuf,DATA,D_UDP,MYADDR|((u_int64_t)MAXTTL<<56),dst,nh);
    return newbuf;
}


void* Herethread(void *args)
{
    u_int64_t tick = getCurrentTime();
    while(true)
    {
        u_int64_t _tick = getCurrentTime();
        while (_tick - tick < HERE_DELAY) 
        {
            pthread_yield();
            _tick = getCurrentTime();
        }
        tick = _tick;
        
        u_char* here_frame = (u_char*)malloc(DotTYlen);
        buildDotTY(here_frame, BUILD, B_HERE, MYADDR, boardcast, boardcast);
        //printf("Here frame\n");
        //showpackage(here_frame, DotTYlen);
        sendp(here_frame, DotTYlen);
    }
}

void* Tablethread(void *args)
{
    u_int64_t tick = getCurrentTime();
    while(true)
    {
        u_int64_t _tick = getCurrentTime();
        while (_tick - tick < HERE_DELAY)
        {
            pthread_yield();
            _tick = getCurrentTime();
        }
        tick = _tick;
        
        u_char* here_frame = (u_char*)malloc(DotTYlen + MAXlength);
        memset(here_frame, 0, DotTYlen + MAXlength);
        int len = tablepacket(here_frame + DotTYlen);
        buildDotTY(here_frame, BUILD, B_UPDATE, MYADDR, boardcast, boardcast);
        sendp(here_frame, DotTYlen + len);
    }
}

void *Updatethread(void *args)
{
    while(true)
    {
        while(Bpackages.empty()) pthread_yield();
        pthread_mutex_lock(&Bp);
        pp head = Bpackages.front();
        if(gettype(head.first) == BUILD)
        {
            if(getsubtype(head.first) == B_HERE) updatekey(getsrcaddr(head.first), getsrcaddr(head.first), getCurrentTime());
            else if(getsubtype(head.first) == B_UPDATE)
            {
                //showpackage(head.first,head.second);
                //printf("length %d\n", (getdatalenth(head.first) - 8)>>3); 
                updatepacket((u_int64_t *)(getdata(head.first) + 8), (getdatalenth(head.first) - 8)>>3, getsrcaddr(head.first));
            }
        }
        free(head.first);
        Bpackages.pop_front();
        pthread_mutex_unlock(&Bp);
    }
}

void* clearthread(void *args)
{
    u_int64_t tick = getCurrentTime();
    while (true)
    {
        u_int64_t _tick = getCurrentTime();
        while (_tick - tick < HERE_DELAY)
        {
            pthread_yield();
            _tick = getCurrentTime();
        }
        tick = _tick;
        updatelist();
    }
}


void uphold_init()
{
    pthread_mutex_init(&Bp, NULL);
    pthread_t tid;
    int status = pthread_create(&tid, NULL, Updatethread, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return;
    }
    pthread_detach(tid);
    status = pthread_create(&tid, NULL, Tablethread, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return;
    }
    pthread_detach(tid);
    status = pthread_create(&tid, NULL, Herethread, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return;
    }
    pthread_detach(tid);
    status = pthread_create(&tid, NULL, clearthread, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return;
    }
    pthread_detach(tid);
}



void *showall(void* arg)
{
    while (1)
    {
        while(Mpackages.empty()) pthread_yield();
        while(!Mpackages.empty())
        {
            pthread_mutex_lock(&Mp);
            //printf("receive package\n");
            //u_int32_t radiolen = getradiotaplen(Mpackages[0].first);
            u_int32_t check = datachecksum((u_int32_t*)(Mpackages[0].first+DotTYlen));
            if (!check)
            {
                Mpackages[0].first[DotTYlen+getdatalenth(Mpackages[0].first)]=0;
                printf("receive message: %s\n", Mpackages[0].first+DotTYlen+8);
            }
            free(Mpackages[0].first);
            Mpackages.pop_front();
            pthread_mutex_unlock(&Mp);
        }
    }
}


int main( int argc, char *argv[])
{
    if (argc != 3)
    {
        perror("iface addr");
        return 1;
    }
    sscanf(argv[2],"%lx",&MYADDR);
    printf("set myaddr to %llx\n", MYADDR);
    interface_init(argv[1],strlen(argv[1]));

    pthread_mutex_init(&Mp, NULL);
    route_init();
    uphold_init();
    pthread_t tid;
    int status = pthread_create(&tid, NULL, showall, NULL);
    if (status != 0)
    {
        perror("thread init failed\n");
        return 1;
    }
    pthread_detach(tid);

    while (1)
    {
        scanf("%llx %s",&sendaddr,mybuf);
        printf("send %s to %llx\n", mybuf, sendaddr);
        u_char* s = builddatapackage(mybuf, strlen((char*)mybuf)+1, sendaddr);
        if (s==NULL)
        {
            perror("failed\n");
            continue;
        }
        u_int32_t len = RadioTaplen + DotTYlen + 8+((strlen((char*)mybuf)+4)&0xfffffffc);
        sendp(s,len);
    }
}