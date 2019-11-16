#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <string.h>
#include <cstdlib>
#include <deque>
#include <pthread.h>


#include "buildpacket.cpp"
#include "packagesolve.cpp"

using namespace std;

int sendfd, listenfd;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025

typedef pair<u_char*, u_int32_t> pp;

struct sockaddr_ll sll;
socklen_t len = sizeof(sll);

pthread_mutex_t Tp;
deque<pp> Tpackages;

extern pthread_mutex_t Bp;
extern deque<pp> Bpackages;

extern pthread_mutex_t Mp;
extern deque<pp> Mpackages;

static u_char buf[6000];

void* listening(void *arg)
{
    while(1)
    {
        int ret = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *) &sll, &len);
        int radlen = getradiotaplen(buf);
        printf("radiotap length %d\n", radlen);
        if (radlen>ret-10)
            continue;
        // unsigned code = ((unsigned)buf[radlen+4]<<24)+((unsigned)buf[radlen+5]<<16)+
        // ((unsigned)buf[radlen+6]<<8)+((unsigned)buf[radlen+7]);
        u_int64_t code;
        memcpy(&code, buf+radlen, 8);
        if (code==0x54592a3200000000LL)
        {
            u_int32_t check = checksum((u_int16_t*)(buf+radlen));
            if (check)
                continue;
            if (BUILD == gettype(buf+radlen))
            {
                u_char*t = (u_char*)malloc(ret - radlen);
                memcpy(t,buf + radlen,ret);
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
                    u_char*t = (u_char*)malloc(ret);
                    memcpy(t,buf,ret);
                    pthread_mutex_lock(&Mp);
                    Mpackages.push_back(make_pair(t, ret));
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
                pthread_mutex_lock(&Tp);
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

int sendp(u_char* buf, u_int32_t len)
{  
    len += 4+RadioTaplen;
    u_char* newbuf = (u_char*)malloc(len);
    memcpy(newbuf+RadioTaplen, buf, len);
    putradiotap(newbuf);
    for (int i=0;i<5;++i)
    {
        int ret = send(sendfd, buf, len, 0);
        if (ret == len)
            return 0;
        usleep(100);
    }
    return 1;
}

int sendpraw(u_char* buf, u_int32_t len)
{
    for (int i=0;i<5;++i)
    {
        int ret = send(sendfd, buf, len, 0);
        if (ret == len)
            return 0;
        usleep(100);
    }
    return 1;
}

u_char* builddatapackage(u_char* buf, u_int32_t len, u_int64_t dst)
{
    u_char* newbuf = buildrawpackage(buf,len);
    putradiotap(newbuf);
    u_int64_t nh = getaddr(dst);
    if (nh == -1)
    {
        perror("NO HOP\n");
        return NULL;
    }
    buildDotTY(newbuf,DATA,D_UDP,MYADDR|((u_int64_t)MAXTTL<<56),dst,nh);
    return newbuf;
}
