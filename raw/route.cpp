#include <map>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <sys/time.h>
#include <pthread.h>

#include "buildpacket.cpp"

using namespace std;

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

u_int64_t getCurrentTime()
{
    struct timeval tv;
    gettimeofday(&tv,NULL); 
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
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
    u_int64_t addr1 = key & 0xffffffffffffffLL;
    u_int8_t ttl = ((key >> 56) & 0xff)+1;
    if (ttl>MAXTTL) return;
    
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
    for (int i = 0; i < len; ++i) updatekey(buf[i], addr, getCurrentTime());
}

u_int64_t getaddr(u_int64_t addr)
{
    pthread_mutex_lock(&Rp);
    map<u_int64_t, TY_TAG>::iterator it = routelist.find(addr);
    
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
    u_int64_t len = routelist.size() * sizeof(long long) + 8;
    
    map<u_int64_t, TY_TAG>::iterator it = routelist.begin();
    u_int64_t *ptr = (u_int64_t *) (buf);
    *ptr = len;
    ptr = ptr + 8;
    datagetchecksum()

    while(it != routelist.end())
    {
        uint64_t ttl = (it -> second).ttl;
        *ptr = (ttl << 56) | (it -> second).nexthop;
        ++it; ++ptr;
    }
    pthread_mutex_unlock(&Rp);
    return len;
}

void route_init()
{
    pthread_mutex_init(&Rp, NULL);
}
