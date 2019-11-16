#include "route.cpp"
#include "interface.cpp"
#include "buildpacket.cpp"
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <pthread.h>
#include "deque"
#include "packagesolve.cpp"

typedef pair<u_char*, u_int32_t> pp;
#define HERE_DELAY 2000
#define pthread_yield getCurrentTime

u_int64_t MYADDR;

pthread_mutex_t Bp;
deque<pp> Bpackages;

void* Herethread()
{
    u_int64_t tick = getCurrentTime();
    while(true)
    {
        u_int64_t _tick = getCurrentTime();
        if(_tick - tick < HERE_DELAY) pthread_yield();
        else tick = _tick;
        
        u_char* here_frame = (u_char*)malloc(DotTYlen);
        buildDotTY(here_frame, BUILD, B_HERE, MYADDR, boardcast, boardcast);
        sendp(here_frame, DotTYlen);
    }
}

void* Tablethread()
{
    u_int64_t tick = getCurrentTime();
    while(true)
    {
        u_int64_t _tick = getCurrentTime();
        if(_tick - tick < HERE_DELAY) pthread_yield();
        else tick = _tick;
        
        u_char* here_frame = (u_char*)malloc(DotTYlen + MAXlength);
        int len = tablepacket(here_frame + DotTYlen);
        buildDotTY(here_frame, BUILD, B_UPDATE, MYADDR, boardcast, boardcast);
        
        sendp(here_frame, DotTYlen + len);
    }
}

void *Updatethread()
{
    while(true)
    {
        while(Bpackages.empty()) pthread_yield();
        pthread_mutex_lock(&Bp);
        pp head = Bpackages.front();
        if(gettype(head.first) == BUILD)
        {
            if(getsubtype(head.first) == B_HERE) updatekey(gettype(head.first), getsrcaddr(head.first), getCurrentTime());
            else if(getsubtype(head.first) == B_UPDATE) updatepacket(getdata(head.first), getdatalenth(buf) - 8, getsrcaddr(buf));
        }
        pthread_mutex_unlock(&Bp);
    }
}

void uphold_init()
{
    pthread_mutex_init(&Bp, NULL);
}
