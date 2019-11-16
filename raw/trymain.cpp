#include "ty2.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include <deque>
#include <pthread.h>

using namespace std;



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
    
    ty2_init(argv[1],strlen(argv[1]));

    pthread_mutex_init(&Mp, NULL);
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