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

using namespace std;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025

u_char a[] = { 0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x91, 0xcd, 0x67, 0x0b, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x24, 0xad, 0x16, 0x40, 0x01, 0xab, 0xa6, 0x01, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x80, 0x8d, 0xb7, 0x7f, 0xcc, 0x92, 0x80, 0x8d, 0xb7, 0x7f, 0xcc, 0x92, 0x40,
    0x5d, 0xb6, 0xa1, 0x1f, 0x33, 0x24, 0x02, 0x00, 0x00, 0x64, 0x00, 0x01, 0x04, 0x00, 0x08, 0x43,
    0x4d, 0x43, 0x43, 0x40, 0x50, 0x4b, 0x55, 0x01, 0x05, 0xa4, 0xb0, 0x48, 0x60, 0x6c, 0x03, 0x01,
    0x9d, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x2d, 0x1a, 0xad, 0x09, 0x1b, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
u_char buf[7000];
char iface[30]="wlp4s0mon";
int main()
{
    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == sd)
    {
        perror("open socket error!\n");
        return 1;
    }
    int ret;
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name,"mon0", 4);
    ret=ioctl(sd,SIOCGIFINDEX,&req);
    if (0 > ret)
    {
        perror("ioctl failed\n");
        return 1;
    }
    // struct sockaddr_ll sll;
    // memset(&sll, 0, sizeof(sll));
	// sll.sll_family = AF_PACKET;
	// sll.sll_ifindex = req.ifr_ifindex;
    // sll.sll_protocol = htons(ETH_P_80211_RAW);
    // if (bind(sd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
	// {
	// 	perror("bind(ETH_P_ALL) failed");
	// 	return (1);
	// }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = req.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_80211_RAW);
    // if (bind(sd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
	// {
	// 	perror("bind(ETH_P_ALL) failed");
	// 	return (1);
	// }
    socklen_t len = sizeof(sll);
    while(1)
    {
        ret = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *) &sll, &len);
        printf("receive %d bytes\n", ret);
        // int cnt = 1;
        // for (int j = 0;j<ret;++j)
        // {
        //     if (cnt%16==0)
        //         printf("\n");
        //     ++cnt;
        //     printf("0x%x ", buf[j]);
        // }
        // printf("\n");
        int radlen = (int)buf[2]+((int)buf[3]<<8);
        
        if (radlen>ret-10)
            continue;
        printf("first x chars %02x%02x%02x%02x%02x%02x%02x%02x\n", buf[radlen],buf[radlen+1],buf[radlen+2],buf[radlen+3],
        buf[radlen+4],buf[radlen+5],buf[radlen+6],buf[radlen+7]);
        // unsigned code = ((unsigned)buf[radlen+4]<<24)+((unsigned)buf[radlen+5]<<16)+
        // ((unsigned)buf[radlen+6]<<8)+((unsigned)buf[radlen+7]);
        unsigned code = ((unsigned)buf[radlen+4]<<24)+((unsigned)buf[radlen+5]<<16)+
        ((unsigned)buf[radlen+6]<<8)+((unsigned)buf[radlen+7]);
        printf("radiotap length %d get code %x\n", radlen, code);
        if (code==0x54592a32)
        {
            printf("found one");
            break;
        }
    }
}