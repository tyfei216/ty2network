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

extern u_char radiotap_template[];

extern u_int32_t seq;

#define RadioTaplen 12

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
extern pthread_mutex_t Rp;
extern map<u_int64_t, TY_TAG> routelist;

#define INTERVAL 3000
#define MAXTTL 32

extern int sendfd;
extern int listenfd;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025


typedef pair<u_char*, u_int32_t> pp;
#define HERE_DELAY 500

extern u_int64_t MYADDR;

extern pthread_mutex_t Bp;
extern deque<pp> Bpackages;

#define ETH_P_ALL 0x0003
#define ETH_P_80211_RAW 0x0025

typedef pair<u_char*, u_int32_t> pp;

extern struct sockaddr_ll sll;
extern socklen_t len;

extern pthread_mutex_t Tp;
extern deque<pp> Tpackages;

extern pthread_mutex_t Mp;
extern deque<pp> Mpackages;

extern u_char mybuf[10000];
extern u_int64_t sendaddr;

extern u_char buf[6000];

extern pthread_mutex_t sp;

u_int8_t gettype(u_char* buf);

u_int8_t getsubtype(u_char* buf);

u_int32_t getseq(u_char* buf);

u_int64_t getsrcaddr(u_char* buf);

u_int64_t getdstaddr(u_char* buf);

u_int64_t getnhaddr(u_char* buf);

u_int8_t getttl(u_char* buf);

u_int32_t getradiotaplen(u_char* buf);

u_char* getdata(u_char *buf);

u_int32_t getdatalenth(u_char* buf);


u_int32_t datachecksum(u_int32_t * buf);

u_int64_t getCurrentTime();

void putradiotap(u_char *buf);

void updatelist();


void updatekey(u_int64_t key, u_int64_t addr, u_int64_t now);

void updatepacket(u_int64_t* buf, u_int32_t len, u_int64_t addr);

u_int64_t getaddr(u_int64_t addr);

u_int64_t tablepacket(u_char *buf);

void showpackage(u_char* buf, u_int32_t len);

int sendp(u_char* buf, u_int32_t len);

int sendpraw(u_char* buf, u_int32_t len);

void route_init();

u_int32_t get_seq();

u_int16_t checksum(u_char* buf);

void buildDotTY(u_char *buf, u_char type, u_char subtype, u_int64_t addr1, u_int64_t addr2, u_int64_t addr3);

u_char* buildrawpackage(u_char* input, u_int32_t length);

void* listening(void *arg);

void* retransmit(void *arg);

int interface_init(char *iface, int len);

u_char* builddatapackage(u_char* buf, u_int32_t len, u_int64_t dst);

void* Herethread(void *args);

void* Tablethread(void *args);

void *Updatethread(void *args);

void* clearthread(void *args);

void uphold_init();

void ty2_init(char *iface, int len);
