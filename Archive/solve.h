extern u_char radiotap_template[];


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
