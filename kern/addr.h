#ifndef _KRN_ADDR_H
#define _KRN_ADDR_H

#ifdef _KERNEL_
#include "./precom.h"
#include "./define.h"
#endif //_KERNEL_

#pragma pack(push, 1)

struct eth_addr {
  u_char data[ETHER_ADDR_LEN];
};

struct sx_addr {
  union {
    struct in_addr      v4;
    struct in6_addr     v6;
    struct eth_addr     eh;
    u_int8_t    addr8[16];
    u_int16_t   addr16[8];
    u_int32_t   addr32[4];
    u_int64_t   addr64[2];
  } sxa;
#define v4      sxa.v4
#define v6      sxa.v6
#define ve      sxa.eh
#define addr8   sxa.addr8
#define addr16  sxa.addr16
#define addr32  sxa.addr32
#define addr64  sxa.addr64
};

/*
  AF_INET  --> 2
  AF_INET6 --> 28
  AF_LINK  --> 18
*/

struct sx_xaddr {
  struct sx_addr addr;
  sa_family_t    af;
};

#pragma pack(pop)


#ifdef _KERNEL_

extern void sx_sprint_addr(struct sx_addr*, sa_family_t, char*, int, u_int8_t);
extern void sx_print_addr(struct sx_addr*, sa_family_t);
extern void sxx_print_addr(struct sx_xaddr*);
extern int sx_addr_cmp(struct sx_addr*, struct sx_addr*, sa_family_t);
extern int sx_addr_cmp_v2(struct sx_addr*, struct sx_addr*, sa_family_t);
extern void sx_addrcpy(struct sx_addr*, struct sx_addr*, sa_family_t);
extern int match_range(struct sx_addr*, struct sx_addr*, struct sx_addr*, sa_family_t);

#endif //_KERNEL_

#endif
