
#ifndef _ONI_PXYARP_H
#define _ONI_PXYARP_H

#include "./precom.h"
#include "./addr.h"

#ifdef _KERNEL_
#include "../com/ioctl_def.h"
#endif //_KERNEL_

#pragma pack(push, 1)

struct proxy_arp {
  u_int8_t  enabled;
  char ifname[IFNAMSIZ+1];                                                                                                                                                                                                                  
  u_int8_t  macaddr[ETHER_ADDR_LEN];
  
  struct ifnet*   ifp;           //input interface  
  struct sx_xaddr from;    
  struct sx_xaddr to;   
};

#pragma pack(pop)

#ifdef _KERNEL_

extern void pxarp_init(void);
extern void pxarp_set(caddr_t*);
extern void pxarp_clr(void);

u_int8_t 
chk_arp(struct mbuf*, struct ether_header*, struct ifnet*, int);

#endif //_KERNEL_


#endif
