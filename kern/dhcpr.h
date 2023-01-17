
#ifndef _DHCP_RELAY_H
#define _DHCP_RELAY_H

#include "./precom.h"

#ifdef _KERNEL_
#include "./pktbuf.h"
#include "./dhcp.h"
#include "../com/ioctl_def.h"
#endif //_KERNEL_

#pragma pack(push, 1)

struct dhcp_relay {
  u_int8_t  enabled;

  char ifname[IFNAMSIZ+1];                                                                                                                                                                                                                  
  
  u_int8_t macaddr[ETHER_ADDR_LEN];

  struct ifnet*   ifp;           //input interface  
  struct sx_xaddr local_addr;    //dhcp relay local address
  struct sx_xaddr dhcp_server;   //dhcp server ip address
};

#pragma pack(pop)

#ifdef _KERNEL_


extern void dhcpr_init(void);
extern void dhcpr_set(caddr_t*);
extern void dhcpr_clr(void);
extern u_int8_t chk_dhcp(struct pktbuf*, int);

#endif //_KERNEL_

#endif /* _DHCP_RELAY_H */
