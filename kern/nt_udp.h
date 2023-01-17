
#ifndef _NT_NTUDP_H
#define _NT_NTUDP_H

#include "./precom.h"
#include "./pktbuf.h"

void send_udp(sa_family_t,
	      struct sx_addr*, struct sx_addr*,
	      u_int16_t, u_int16_t,
	      struct ifnet*, u_int8_t*, int);


#endif
