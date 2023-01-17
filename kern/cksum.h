#ifndef _PKT_CKSUM_H
#define _PKT_CKSUM_H

#include "./precom.h"
#include "./pktbuf.h"

void fix_in4_cksum(struct mbuf*, struct ip*);
void fix_cksum(struct pktbuf*, int);

#endif
