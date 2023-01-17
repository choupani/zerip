
#ifndef _KRN_IPSET_H
#define _KRN_IPSET_H

#ifdef _KERNEL_
#include "./precom.h"
#include "../com/ioctl_def.h"
#endif //_KERNEL_

#include "./addr.h"


#pragma pack(push, 1)

struct ipset {
  RB_ENTRY(ipset) entry;
  
  struct sx_xaddr addr;
};

#pragma pack(pop)

#ifdef _KERNEL_


RB_HEAD(ipset_tree, ipset);
RB_PROTOTYPE(ipset_tree, ipset, entry, ipset_compare);
extern struct ipset_tree tree_ipset_tracking;

void ipset_insert(struct ioctlbuffer*, caddr_t*);
void ipset_clear(void);
void ipset_init(void);

extern int match_ipset(struct sx_addr*, sa_family_t);

#endif // _KERNEL_

#endif
