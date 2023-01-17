
#include "./addr.h"

void
sx_sprint_addr(struct sx_addr *addr, sa_family_t af, char *buf, int lbuf, u_int8_t braket)
{
  buf[0] = 0;
  int l = 0;

  switch (af) {
  case AF_LINK: {
    l = snprintf(buf, lbuf, "%6D", addr->ve.data, ":");
    break;
  }
  case AF_INET: {
    u_int32_t a = ntohl(addr->addr32[0]);
    l = sprintf(buf, "%u.%u.%u.%u", (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255);
    break;
  }
  case AF_INET6: {
    if( braket ) {
      char ip6buf[INET6_ADDRSTRLEN];
      l = snprintf(buf, lbuf, "[%s]",
	       ip6_sprintf(ip6buf, &addr->v6));
    }
    else
      ip6_sprintf(buf, &addr->v6);
    break;
  }
  }

  if( l<0 || l>=lbuf ) 
    buf[0] = 0;
}

void
sx_print_addr(struct sx_addr *addr, sa_family_t af)
{
  switch (af) {
  case AF_LINK: {
    int i = 0;
    for(i = 0; i < ETHER_ADDR_LEN - 1; ++i)
      printf("%02x:", addr->ve.data[i]);
    printf("%02x", addr->ve.data[i]);
    break;
  }
  case AF_INET: {
    u_int32_t a = ntohl(addr->addr32[0]);
    printf("%u.%u.%u.%u", (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255);
    break;
  }
  case AF_INET6: {
    char buf[INET6_ADDRSTRLEN];
    ip6_sprintf(buf, &addr->v6);
    printf("%s", buf);
    break;
  }
  }
}

void
sxx_print_addr(struct sx_xaddr *addr)
{
  sx_print_addr(&addr->addr, addr->af);
}

int
match_range(struct sx_addr *b, struct sx_addr *e, struct sx_addr *a, sa_family_t af)
{
  int match = 0;
  
  switch (af) {
  case AF_INET: {
    u_int32_t aN, bN, eN;
    aN = htonl(a->addr32[0]);
    bN = htonl(b->addr32[0]);
    eN = htonl(e->addr32[0]);
    if ((aN < bN) || (aN > eN))
      goto done;
    match = 1;
    break;
  }
  case AF_INET6: {
    int i;
    
    for (i = 0; i < 4; ++i) {

      if (ntohl(a->addr32[i]) > ntohl(b->addr32[i]))
	break;
      else if (ntohl(a->addr32[i]) < ntohl(b->addr32[i]))
	goto done;
    }
    
    for (i = 0; i < 4; ++i) {

      if (ntohl(a->addr32[i]) < ntohl(e->addr32[i]))
	break;
      else if (ntohl(a->addr32[i]) > ntohl(e->addr32[i]))
	goto done;
    }
    
    match = 1;
    break;
  }
  case AF_LINK:
    /* no implemented yet */
    break;
  }

 done:

  return (match);
}

int
sx_addr_cmp(struct sx_addr *a, struct sx_addr *b, sa_family_t af)
{
  switch (af) {
  case AF_INET:
    if(a->addr32[0] < b->addr32[0]) return (-1);
    if(a->addr32[0] > b->addr32[0]) return (1);
    break;
  case AF_INET6:
    if(a->addr32[3] < b->addr32[3]) return (-1); 
    if(a->addr32[3] > b->addr32[3]) return (1); 
    if(a->addr32[2] < b->addr32[2]) return (-1); 
    if(a->addr32[2] > b->addr32[2]) return (1); 
    if(a->addr32[1] < b->addr32[1]) return (-1); 
    if(a->addr32[1] > b->addr32[1]) return (1); 
    if(a->addr32[0] < b->addr32[0]) return (-1); 
    if(a->addr32[0] > b->addr32[0]) return (1); 
    break;
  case AF_LINK:
    return memcmp(a->ve.data, b->ve.data, ETHER_ADDR_LEN);
    break;
  }
  return (0);
}

int
sx_addr_cmp_v2(struct sx_addr *a, struct sx_addr *b, sa_family_t af)
{
  switch (af) {
  case AF_INET:
    if(ntohl(a->addr32[0]) < ntohl(b->addr32[0])) return (-1);
    if(ntohl(a->addr32[0]) > ntohl(b->addr32[0])) return (1);
    break;
  case AF_INET6:
    if(ntohl(a->addr32[0]) < ntohl(b->addr32[0])) return (-1); 
    if(ntohl(a->addr32[0]) > ntohl(b->addr32[0])) return (1); 
    if(ntohl(a->addr32[1]) < ntohl(b->addr32[1])) return (-1); 
    if(ntohl(a->addr32[1]) > ntohl(b->addr32[1])) return (1); 
    if(ntohl(a->addr32[2]) < ntohl(b->addr32[2])) return (-1); 
    if(ntohl(a->addr32[2]) > ntohl(b->addr32[2])) return (1); 
    if(ntohl(a->addr32[3]) < ntohl(b->addr32[3])) return (-1); 
    if(ntohl(a->addr32[3]) > ntohl(b->addr32[3])) return (1); 
    break;
  case AF_LINK:
    return memcmp(a->ve.data, b->ve.data, ETHER_ADDR_LEN);
    break;
  }
  return (0);
}

void
sx_addrcpy(struct sx_addr *dst, struct sx_addr *src, sa_family_t af)
{
  switch (af) {
  case AF_INET:
    dst->addr32[0] = src->addr32[0];
    break;
  case AF_INET6:
    dst->addr32[0] = src->addr32[0];
    dst->addr32[1] = src->addr32[1];
    dst->addr32[2] = src->addr32[2];
    dst->addr32[3] = src->addr32[3];
    break;
  case AF_LINK:
    dst->addr16[0] = src->addr16[0];
    dst->addr16[1] = src->addr16[1];
    dst->addr16[2] = src->addr16[2];
    break;
  }
}
