#ifndef _KRN_PKTBUF_H
#define _KRN_PKTBUF_H

#include "./precom.h"
#include "./addr.h"

struct pktbuf {

  struct ether_header *eth;
  
  union {
    struct ip         *ip4;
    struct ip6_hdr    *ip6;
  } iph;

  union {
    struct tcphdr     *tcp;
    struct udphdr     *udp;
    struct icmp       *icmp4;
    struct icmp6_hdr  *icmp6;
    struct ppp_grehdr *grev1;
    struct esphdr     *esp;
    struct sctphdr    *sctp;
    caddr_t            any;
  } hdr;

  union  sx_port *sport;  /* current sport of packet  */
  union  sx_port *dport;  /* current dport of packet  */
  struct sx_addr *saddr;  /* current src address of packet */ 
  struct sx_addr *daddr;  /* current dst address of packet */

  u_int8_t frag;
  
  struct ifnet   *oifp;
  struct ifnet   *iifp;
  struct mbuf    *m;
  u_int16_t      *ip_sum;
  
  int             tot_len; /* Make Mickey money tot_len = ntohs(iph->ip_len) */
  int             p_len;   /* length of payload l7 data*/
  u_int8_t        iph_len; /* length of ipv4/ipv6 header */
  u_int8_t        h_len;   /* header length (i.e header len of tcp/udp/icmp/... protocol)*/

  u_int8_t        fib;

  u_int8_t        local_src;
  u_int8_t        local_dst;
 
  sa_family_t     af;
  u_int8_t        proto;
  int             dir;
};

u_int8_t process_pkt(struct pktbuf*);
u_int8_t is_local_access(struct sx_addr*, sa_family_t);
u_int8_t is_local_mbuf(struct mbuf*, sa_family_t);


#endif
