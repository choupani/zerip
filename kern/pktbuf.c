
#include "./pktbuf.h"
#include "./ipset.h"
#include "./dhcpr.h"

u_int8_t 
is_local_access(struct sx_addr *addr, sa_family_t af)
{
  u_int8_t d = 0;

  switch (af) {
  case AF_INET:
    d = in_localip(addr->v4);
    break;
  case AF_INET6:
    d = in6_localip(&addr->v6);
    break;
  }

  return (d);
}

u_int8_t
is_local_mbuf(struct mbuf *m, sa_family_t af)
{
  struct ip      *ip4 = NULL;
  struct ip6_hdr *ip6 = NULL;

  switch (af) {
  case AF_INET: {
    ip4 = mtod(m, struct ip *);
    if (m->m_pkthdr.len < (int)sizeof (struct ip)) {
      return (0);
    }
    struct sx_addr *saddr = (struct sx_addr *)&ip4->ip_src;
    struct sx_addr *daddr = (struct sx_addr *)&ip4->ip_dst;
    if( is_local_access(saddr, af) || is_local_access(daddr, af) )
      return (1);
  }
    break;
  case AF_INET6: {
    ip6 = mtod(m, struct ip6_hdr *);
    if (m->m_pkthdr.len < (int)sizeof (struct ip6_hdr)) {
      return (0);
    }
    struct sx_addr *saddr = (struct sx_addr *)&ip6->ip6_src;
    struct sx_addr *daddr = (struct sx_addr *)&ip6->ip6_dst;
    if( is_local_access(saddr, af) || is_local_access(daddr, af) )
      return (1);
  }
    break;
  }

  return (0);
}

static u_int8_t
build_pktbuf(struct pktbuf *pkt, int *off)
{
  u_int8_t action = FW_PASS;
  
  switch (pkt->af) {
  case AF_INET: {
    pkt->iph.ip4 = mtod(pkt->m, struct ip *);
    *off = pkt->iph.ip4->ip_hl << 2;
    pkt->iph_len = pkt->iph.ip4->ip_hl << 2;
    if (pkt->m->m_pkthdr.len < (int)sizeof (*pkt->iph.ip4)) {
      action = FW_DROP;
      printf("Short IPv4 packet");
      goto done;
    }    
    pkt->saddr = (struct sx_addr *)&pkt->iph.ip4->ip_src;
    pkt->daddr = (struct sx_addr *)&pkt->iph.ip4->ip_dst;
    pkt->ip_sum = &pkt->iph.ip4->ip_sum;
    pkt->tot_len = ntohs(pkt->iph.ip4->ip_len);
    pkt->proto = pkt->iph.ip4->ip_p;
    if ( (ntohs(pkt->iph.ip4->ip_off) & (IP_MF | IP_OFFMASK)) ) 
      pkt->frag = 1;
  }
    break;
  case AF_INET6: {
    pkt->iph.ip6 = mtod(pkt->m, struct ip6_hdr *);
    if (pkt->m->m_pkthdr.len < (int)sizeof (*pkt->iph.ip6)) {
      action = FW_DROP;
      printf("Short IPv6 packet");
      goto done;
    }

    if (htons(pkt->iph.ip6->ip6_plen) == 0) {
      action = FW_DROP;
      printf("IPv6 packet length is zeroip (jumbo-datagram)");
      goto done;
    }

    pkt->saddr = (struct sx_addr *)&pkt->iph.ip6->ip6_src;
    pkt->daddr = (struct sx_addr *)&pkt->iph.ip6->ip6_dst; 
    pkt->ip_sum = NULL;
    pkt->tot_len = ntohs(pkt->iph.ip6->ip6_plen) + sizeof (struct ip6_hdr);
    *off = ((caddr_t)pkt->iph.ip6 - pkt->m->m_data) + sizeof (struct ip6_hdr);
    pkt->iph_len = sizeof(struct ip6_hdr);
    pkt->proto = pkt->iph.ip6->ip6_nxt;
    break;
  }
  }
  
  pkt->local_src = is_local_access(pkt->saddr, pkt->af);
  pkt->local_src = is_local_access(pkt->daddr, pkt->af);
   
 done:  
  return (action);
}

static u_int8_t 
check_pkt(struct pktbuf *pkt, int off)
{
  u_int8_t action = FW_PASS;
  struct rm_priotracker rmpt;

  Z_RLOCK(&z_lock, &rmpt);
  
  if( match_ipset(pkt->saddr, pkt->af) ||
      match_ipset(pkt->daddr, pkt->af) )
    action = FW_DROP;
  
  Z_RUNLOCK(&z_lock, &rmpt);

  return (action);
}

u_int8_t
process_pkt(struct pktbuf *pkt)
{
  int off = 0;
  u_int8_t action = 0;
  void *udp = NULL;
  
  action = build_pktbuf(pkt, &off);

  pkt->m->m_flags |= M_SKIP_ZEROIP;

  if( action == FW_DROP ) {
    goto done;
  }

  action = check_pkt(pkt, off);

  if( pkt->proto==IPPROTO_UDP &&
      pkt->af == AF_INET &&
      !pkt->frag &&
      action != FW_DROP ) {
    PULLUP_TO(off, udp, sizeof(struct udphdr));
    if( pkt->m ) {
      pkt->hdr.udp = (struct udphdr*)udp;
      pkt->h_len = sizeof (*pkt->hdr.udp);
      pkt->sport = (union sx_port *)&pkt->hdr.udp->uh_sport;
      pkt->dport = (union sx_port *)&pkt->hdr.udp->uh_dport;
      pkt->p_len = pkt->tot_len - off - pkt->h_len;

      action = chk_dhcp(pkt, off + sizeof(*pkt->hdr.udp));
      
    } else
      action = FW_DROP;
  }

 done:
  return (action);
}
