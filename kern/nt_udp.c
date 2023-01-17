
#include "./nt_udp.h"
#include "./cksum.h"

static int 
oni_route_addr(u_int8_t fib, struct sx_addr *daddr, struct sx_addr *raddr, sa_family_t af, struct ifnet **oifp, struct sx_addr *rt_gateway)
{
  struct sockaddr_in *dst = NULL;
  struct route ro;
  struct sockaddr_in6 *dst6;
  struct route_in6 ro6;
  struct rtentry *rt = NULL;
  int hlen = 0;
  int d = 0;
  
  switch (af) {
  case AF_INET:
    hlen = sizeof (struct ip);
    bzero(&ro, sizeof (ro));
    dst = (struct sockaddr_in *)&ro.ro_dst;
    dst->sin_family = AF_INET;
    dst->sin_len = sizeof (*dst);
    dst->sin_addr = daddr->v4;
    in_rtalloc_ign(&ro, 0, fib);
    rt = ro.ro_rt;
    break;
  case AF_INET6:
    hlen = sizeof (struct ip6_hdr);
    bzero(&ro6, sizeof (ro6));
    dst6 = (struct sockaddr_in6 *)&ro6.ro_dst;
    dst6->sin6_family = AF_INET6;
    dst6->sin6_len = sizeof (*dst6);
    dst6->sin6_addr = daddr->v6;
    in6_rtalloc_ign(&ro6, 0, fib);
    rt = ro6.ro_rt;
    break;
  default:
    goto done;
  }

  if (rt) {    

    if( oifp )
      *oifp = rt->rt_ifp;

    if( rt->rt_ifa && raddr ) {
      switch (af) {
      case AF_INET: {
	struct sockaddr_in *in;

	in = (struct sockaddr_in *)rt->rt_ifa->ifa_addr;

	if( in ) {
	  raddr->v4 = in->sin_addr;

	  if( rt_gateway && rt->rt_gateway && (rt->rt_flags&RTF_GATEWAY) ) {
	    in = (struct sockaddr_in *)rt->rt_gateway;
	    rt_gateway->v4 = in->sin_addr;
	  }
	}
      }
	break;
      case AF_INET6: {
	struct sockaddr_in6 *in6 = NULL;

	in6 = (struct sockaddr_in6 *)rt->rt_ifa->ifa_addr;
	
	if( in6 ) {
	  raddr->v6 = in6->sin6_addr;

	  if( rt_gateway && rt->rt_gateway ) {
	    in6 = (struct sockaddr_in6 *)rt->rt_gateway;
	    rt_gateway->v6 = in6->sin6_addr;
	  }
	}
      }
	break;
      }
    }
    d = 1;
  }
  
 done:
  if( rt )
    RTFREE(rt);
  
  return (d);
}

void
send_udp(sa_family_t af,
	 struct sx_addr *saddr, struct sx_addr *daddr,
	 u_int16_t sport, u_int16_t dport,
	 struct ifnet *ifp, u_int8_t *data, int dlen)
{
  struct sx_addr addr_any;

  struct mbuf *m;
  int len, ulen;
  struct ip *h = NULL;
  struct ip6_hdr *h6 = NULL;
  struct udphdr *uh = NULL;
  struct ifnet *oifp = NULL;
  u_int8_t fwd_ours = 0;

  if( !saddr ) {
    bzero(&addr_any, sizeof(struct sx_addr));
    saddr = &addr_any;
  }

  /* maximum segment size udp option */
  ulen = sizeof (struct udphdr);

  switch (af) {
  case AF_INET:
    len = sizeof (struct ip) + ulen + dlen;
    if ((ntohl(saddr->v4.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET &&
        (ntohl(daddr->v4.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
      fwd_ours = 1;
    break;
  case AF_INET6:
    len = sizeof (struct ip6_hdr) + ulen + dlen;
    if( IN6_IS_ADDR_LOOPBACK(&saddr->v6) &&
	IN6_IS_ADDR_LOOPBACK(&daddr->v6) )
      fwd_ours = 1;
    break;
  default:
    return;
  }

  /* create outgoing mbuf */
  MGETHDR(m, M_NOWAIT, MT_HEADER);
  if (m == NULL) {
    return;
  }

  m->m_flags |= M_SKIP_ZEROIP;
  if( fwd_ours )
    m->m_flags |= M_FASTFWD_OURS;
  
  m->m_data += max_linkhdr;
  m->m_pkthdr.len   = m->m_len = (len - dlen);
  m->m_pkthdr.rcvif = NULL;

  bzero(m->m_data, (len - dlen));

  switch (af) {
  case AF_INET:

    if( dlen ) {
      m_copyback(m, (sizeof (*h) + ulen), dlen, data);
    }

    if (saddr->v4.s_addr == INADDR_ANY)
      oni_route_addr(M_GETFIB(m), daddr, saddr, af, &oifp, NULL);

    h = mtod(m, struct ip *);

    h->ip_p = IPPROTO_UDP;
    h->ip_len = htons(len);
    h->ip_src.s_addr = saddr->v4.s_addr;
    h->ip_dst.s_addr = daddr->v4.s_addr;

    uh = (struct udphdr *)((caddr_t)h + sizeof (struct ip));
    break;
  case AF_INET6:
    
    if( dlen ) {
      m_copyback(m, (sizeof (struct ip6_hdr) + ulen), dlen, data);
    }

    if (IN6_IS_ADDR_UNSPECIFIED(&saddr->v6))
      oni_route_addr(M_GETFIB(m), daddr, saddr, af, &oifp, NULL);

    h6 = mtod(m, struct ip6_hdr *);

    h6->ip6_nxt = IPPROTO_UDP;
    h6->ip6_plen = htons(len);
    memcpy(&h6->ip6_src, &saddr->v6, sizeof (struct in6_addr));
    memcpy(&h6->ip6_dst, &daddr->v6, sizeof (struct in6_addr));

    uh = (struct udphdr *)((caddr_t)h6 + sizeof (struct ip6_hdr));
    break;
  }

  /* UDP header */
  uh->uh_sport = ntohs(sport);
  uh->uh_dport = ntohs(dport);
  uh->uh_ulen  = ntohs(dlen + ulen);

  switch (af) {
  case AF_INET: {
    h->ip_v = 4;
    h->ip_hl = sizeof (*h) >> 2;
    h->ip_tos = IPTOS_LOWDELAY;
    h->ip_len = ntohs(len);
    h->ip_off = 0;
    h->ip_ttl = ip_defttl;
    h->ip_sum = 0;

    uh->uh_sum = in_pseudo(h->ip_src.s_addr,
			   h->ip_dst.s_addr,
			   htons(h->ip_p + ntohs(h->ip_len) - (h->ip_hl << 2))
			   );
    
    uh->uh_sum = in_cksum_skip(m, ntohs(h->ip_len), (h->ip_hl << 2));
    
    if( uh->uh_sum == 0 )
      uh->uh_sum = 0xffff;
    ip_output(m, NULL, NULL, 0, NULL, NULL);
    break;
  }
  case AF_INET6: {
    /* UDP checksum */
    uh->uh_sum = in6_cksum(m, IPPROTO_UDP,
			   sizeof (struct ip6_hdr), (dlen + ulen));
    
    h6->ip6_vfc |= IPV6_VERSION;
    h6->ip6_hlim = IPV6_DEFHLIM;
    ip6_output(m, NULL, NULL, 0, NULL, NULL, 0);
    break;
  }
  }
}
