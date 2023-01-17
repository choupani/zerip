
#include "./pxarp.h"
#include "./addr.h"

struct proxy_arp pxarp;

void 
pxarp_init(void)
{
  bzero(&pxarp, sizeof(struct proxy_arp));
}

void
pxarp_clr(void)
{
  pxarp_init();
}

void 
pxarp_set(caddr_t *kb)
{
  struct proxy_arp *sx = (struct proxy_arp*)kb;
  
  memcpy(&pxarp, sx, sizeof(struct proxy_arp));
  
  if( pxarp.enabled )
    pxarp.ifp = ifunit(pxarp.ifname);
}

static u_int8_t
pxarp_match_src(struct sx_xaddr *addr)
{
  int d = 0;

  d = match_range(&pxarp.from.addr, &pxarp.to.addr, &addr->addr, addr->af);

  return (d);
}

static u_int8_t
pxarp_match(struct ifnet *ifp, struct sx_xaddr *addr)
{
  int d = 0;

  printf("%d, %d, %d\n",
	 pxarp.enabled,
	 pxarp.ifp == ifp,
	 pxarp_match_src(addr));
  
  if( pxarp.enabled &&
      pxarp.ifp == ifp &&
      pxarp_match_src(addr) ) {
    d = 1;
  }
      
  return (d);
}

/*
  checkarp

  check responsibility of the ARP request
  return true if responsible

  arpbuf is pointing top of link-level frame
*/

static int
checkarp(struct arphdr *arp, struct ifnet *ifp)
{
  struct sx_xaddr target_ip;

  if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
      ntohs(arp->ar_op)  != ARPOP_REQUEST ||
      /* XXX: ARPHRD_802 */
      ntohs(arp->ar_pro) != ETHERTYPE_IP ||
      (int) (arp->ar_hln) != ETHER_ADDR_LEN || /* length of ethernet addr */
      (int) (arp->ar_pln) != 4){  /* length of protocol addr */
    return (0);
  }
  if ( (*(u_int32_t *)(ar_spa(arp))) == (*(u_int32_t *)(ar_tpa(arp))) ) {
    return (0);
  }
  target_ip.addr.addr32[0] = (*(u_int32_t *)(ar_tpa(arp)));
  target_ip.af = AF_INET;

  return (pxarp_match(ifp, &target_ip));
}

static int
arp_fillhdr(struct ifnet *ifp, struct arphdr *ah, int bcast, u_char *buf, size_t *bufsize)
{
  struct if_encap_req ereq;
  int error;

  bzero(buf, *bufsize);
  bzero(&ereq, sizeof(ereq));
  ereq.buf = buf;
  ereq.bufsize = *bufsize;
  ereq.rtype = IFENCAP_LL;
  ereq.family = AF_ARP;
  ereq.lladdr = ar_tha(ah);
  ereq.hdata = (u_char *)ah;
  if (bcast)
    ereq.flags = IFENCAP_FLAG_BROADCAST;
  error = ifp->if_requestencap(ifp, &ereq);
  if (error == 0)
    *bufsize = ereq.bufsize;

  struct ether_header *eh;
  eh = (struct ether_header *)ereq.buf;

  return (error);
}

u_int8_t 
chk_arp(struct mbuf *m, struct ether_header *eh, struct ifnet *ifp, int dir)
{
  struct arphdr *ah = NULL;
  struct rm_priotracker rmpt;

  if( dir==FW_OUT )
    return (FW_PASS);

  if (m->m_len < sizeof(struct arphdr) &&
      ((m = m_pullup(m, sizeof(struct arphdr))) == NULL)) {
    return (FW_DROP);
  }
  ah = mtod(m, struct arphdr *);
  
  if (m->m_len < arphdr_len(ah)) {
    if ((m = m_pullup(m, arphdr_len(ah))) == NULL) {
      return (FW_DROP);
    }
    ah = mtod(m, struct arphdr *);
  }
  
  if (ah->ar_pln != sizeof(struct in_addr)) {
    return (FW_PASS);
  }
  
  Z_RLOCK(&z_lock, &rmpt);

  if( checkarp(ah, ifp) ) {
        
    struct mbuf *m1 = NULL;
    
    struct sockaddr sa;
    struct route ro;
    uint8_t linkhdr[LLE_MAX_LINKHDR];
    size_t linkhdrsize = 0;
    struct arphdr *ah1 = NULL;

    m1 = m_gethdr(M_NOWAIT, MT_DATA);

    if( m1 == NULL )
      goto drop;
        
    m_clrprotoflags(m1);

    m1->m_nextpkt = NULL;
    m1->m_pkthdr.rcvif = NULL;
    m1->m_len = sizeof(*ah1) + 2 * sizeof(struct in_addr) + 2 * ifp->if_addrlen;
    m1->m_pkthdr.len = m1->m_len;
    M_ALIGN(m1, m1->m_len);
    ah1 = mtod(m1, struct arphdr *);
    bzero((caddr_t)ah1, m1->m_len);

    ah1->ar_pro = htons(ETHERTYPE_IP);
    ah1->ar_hln = ifp->if_addrlen;           
    ah1->ar_pln = sizeof(struct in_addr);    
    ah1->ar_op = htons(ARPOP_REPLY);
    memcpy(ar_sha(ah1), pxarp.macaddr, ah1->ar_hln);
    memcpy(ar_tha(ah1), ar_sha(ah), ah1->ar_hln);
    memcpy(ar_spa(ah1), ar_tpa(ah), ah1->ar_pln);
    memcpy(ar_tpa(ah1), ar_spa(ah), ah1->ar_pln);
    
    sa.sa_family = AF_ARP;
    sa.sa_len = 2;
    bzero(&ro, sizeof(ro));
    linkhdrsize = sizeof(linkhdr);
    arp_fillhdr(ifp, ah1, 0, linkhdr, &linkhdrsize);
    ro.ro_prepend = linkhdr;
    ro.ro_plen = linkhdrsize;
    ro.ro_flags = 0;

    Z_RUNLOCK(&z_lock, &rmpt);
    (*ifp->if_output)(ifp, m1, &sa, &ro);
    Z_RLOCK(&z_lock, &rmpt);

  drop:
    Z_RUNLOCK(&z_lock, &rmpt);
    m_freem(m);
    return (FW_DROP);
  }
      
  Z_RUNLOCK(&z_lock, &rmpt);
  return (FW_PASS);
}
