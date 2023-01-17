
#include "./dhcpr.h"
#include "./nt_udp.h"
#include "./cksum.h"
#include "../com/ioctl_def.h"

struct dhcp_relay dhcp_r;

void 
dhcpr_init(void)
{
  bzero(&dhcp_r, sizeof(struct dhcp_relay));
}

void 
dhcpr_clr(void)
{
  dhcpr_init();
}

void 
dhcpr_set(caddr_t *kb)
{
  struct dhcp_relay *sx = (struct dhcp_relay*)kb;
  
  memcpy(&dhcp_r, sx, sizeof(struct dhcp_relay));
  
  if( dhcp_r.enabled ) {
    dhcp_r.ifp = ifunit(dhcp_r.ifname);
    if( dhcp_r.ifp ) {
      if_addr_rlock(dhcp_r.ifp);
      memcpy(dhcp_r.macaddr, IF_LLADDR(dhcp_r.ifp),  ETHER_ADDR_LEN);
      if_addr_runlock(dhcp_r.ifp);
    }
  }
}

u_int8_t
chk_dhcp(struct pktbuf *pkt, int off)
{
  int dlen = 0;
  u_int8_t ether_output = 0;
  struct dhcp_packet dhcp_pkt;
  struct udphdr *uh = pkt->hdr.udp;
  struct ifnet *ifp = NULL;
  struct sx_addr bind_addr;
  struct mbuf *m = NULL;
  struct ether_header eh;
  u_char relay_shost[ETHER_ADDR_LEN];
  u_char relay_dhost[ETHER_ADDR_LEN];
  struct rm_priotracker rmpt;
  static u_char broadcast_eth[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


#define MAX_DHCP_PACKET sizeof(struct dhcp_packet)
  
  dlen = MIN(MAX_DHCP_PACKET, pkt->m->m_pkthdr.len - off);

  Z_RLOCK(&z_lock, &rmpt);
  
  if( !dhcp_r.enabled ||
      dhcp_r.ifp == NULL ||
      pkt->af != AF_INET )
    goto done;
  
  m_copydata(pkt->m, off, dlen, (void*)&dhcp_pkt);

  if( dhcp_pkt.op == BOOTREQUEST ) {
    if( dhcp_r.ifp == pkt->iifp ) {

      dhcp_pkt.giaddr = dhcp_r.local_addr.addr.v4;
      dhcp_pkt.hops++;

      Z_RUNLOCK(&z_lock, &rmpt);
      
      send_udp(pkt->af,
	       &dhcp_r.local_addr.addr, &dhcp_r.dhcp_server.addr,
	       DHCP_PORT, DHCP_PORT,
	       NULL, (u_int8_t*)&dhcp_pkt, dlen);

      Z_RLOCK(&z_lock, &rmpt);
      
      goto drop;
    }
  } else if( dhcp_pkt.op == BOOTREPLY ) {
    if( !sx_addr_cmp(pkt->saddr, &dhcp_r.dhcp_server.addr, pkt->af) &&
	!sx_addr_cmp(pkt->daddr, &dhcp_r.local_addr.addr, pkt->af) ) {

      ifp = dhcp_r.ifp;
	
      bind_addr.v4 = dhcp_pkt.yiaddr;
      bzero(&dhcp_pkt.giaddr, sizeof(dhcp_pkt.giaddr));

      memcpy(relay_shost, dhcp_r.macaddr, ETHER_ADDR_LEN);
      memcpy(relay_dhost, dhcp_pkt.chaddr, ETHER_ADDR_LEN);
     	
      if( ntohs(dhcp_pkt.flags) == DHCP_BROADCAST_MASK ) {
	bind_addr.v4.s_addr = INADDR_BROADCAST;
	memcpy(relay_dhost, broadcast_eth, ETHER_ADDR_LEN);
      } 

      uh->uh_dport = ntohs(DHCP_PORT+1);

      pkt->saddr->v4 = dhcp_r.local_addr.addr.v4;
      pkt->daddr->v4 = bind_addr.v4;

      ether_output = 1;
    }
  }
  

  if( ether_output && ifp )  {

    pkt->m->m_flags &= ~(M_MCAST|M_BCAST);
    m_copyback(pkt->m, off, dlen, (caddr_t )&dhcp_pkt);
    
    fix_cksum(pkt, off - sizeof(*uh));
    
    m = m_dup(pkt->m, M_NOWAIT);
    if( m ) {
      m->m_flags |= M_SKIP_ZEROIP;
      
      M_PREPEND(m, ETHER_HDR_LEN, M_NOWAIT);
      if (m != NULL) {
	memcpy(eh.ether_shost, relay_shost, ETHER_ADDR_LEN);
	memcpy(eh.ether_dhost, relay_dhost, ETHER_ADDR_LEN);
	eh.ether_type = ntohs(ETHERTYPE_IP);
	bcopy(&eh, mtod(m, struct ether_header *), ETHER_HDR_LEN);

	m->m_nextpkt = NULL;
	m->m_pkthdr.rcvif = NULL;

	Z_RUNLOCK(&z_lock, &rmpt);
	
	ether_output_frame(ifp, m);
	//(ifp->if_transmit)(ifp, m);

	Z_RLOCK(&z_lock, &rmpt);
      }
    }

    goto drop;
  }

 done:

  Z_RUNLOCK(&z_lock, &rmpt);
  
  return (FW_PASS);

 drop:

  Z_RUNLOCK(&z_lock, &rmpt);
  
  return (FW_DROP);
}
