
#include "./cksum.h"

void
fix_in4_cksum(struct mbuf *m, struct ip *ip4)
{
  ip4->ip_sum = 0;
  ip4->ip_sum = in_cksum(m, ip4->ip_hl << 2);
}

void
fix_cksum(struct pktbuf *pkt, int off)
{
  if( pkt->af==AF_INET && pkt->proto==IPPROTO_UDP ) {

    fix_in4_cksum(pkt->m, pkt->iph.ip4);
      
    pkt->hdr.udp->uh_sum = in_pseudo(pkt->iph.ip4->ip_src.s_addr,
				    pkt->iph.ip4->ip_dst.s_addr,
				    htons(pkt->proto + ntohs(pkt->iph.ip4->ip_len) - (pkt->iph.ip4->ip_hl << 2))
				    );
    pkt->hdr.udp->uh_sum = in_cksum_skip(pkt->m, ntohs(pkt->iph.ip4->ip_len), (pkt->iph.ip4->ip_hl << 2));
    if( pkt->hdr.udp->uh_sum == 0 )
      pkt->hdr.udp->uh_sum = 0xffff;
  }
}
