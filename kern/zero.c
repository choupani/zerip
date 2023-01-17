#include "./precom.h"
#include "./define.h"
#include "./stdinc.h"
#include "./ioctl.h"
#include "./pktbuf.h"
#include "./inito.h"
#include "./dinito.h"
#include "./pxarp.h"
#include "./mem_defs.h"
#include "../com/ioctl_def.h"

MALLOC_DEFINE(M_ZERO_IOCTL, "zero_ioctl", DEV_NAME " ioctl");

static int IPv4_hooked  = 0;
static int IPv6_hooked  = 0;
static int ETH_hooked   = 0;

d_open_t  dev_open;
d_close_t dev_close;
d_read_t  dev_read;
d_write_t dev_write;
d_ioctl_t dev_ioctl;

static struct cdev *sdev;
static int count = 0;       /* Device Busy flag */

u_int8_t z_hooked  = 0;
u_int8_t z_running = 0;

struct rmlock  z_lock;

static int pkt_rcv(void*, struct mbuf**, struct ifnet*, struct ifnet*, int, int);

static struct cdevsw flwacct_cdevsw = {
  .d_version = D_VERSION,
  .d_open    = dev_open,
  .d_close   = dev_close,
  .d_read    = dev_read,
  .d_write   = dev_write,
  .d_ioctl   = dev_ioctl,
  .d_name    = DEV_NAME,
  .d_flags   = D_TTY,
};

static int
layer2_hook(struct pktbuf *pkt)
{
  int dir;
  u_int16_t etype = 0;

  if( pkt->eth )
    etype = ntohs(pkt->eth->ether_type);
  
  dir = (pkt->oifp==NULL)?(FW_IN):(FW_OUT);

  if(pkt->eth != NULL && ntohs(pkt->eth->ether_type)==ETHERTYPE_ARP ) {
    if( chk_arp(pkt->m, pkt->eth, pkt->iifp, dir) == FW_DROP ) {
      pkt->m = NULL;
      return (FW_DROP);
    }
  }
  
  return (FW_PASS);
}

static int
input_hook(void *arg, struct mbuf **m, struct ifnet *ifp, int dir, int flags, struct inpcb *inp)
{
  
  int action = FW_PASS;

  action = pkt_rcv(arg, m, ifp, ifp, dir, flags);

  return (action);
}

static int
output_hook(void *arg, struct mbuf **m, struct ifnet *ifp, int dir, int flags, struct inpcb *inp)
{
  int action = FW_PASS;

  action = pkt_rcv(arg, m, ifp, ifp, dir, flags);

  return (action);
}

/*
 * processing for ethernet packets (in and out).
 */
static int
ether_hook(void *arg, struct mbuf **m0, struct ifnet *ifp, int dir, int flags, struct inpcb *inp)
{
  struct ether_header *eh;
  struct ether_header save_eh;
  struct mbuf *m;
  int i, ret;
  struct pktbuf pkt;

  /* I need some of data to be contiguous */
  m = *m0;
  i = min(m->m_pkthdr.len, max_protohdr);
  if (m->m_len < i) {
    m = m_pullup(m, i);
    if (m == NULL) {
      *m0 = m;
      return (0);
    }
  }

  eh = mtod(m, struct ether_header *);
  save_eh = *eh;           
  m_adj(m, ETHER_HDR_LEN); 

  pkt.m = m;           
  pkt.oifp = (dir == PFIL_OUT) ? ifp : NULL;
  pkt.iifp = ifp;
  pkt.eth = &save_eh; 
  ret = layer2_hook(&pkt);
  m = pkt.m;

  if (m != NULL) {
    M_PREPEND(m, ETHER_HDR_LEN, M_NOWAIT);
    if (m == NULL) {
      *m0 = NULL;
      return (0);
    }
    if (eh != mtod(m, struct ether_header *)) {
      bcopy(&save_eh, mtod(m, struct ether_header *), ETHER_HDR_LEN);
    }
  }
  
  *m0 = m;

  if (ret != 0) {
    if (*m0) {
      FREE_PKT(*m0);
    }
    *m0 = NULL;
  }
  
  return (ret);
}

static int
init_module(void)
{
  struct pfil_head *pfh_inet = NULL;
  struct pfil_head *pfh_inet6 = NULL;
  struct pfil_head *pfh_eth = NULL;

  if (z_hooked)
    return (0);

  init_objects();
  
  pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
  if (pfh_inet == NULL)
    return (ENOENT);
  pfil_add_hook_flags(input_hook, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet);
  pfil_add_hook_flags(output_hook, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet);
  IPv4_hooked = 1;
  

  pfh_inet6 = pfil_head_get(PFIL_TYPE_AF, AF_INET6);
  if (pfh_inet6 == NULL)
    return (ENOENT);
  
  pfil_add_hook_flags(input_hook, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet6);
  pfil_add_hook_flags(output_hook, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet6);
  IPv6_hooked = 1;
  
  pfh_eth = pfil_head_get(PFIL_TYPE_AF, AF_LINK);
  if (pfh_eth == NULL)
    return (ENOENT);
  pfil_add_hook_flags(ether_hook, NULL, PFIL_IN | PFIL_OUT | PFIL_WAITOK, pfh_eth);
  ETH_hooked = 1;

  z_hooked = 1;
  z_running = 1;
  
  sdev = make_dev(&flwacct_cdevsw,
		  MOD_MINOR,
		  UID_ROOT,
		  GID_WHEEL,
		  0600,
		  DEV_NAME);
  
  printf("loaded " DEV_NAME " kernel module.\n");
  
  return (0);
}

static int
deinit_module(void)
{
  struct pfil_head *pfh_inet;
  struct pfil_head *pfh_inet6;
  struct pfil_head *pfh_eth;

  if (!z_hooked)
    return (0);

  pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
  if (pfh_inet == NULL)
    return (ENOENT);
  if( IPv4_hooked ) {
    pfil_remove_hook_flags(input_hook, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet);
    pfil_remove_hook_flags(output_hook, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet);
  }
  
  pfh_inet6 = pfil_head_get(PFIL_TYPE_AF, AF_INET6);
  if (pfh_inet6 == NULL)
    return (ENOENT);
  if( IPv6_hooked ) {
    pfil_remove_hook_flags(input_hook, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet6);
    pfil_remove_hook_flags(output_hook, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet6);
  }

  pfh_eth = pfil_head_get(PFIL_TYPE_AF, AF_LINK);
  if (pfh_eth == NULL)
    return (ENOENT);
  if( ETH_hooked )
    pfil_remove_hook_flags(ether_hook, NULL, PFIL_IN | PFIL_OUT | PFIL_WAITOK, pfh_eth);

  IPv4_hooked = 0;
  IPv6_hooked = 0;
  ETH_hooked  = 0;

  z_hooked  = 0;
  z_running = 0;

  dinit_objects();
 
  destroy_dev(sdev);
  
  printf("unloaded " DEV_NAME " kernel module.\n");
  
  return (0);
}

static int
mod_evhandler(struct module *m, int what, void *arg)
{
  int err = 0;
    
  switch(what) {
  case MOD_LOAD:
    err = init_module();
  break;
  case MOD_QUIESCE:
  case MOD_SHUTDOWN:
    err = deinit_module();
    break;
  case MOD_UNLOAD:
  break;
  default:
    err = EINVAL;
  break;
  }
  return (err);
}

int
dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
  int err = 0;
  count++;
  return (err);
}

int
dev_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
  int err = 0;
  if( count>0 )
    count--;
  return (err);
}

int
dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
  return (0);
}

int
dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{  
  return (0);
}

static int
pkt_rcv(void *arg, struct mbuf **m, struct ifnet *iifp, struct ifnet *oifp, int dir, int flag)
{
  u_int16_t action = FW_PASS;
  sa_family_t af;
  struct pktbuf pkt;

  if(!z_running)
    goto PASS;

  if (mtod(*m, struct ip *)->ip_v == 4)
    af = AF_INET;
  else
    af = AF_INET6;

  if( (*m)->m_flags&M_SKIP_ZEROIP ) 
    goto PASS;
    
  pkt.iifp = iifp;
  pkt.oifp = oifp;
  pkt.af   = af;
  pkt.dir  = dir;
  pkt.m    = *m;
  pkt.frag = 0;
  pkt.local_src = 0;
  pkt.local_dst = 0;

  action = process_pkt(&pkt);
  
  switch ( action ) {
  case FW_DROP:
    if( pkt.m )
      m_freem(*m);
    *m = NULL;
    break;
  }
  
 PASS:
  return (action);
}

int
dev_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags, struct thread *td)
{
  int error = NO_ERROR;
  struct ioctlbuffer *ub = NULL;
  caddr_t *kb = NULL;
  struct ioctlST iost;
  u_int8_t copy_out = 0;
  
  if( !z_hooked )
    return (EACCES);

  ub = (struct ioctlbuffer *)addr;
  if (ub == NULL)
    return (ERROR_INVALID);
  kb = MEM_ALLOC(ub->size, M_ZERO_IOCTL, M_NOWAIT);
  if (kb == NULL) {
    return (ERROR_MALLOC);
  }
  if (copyin(ub->buffer, kb, ub->size)) {
    MEM_FREE(kb, M_ZERO_IOCTL);
    return (ERROR_INVALID);
  }

  iost.ub = ub;
  iost.kb = kb;

  error = parsecmd(&iost, cmd, &copy_out);

  if (kb != NULL) {
    if( copy_out )
      if (copyout(kb, ub->buffer, ub->size))
	error = ERROR_INVALID;
    MEM_FREE(kb, M_ZERO_IOCTL);
  }

  return (error);
}

DEV_MODULE(zeroip, mod_evhandler, NULL);
MODULE_VERSION(zeroip, 1);
