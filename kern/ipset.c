
#include "./ipset.h"
#include "./stdinc.h"

int ipbnd_num = 0;

static MALLOC_DEFINE(M_ZERO_IPSET, "zero_ipset",  DEV_NAME " ipset");

static __inline int ipset_compare(struct ipset *, struct ipset *);
struct ipset_tree tree_ipset_tracking;
RB_GENERATE(ipset_tree, ipset, entry, ipset_compare);

static int
ipset_compare(struct ipset *a, struct ipset *b)
{
  int diff = 0;

  if ((diff = a->addr.af - b->addr.af) != 0) return (diff);
  diff = sx_addr_cmp(&a->addr.addr, &b->addr.addr, a->addr.af);
  if(diff!=0) return (diff);
  return (0);
}

void 
ipset_insert(struct ioctlbuffer *ub, caddr_t *kb)
{
  int n = 0;

  if( ub->size < sizeof (struct ipset) ) {
    printf("ub size is too small then skip.\n");
    return;
  }
  struct ipset *sxs = (struct ipset *)((u_int8_t*)kb);

  for( n = 0; n < ub->entries; ++n ) {

    struct ipset *sx;

    sx = MEM_ALLOC(sizeof(struct ipset), M_ZERO_IPSET, M_NOWAIT);
    if( sx == NULL ) {
      printf("memory allocation to ipset failed\n");
    }
    
    sx->addr.af = sxs->addr.af;
    sx_addrcpy(&sx->addr.addr, &sxs->addr.addr, sxs->addr.af);

    //sx_print_addr(&sx->addr.addr, sx->addr.af);
    //printf("\n");

    if( RB_INSERT(ipset_tree, &tree_ipset_tracking, sx) != NULL ) {
      printf("ipset insert failed\n");
      MEM_FREE(sx, M_ZERO_IPSET);
    } else {
      ipbnd_num++;
    }

    sxs = (sxs + 1);
  }
}

void 
ipset_clear(void)
{
  struct ipset *cur, *next;

  for(cur = RB_MIN(ipset_tree, &tree_ipset_tracking); cur; cur = next) {
    next = RB_NEXT(ipset_tree, &tree_ipset_tracking, cur);
    
    RB_REMOVE(ipset_tree, &tree_ipset_tracking, cur);

    MEM_FREE(cur, M_ZERO_IPSET);
  }

  ipbnd_num = 0;
}

void 
ipset_init(void)
{
  RB_INIT(&tree_ipset_tracking);
}

int 
match_ipset(struct sx_addr *addr, sa_family_t af)
{
  int d = 0;
  struct ipset k;
  struct ipset *sx = NULL;

  k.addr.af = af;
  sx_addrcpy(&k.addr.addr, addr, af);

  sx = RB_FIND(ipset_tree, &tree_ipset_tracking, &k);

  if( sx == NULL ) {
    goto done;
  }

  d = 1;

 done:

  return (d);
}
