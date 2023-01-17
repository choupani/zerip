#ifndef _KRN_DEFINE_H
#define _KRN_DEFINE_H

#define  MOD_VERSION   "1.0"
#define  DEV_NAME      "zeroip"

#define  MOD_MINOR     15

#define MAX_URL_RW 104

enum  {FW_IN=1, FW_OUT};

enum  {FW_PASS, FW_DROP};

#define M_SKIP_ZEROIP       M_PROTO12        /* packet processed by zero */

extern struct rmlock  z_lock;

#define	Z_LOCK_INIT(l, t)       rm_init(l, DEV_NAME " " t " rmlock")
#define	Z_LOCK_DESTROY(l)	rm_destroy(l)
#define	Z_TRY_RLOCK(l, t)	rm_try_rlock(l, (t))
#define	Z_RLOCK(l, t)	        rm_rlock(l, (t))
#define	Z_WLOCK(l)		rm_wlock(l)
#define	Z_RUNLOCK(l, t)	        rm_runlock(l, (t))
#define	Z_WUNLOCK(l)		rm_wunlock(l)
#define	Z_WOWNED(l)		rm_wowned(l)

#define PULLUP_TO(len, p, T)			\
  do {						\
    int x = (len) + (T);			\
    if (pkt->m->m_len < x)			\
      pkt->m = m_pullup(pkt->m, x);		\
    p = mtod(pkt->m, char *) + (len);		\
  } while (0)

#endif

