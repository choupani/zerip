
#include "./dinito.h"
#include "./ipset.h"

void 
dinit_objects(void)
{
  Z_WLOCK(&z_lock);
  ipset_clear();
  Z_WUNLOCK(&z_lock);

  Z_LOCK_DESTROY(&z_lock);
}
