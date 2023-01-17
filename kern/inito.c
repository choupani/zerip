
#include "./inito.h"
#include "./ipset.h"
#include "./dhcpr.h"
#include "./pxarp.h"

void 
init_objects(void)
{
  Z_LOCK_INIT(&z_lock, "shared");
  
  ipset_init();
  dhcpr_init();
  pxarp_init();
}
