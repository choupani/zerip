
#include "./ioctl.h"
#include "./ipset.h"
#include "./dhcpr.h"
#include "./pxarp.h"
#include "../com/ioctl_def.h"


extern u_int8_t z_running;

static int ioctl_start(struct ioctlST*);
static int ioctl_stop(struct ioctlST*);
static int ioctl_SETipset(struct ioctlST*);
static int ioctl_CLRipset(struct ioctlST*);
static int ioctl_SETdhcpr(struct ioctlST*);
static int ioctl_CLRdhcpr(struct ioctlST*);
static int ioctl_SETpxarp(struct ioctlST*);
static int ioctl_CLRpxarp(struct ioctlST*);


struct zero_ioctl
{
  u_long     cmd;
  int (*funcname) (struct ioctlST*);
  u_int8_t   copy_out;
} zero_ioctl_list[] = {

  {IOCSTART,           ioctl_start,                   0},
  {IOCSTOP,            ioctl_stop,                    0},
  {IOCSETIPSET,        ioctl_SETipset,                0},
  {IOCCLRIPSET,        ioctl_CLRipset,                0},
  {IOCSETDHCPR,        ioctl_SETdhcpr,                0},
  {IOCCLRDHCPR,        ioctl_CLRdhcpr,                0},
  {IOCSETPXARP,        ioctl_SETpxarp,                0},
  {IOCCLRPXARP,        ioctl_CLRpxarp,                0},
  
  {0,                  NULL,                          0}
};

int
parsecmd(struct ioctlST *iost, u_long cmd, u_int8_t *copy_out)
{
  int error = ERROR_INVALID;
  int n = 0;
  u_int8_t found = 0;

  while( zero_ioctl_list[n].funcname ) {

    if( cmd == zero_ioctl_list[n].cmd ) {
      error = zero_ioctl_list[n].funcname(iost);
      *copy_out = zero_ioctl_list[n].copy_out;
      found = 1;
      break;
    }
    
    ++n;
  }

  if( !found )
    printf("Not found ioctl: %lu\n", cmd);

  return (error);
}

static int
ioctl_start(struct ioctlST *iost)
{
  int error = 0;

  if (z_running)
    error = ERROR_INVALID;
  else {
    z_running = 1;
    printf("zero kernel module started.\n");
  }

  return (error);
}

static int
ioctl_stop(struct ioctlST *iost)
{
  int error = 0;

  if (!z_running)
    error = ERROR_INVALID;
  else {
    z_running = 0;
    printf("zero kernel module stopped.\n");
  }

  return (error);
}

static int
ioctl_SETipset(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  ipset_insert(iost->ub, iost->kb);

  Z_WUNLOCK(&z_lock);

  return (error);
}

static int
ioctl_CLRipset(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  ipset_clear();
  ipset_init();

  Z_WUNLOCK(&z_lock);

  return (error);
}      

static int
ioctl_SETdhcpr(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  dhcpr_set(iost->kb);

  Z_WUNLOCK(&z_lock);

  return (error);
}

static int
ioctl_CLRdhcpr(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  dhcpr_clr();

  Z_WUNLOCK(&z_lock);

  return (error);
}      

static int
ioctl_SETpxarp(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  pxarp_set(iost->kb);

  Z_WUNLOCK(&z_lock);

  return (error);
}

static int
ioctl_CLRpxarp(struct ioctlST *iost)
{
  int error = 0;

  Z_WLOCK(&z_lock);
  
  pxarp_clr();

  Z_WUNLOCK(&z_lock);

  return (error);
}      
