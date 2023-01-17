
#include "./precom.h"
#include "./paths.h"
#include "../kern/addr.h"
#include "../kern/ipset.h"
#include "../kern/dhcpr.h"
#include "../kern/pxarp.h"
#include "../com/ioctl_def.h"


/*
returns 1 if string 'addr' has two or more ':' characters.
*/
static u_int8_t 
is_ipv6(const char *addr)
{
  struct in6_addr in6;
  if( inet_pton(AF_INET6, addr, (void *)&in6)!=1 )
    return (0);
  return (1);

}

/*
return 1 if a string appears to be an IP address
*/
static u_int8_t 
is_ipv4(const char *addr)
{
  struct in_addr in4;
  if( inet_pton(AF_INET, addr, (void *)&in4)!=1 )
    return (0);
  return (1);
}

/*
return 1 if a string appears to be an IP address
*/
static u_int8_t 
is_valid_addr(const char *addr)
{
  return (is_ipv4(addr) || is_ipv6(addr));
}

static u_int8_t
parse_addr_value(const char* str, struct sx_xaddr *sx)
{
  u_int8_t d = 0;

  sx->af = AF_INET;
  if( inet_pton(sx->af, str, (void *)&sx->addr.v4)==1 ) 
    d = 1;
  else {
    sx->af = AF_INET6;
    if( inet_pton(sx->af, str, (void *)&sx->addr.v6)==1 )
      d = 1;
  }

  if(!d)
    printf("addr %s is not valid.\n", str);
  
  return (d);
}

void
MAC_str2bin(const char* szMAC, u_char pbHexMAC[ETHER_ADDR_LEN])
{
  u_char pbh[ETHER_ADDR_LEN*2+1] = {0};
  sscanf(szMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &pbh[0], &pbh[1], &pbh[2], &pbh[3], &pbh[4], &pbh[5]);
  memcpy(pbHexMAC, pbh, ETHER_ADDR_LEN);
  
  return;
}

int 
ioctl_set_ipset(int dev, struct ipset *data, int count)
{
  struct ioctlbuffer iobuf;
  int n = 0 , error;

  memset(&iobuf, 0, sizeof (iobuf));

  iobuf.entries = count;
  iobuf.size = sizeof (struct ipset)*iobuf.entries;
  iobuf.buffer = data;
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    return (ERROR_MALLOC);
  }

  error = ioctl(dev, IOCSETIPSET, &iobuf);
  
  return (error);
}

static int
ioctl_clear_ipset(int dev)
{
  struct ioctlbuffer iobuf;
  int error = ERROR_INVALID;

  memset(&iobuf, 0, sizeof (iobuf));	
  iobuf.buffer = malloc(iobuf.size);
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    goto done;
  }
  
  error = ioctl(dev, IOCCLRIPSET, &iobuf);

 done:

  if( iobuf.buffer )
    free(iobuf.buffer);
  
  return (error);
}

int 
ioctl_set_dhcpr(int dev, struct dhcp_relay *sx)
{
  struct ioctlbuffer iobuf;
  int n = 0 , error;

  memset(&iobuf, 0, sizeof (iobuf));

  iobuf.entries = 1;
  iobuf.size = sizeof (struct dhcp_relay)*iobuf.entries;
  iobuf.buffer = (void*)sx;
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    return (ERROR_MALLOC);
  }

  error = ioctl(dev, IOCSETDHCPR, &iobuf);
  
  return (error);
}

static int
ioctl_clear_dhcpr(int dev)
{
  struct ioctlbuffer iobuf;
  int error = ERROR_INVALID;

  memset(&iobuf, 0, sizeof (iobuf));	
  iobuf.buffer = malloc(iobuf.size);
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    goto done;
  }
  
  error = ioctl(dev, IOCCLRDHCPR, &iobuf);

 done:
  if( iobuf.buffer )
    free(iobuf.buffer);
  
  return (error);
}

int 
ioctl_set_pxarp(int dev, struct proxy_arp *sx)
{
  struct ioctlbuffer iobuf;
  int n = 0 , error;

  memset(&iobuf, 0, sizeof (iobuf));

  iobuf.entries = 1;
  iobuf.size = sizeof (struct proxy_arp)*iobuf.entries;
  iobuf.buffer = (void*)sx;
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    return (ERROR_MALLOC);
  }

  error = ioctl(dev, IOCSETPXARP, &iobuf);
  
  return (error);
}

static int
ioctl_clear_pxarp(int dev)
{
  struct ioctlbuffer iobuf;
  int error = ERROR_INVALID;

  memset(&iobuf, 0, sizeof (iobuf));	
  iobuf.buffer = malloc(iobuf.size);
  if( !iobuf.buffer ) {
    printf("allocation failed size:%d, %s:%d.\n", iobuf.size, __FUNCTION__, __LINE__);
    goto done;
  }
  
  error = ioctl(dev, IOCCLRPXARP, &iobuf);

 done:
  if( iobuf.buffer )
    free(iobuf.buffer);
  
  return (error);
}

int
load_dhcpr(int dev, const char *file)
{
  static const int max_line_len = 255;

  FILE *fd = NULL;
  char key[max_line_len+1];
  char val[max_line_len+1];
  size_t len = 0;
  struct dhcp_relay sx;

  ioctl_clear_dhcpr(dev);

  bzero(&sx, sizeof(struct dhcp_relay));

  fd = fopen(file, "r");
  
  if( fd ) {
    
    while (fscanf(fd, "%50[^=]=%200[^\n]%*c", key, val) == 2) {
      if (!strcmp(key, "enabled")) {
	sx.enabled = atoi(val);
      } else if (!strcmp(key, "server")) {
	if( !parse_addr_value(val, &sx.dhcp_server) )
	  printf("IP Address [%s] is not valid in dhcp-relay.\n", val);
      } else if (!strcmp(key, "local")) {
	if( !parse_addr_value(val, &sx.local_addr) )
	  printf("IP Address [%s] is not valid in dhcp-relay.\n", val);
      } else if (!strcmp(key, "ifname")) {
	strlcpy(sx.ifname, val, IFNAMSIZ);
      }
    }
    
    ioctl_set_dhcpr(dev, &sx);

    fclose(fd);

  } else {
    printf("open file [%s] failed.\n", file);
    return (-1);
  }

  return (0);
}

int
load_pxarp(int dev, const char *file)
{
  static const int max_line_len = 255;

  FILE *fd = NULL;
  char key[max_line_len+1];
  char val[max_line_len+1];
  size_t len = 0;
  struct proxy_arp sx;

  ioctl_clear_pxarp(dev);

  bzero(&sx, sizeof(struct proxy_arp));

  fd = fopen(file, "r");

  if( fd ) {
    
    while (fscanf(fd, "%50[^=]=%200[^\n]%*c", key, val) == 2) {
      if (!strcmp(key, "enabled")) {
	sx.enabled = atoi(val);
      } else if (!strcmp(key, "from")) {
	if( !parse_addr_value(val, &sx.from) )
	  printf("IP Address [%s] is not valid in proxy-arp.\n", val);
      } else if (!strcmp(key, "to")) {
	if( !parse_addr_value(val, &sx.to) )
	  printf("IP Address [%s] is not valid in proxy-arp.\n", val);
      } else if (!strcmp(key, "ifname")) {
	strlcpy(sx.ifname, val, IFNAMSIZ);
      } else if (!strcmp(key, "macaddr")) {
	MAC_str2bin(val, sx.macaddr);
      }
    }
    
    ioctl_set_pxarp(dev, &sx);

    fclose(fd);

  } else {
    printf("open file [%s] failed.\n", file);
    return (-1);
  }

  return (0);
}

int
load_ipset(int dev, const char *file)
{
  static const int max_line_len = 255;
  static const int max_count = 64000;

  FILE *fd = NULL;
  char line[max_line_len+1];
  size_t len = 0, count = 0, cur = 0, total = 0;
  struct ipset sx;
  struct ipset *data = NULL;

  data = (struct ipset*)malloc(max_count*sizeof(struct ipset));

  if(data==NULL) {
    printf("allocation failed %s:%d.\n",  __FUNCTION__, __LINE__);
    return (-1);
  }

  ioctl_clear_ipset(dev);

  fd = fopen(file, "r");
  
  if( fd ) {
    
    while(1) {

      if( fgets(line, max_line_len, fd)!=NULL ) {
	len = strlen(line);
	if(len>1) {
	  if(line[len-1] == '\n')
	    line[len-1] = 0;
	  if(line[0]=='#' || !parse_addr_value(line, &sx.addr) )
	    continue;
	  
	  ++total;
	  memcpy(data+count++, &sx, sizeof(struct ipset));
	  if( count==max_count ) {
	    ioctl_set_ipset(dev, data, count);
	    count = 0;
	  }
	}
      }

      if( feof(fd) )
	break;
    }

    if( count )
      ioctl_set_ipset(dev, data, count);

    fclose(fd);

    if(data) free(data);
    
  } else {
    if(data) free(data);
    printf("open file [%s] failed.\n", file);
    return (-1);
  }

  printf("Read [%lu] IP address in ipset.\n", total);

  return (0);
}

int
get_cur_path(char *cur_path, size_t len)
{
  int mib[4];

  cur_path[0] = '\0';
  
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;
  
  if (sysctl(mib, 4, cur_path, &len, NULL, 0) != 0)
    return (0);
  
  return (len);
}

void
get_cfg_path(char *cur_path, char *cfg_path)
{
  char *last = NULL;

  cfg_path[0] = 0;
  
  last = strrchr(cur_path, '/');
  if( last ) {
    strncpy(cfg_path, cur_path, last-cur_path);
    last = strrchr(cfg_path, '/');
    if( last ) 
      cfg_path[last-cfg_path] = 0;
  }
  
  return;  
}

/*
 * Display usage to the user.
 */
static void
display_usage(void)
{
  printf("Usage: %s [options]\n", DEV_NAME);
  printf("\
Options:\n\
\t-i\tReload ipset block ip addresses.\n\
\t-r\tReload dhcp relay configuration.\n\
\t-p\tReload proxy arp configuration.\n\
\t-a\tReload all configuration.\n\
\t-h\tDisplay this usage information.\n");
}

int
main(int argc, char *argv[])
{
  
  int dev = 0;
  int optch = 0;
  int l = 0;
  u_int8_t ipset_load=0, dhcpr_load=0, pxarp_load=0;
  char cur_path[PATH_MAX+1];
  char cfg_path[PATH_MAX+1];
  char cfg_file[PATH_MAX+1];
  
  cur_path[0]=cfg_path[0]=cfg_file[0] = 0; 

  while ((optch = getopt(argc, argv, "a1rph")) != EOF) {
    switch (optch) {
    case 'a':
      ipset_load = dhcpr_load = pxarp_load = 1;
      break;
    case 'i':
      ipset_load = 1;
      break;
    case 'r':
      dhcpr_load = 1;
      break;
    case 'p':
      pxarp_load = 1;
      break;
    case 'h':
    default:
      display_usage();
      exit(EXIT_SUCCESS);
    }
  }
  
  if( !get_cur_path(cur_path, PATH_MAX) ) {
    printf("unable find the current path.\n");
    exit(EXIT_FAILURE);
  }
  get_cfg_path(cur_path, cfg_path);
    
  dev = open("/dev/" DEV_NAME, O_RDWR);
  
  if (dev == -1) {
    printf("unable open /dev/%s device.\n", DEV_NAME);
    exit(EXIT_FAILURE);
  }

#define CREATE_PATH(X) {						\
    l = snprintf(cfg_file, PATH_MAX, "%s%s", cfg_path, CONFIG_PATH X);	\
    if( l<0 || l>PATH_MAX )						\
      goto done;							\
    cfg_file[l] =  0;							\
  }
    
  if( ipset_load ) {
    CREATE_PATH(IPSET_FILE);
    load_ipset(dev, cfg_file);
  }
  if( dhcpr_load ) {
    CREATE_PATH(DHCPR_FILE);
    load_dhcpr(dev, cfg_file);
  }
  if( pxarp_load ) {
    CREATE_PATH(PXARP_FILE);
    load_pxarp(dev, cfg_file);
  }

 done:
  close(dev);
  
  return (0);
}
