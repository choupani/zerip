#ifndef _COM_IOCTL_H
#define _COM_IOCTL_H

/*
 * ioctl parameter structure
 */

struct ioctlbuffer {
  u_int32_t size;
  u_int32_t entries;
  void *buffer;
};

/*
 * ioctl operations
 */


#define IOCSTART          _IOWR('Z',  1,    struct ioctlbuffer)
#define IOCSTOP           _IOWR('Z',  2,    struct ioctlbuffer)
#define IOCSETIPSET       _IOWR('Z',  10,   struct ioctlbuffer)
#define IOCCLRIPSET       _IOWR('Z',  11,   struct ioctlbuffer)
#define IOCSETDHCPR       _IOWR('Z',  20,   struct ioctlbuffer)
#define IOCCLRDHCPR       _IOWR('Z',  21,   struct ioctlbuffer)
#define IOCSETPXARP       _IOWR('Z',  30,   struct ioctlbuffer)
#define IOCCLRPXARP       _IOWR('Z',  31,   struct ioctlbuffer)


/*
 * ioctl errors
 */

enum ioctl_error {
  NO_ERROR=0,
  ERROR_INVALID=20,
  ERROR_MALLOC
};



#endif
