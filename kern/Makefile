SRCS = zero.c ioctl.c str.c addr.c ipset.c pktbuf.c inito.c dinito.c dhcpr.c nt_udp.c cksum.c pxarp.c

KMOD = zeroip

CFLAGS += -D_KERNEL_
DEBUG_FLAGS += -g

install:
	cp zeroip.ko ../out/krn/
	cp zeroip.ko.debug ../out/krn/
rclean:
	@make clean
	rm -f *~
.include  <bsd.kmod.mk>
