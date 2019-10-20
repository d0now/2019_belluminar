#!/bin/sh

qemu-system-x86_64                 \
    -cpu kvm64,+smep,+smap         \
	-m 64                          \
	-kernel bzImage                \
	-initrd initramfs.cpio         \
	-nographic                     \
	-append "console=ttyS0 quiet"  \
	-monitor /dev/null
