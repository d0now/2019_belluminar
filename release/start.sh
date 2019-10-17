#!/bin/sh

qemu-system-x86_64 \
	-m 64 \
	-kernel bzImage \
	-initrd initramfs.cpio \
	-nographic \
	-append "console=ttyS0 quiet" \
	-monitor /dev/null
