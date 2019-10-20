#!/bin/bash

echo "Enter the link for your exploit (max: 5MB)"
echo "It will be saved in /exploit"
echo -n "link : "
read EXP_LINK

if [ ! -d tmp ] ; then
    mkdir tmp;
fi

cd tmp

    RANDOM_SUFIX=$(mktemp -u XXXXXXXXXX)
    INITRD_NAME=initrd."$RANDOM_SUFIX"
    mkdir $INITRD_NAME
    cd $INITRD_NAME ; cat ../../initramfs.cpio | cpio -idmv 2>/dev/null ; cd ..

    if [ -n "EXP_LINK" ] ; then
        curl --max-filesize 5m $EXP_LINK -o $INITRD_NAME/exploit
        if [ $? -ne 0 ] ; then
            exit;
        fi
        cd $INITRD_NAME ; find . | cpio -H newc -ov -F ../$INITRD_NAME.img 2>/dev/null ; cd ..
        rm -dR $INITRD_NAME
    fi

cd ..

qemu-system-x86_64                 \
    -cpu kvm64,+smep,+smap         \
	-m 64                          \
	-kernel bzImage                \
	-initrd tmp/"$INITRD_NAME".img \
	-nographic                     \
	-append "console=ttyS0 quiet"  \
	-monitor /dev/null
