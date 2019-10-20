#!/bin/sh

if [ ! $1 ]; then
    echo "Usage: $0 [flag]";
    exit;
fi

cp release/* server/
scripts/unpack_initramfs.sh server/initramfs.cpio /tmp/initrd_srv
echo $1 | base64 > /tmp/initrd_srv/flag
gzip /tmp/initrd_srv/flag
mv /tmp/initrd_srv/flag.gz /tmp/initrd_srv/flag
scripts/pack_initramfs.sh /tmp/initrd_srv server/initramfs.cpio