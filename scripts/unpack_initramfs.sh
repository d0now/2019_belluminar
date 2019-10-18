#!/bin/bash

if [ $1 ] && [ -f $1 ]; then
    CPIO_PATH=$(realpath $1);
else
    echo "Usage: $0 [cpio file path]";
    exit
fi

WORKDIR="/tmp/initrd"
ORIGDIR=`pwd`

if [ -d $WORKDIR ]; then
    echo "$WORKDIR found. deleting..."
    rm -rf $WORKDIR
else
    echo "NO"
fi

mkdir $WORKDIR
cd $WORKDIR

cat $CPIO_PATH | cpio -idmv 2>/dev/null

echo "Unpacked path $WORKDIR"
