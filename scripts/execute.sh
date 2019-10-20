#!/bin/sh

PROJ_DIR="/home/bc/Lab/shrd/project/2019_belluminar"
INIT_DIR="/tmp/initrd"

## Update super_modern_service
cd super_modern_service
./build.sh
cp ./super_modern_service.elf64 $INIT_DIR/super_modern_service.elf64
cd $PROJ_DIR

## Update exploit
cd exploit
./build.sh
cp ./exploit $INIT_DIR/exploit
cd $PROJ_DIR

## Pack initrd
$PROJ_DIR/scripts/pack_initramfs.sh $INIT_DIR $PROJ_DIR/release/initramfs.cpio

## spawn
cd release
./start.sh