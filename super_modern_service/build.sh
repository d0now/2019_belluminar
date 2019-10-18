#!/bin/sh

echo "[!] Building..."
gcc -o super_modern_service.elf \
    -I includes                 \
    sources/main.c              \
    sources/binder.c
echo "[+] Done"