#!/bin/sh

echo "[!] Building..."
gcc -o super_modern_service.elf64   \
    -I includes                     \
    -static                         \
    -s                              \
    sources/main.c                  \
    sources/binder.c
echo "[+] Done"