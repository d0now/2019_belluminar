#!/bin/sh

echo "[!] Building..."
gcc -o super_modern_service.elf64   \
    -I includes                     \
    -s                              \
    -U_FORTIFY_SOURCE               \
    -D_FORTIFY_SOURCE=0             \
    -z relro                        \
    -no-pie                         \
    -D DEBUG                        \
    sources/main.c                  \
    sources/binder.c                \
    sources/logger.c
echo "[+] Done"