#!/bin/sh

echo "[!] Building... super_modern_service"
gcc -o super_modern_service.elf64   \
    -I includes                     \
    -U_FORTIFY_SOURCE               \
    -D_FORTIFY_SOURCE=0             \
    -z relro                        \
    -no-pie                         \
    -s                              \
    -D DEBUG                        \
    sources/main.c                  \
    sources/binder.c                \
    sources/logger.c
echo "[+] Done"