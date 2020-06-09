#!/usr/bin/env bash

set -eux
gcc \
  -L "${glibc_install}/lib" \
  -I "${glibc_install}/include" \
  -Wl,--rpath="${glibc_install}/lib" \
  -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2" \
  -std=c11 \
  -lrt \
  -mfentry \
  -I../../include \
  -I../../functional/mqueues \
  -D_POSIX_C_SOURCE=200809L \
  -D_XOPEN_SOURCE=700 \
  -g \
  -fno-omit-frame-pointer \
  -ggdb \
  -o test_glibc.out \
  -v \
  -g \
  -O0 \
  send_rev_1.c \
  -pthread \
;
ldd ./test_glibc.out
./test_glibc.out


