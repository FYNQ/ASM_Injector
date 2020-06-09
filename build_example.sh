#!/usr/bin/env bash

set -eux
gcc \
  -L "${glibc_install}/lib" \
  -I "${glibc_install}/include" \
  -Wl,--rpath="${glibc_install}/lib" \
  -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2" \
  -std=c11 \
  -D_POSIX_C_SOURCE=200809L \
  -D_XOPEN_SOURCE=700 \
  -g \
  -ggdb \
  -o test_glibc \
  -v \
  -O3 \
  test_glibc.c \
  -pthread \
;
#ldd ./test_glibc.out
#./test_glibc.out

