# PoC for glibc tracer for glibc

## Compile glibc

../configure CC='/usr/bin/gcc -g -O2 -Wno-error=stringop-truncation -Wno-error=maybe-uninitialized -Wno-error=uninitialized -fplugin=/path/to/inject.so -fplugin-arg-inject-rules=/path/to/rules.yml' --prefix=/path/to/installed/glibc

make && make install

## Notes

- Works only with optimization level O2 or O3
- flags needed:
  -Wno-error=maybe-uninitialized
  -Wno-error=uninitialized
  -Wno-error=stringop-truncation

## Use with LD_PRELOAD_PATH

Export glibc path:

export glibc_install=/path/to/installed/glibc

Compile:

build_test.sh

Execute:

./test_glibc > log.txt

## Postprocessor for indentatio

python3 indent.py log.txt > log_formated.txt

