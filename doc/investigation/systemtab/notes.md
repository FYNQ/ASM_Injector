
# systemtap

## Note

General information can be obtained for systemtap usage see [1]. During
asessment and error message occured which could be resolved withhelp of [2]


## Preparations

### Build glibc

To enable systemtab add --enable-systemtap

```
../configure --enable-dtrace --enable-systemtap --enable-cassert \
    --enable-debug CFLAGS="-O3 -g3 -ggdb"  \
    --prefix=/home/markus/work_ot/c_analysis/glibc_install \
    --with-dynamic-trace=lttng
```

### Show all probes

```
stap -L 'process("path_to_libs/*.so").provider("libc").mark("*")'
stap -L 'process("path_to_libs/*.so").provider("libpthread").mark("*")'
```

## Evaluation
### Check coverage

A superficial function coverage has been evaluated by checking the
libc:

1. check how many systemtab descriptors are in libc.so
2. check how many FUNC symbols are in libc.so

```
$ readelf -a path_to_lib/libc.so.6 | grep stap | wc -l
48
$ readelf -sW path_to_lib/libc.so.6 | awk '$4 == "FUNC"' | wc -l
7362
```

*Show existing systemtab probes*

```
stap -L 'process("path_to_libc/libc.so.6").provider("libc").mark("*")' | wc -l
32
```

### Test

The test program (test\_glibc) has been build and linked with our custom compiled glibc.

```
stap callgraph.stp 'process("path_to_test_program/test_glibc.out").function("*")' \
    -c 'path_to_test_program/test_glibc.out' 
    'process("path_to_libc/libc.so.6").provider("libc").mark("*")' \
    -DSTP_NO_BUILDID_CHECK

```
### Output

```
     0 test_glibc.out(6023):->_start
    13 test_glibc.out(6023): ->__libc_csu_init
    15 test_glibc.out(6023):  ->_init
    17 test_glibc.out(6023):  <-_init
    19 test_glibc.out(6023):  ->frame_dummy
    21 test_glibc.out(6023):   ->register_tm_clones
    23 test_glibc.out(6023):   <-register_tm_clones
    24 test_glibc.out(6023):  <-frame_dummy
    26 test_glibc.out(6023): <-__libc_csu_init
    29 test_glibc.out(6023): ->main
     0 test_glibc.out(6026):<-main
   304 test_glibc.out(6023):  ->__do_global_dtors_aux
   310 test_glibc.out(6023):   ->deregister_tm_clones
   314 test_glibc.out(6023):   <-deregister_tm_clones
   317 test_glibc.out(6023):  <-__do_global_dtors_aux
   319 test_glibc.out(6023):  ->_fini
    19 test_glibc.out(6026):->__do_global_dtors_aux
   322 test_glibc.out(6023):  <-_fini
     0 test_glibc.out(6026):->deregister_tm_clones
     3 test_glibc.out(6026):<-deregister_tm_clones
     0 test_glibc.out(6026):<-__do_global_dtors_aux
     1 test_glibc.out(6026):->_fini
     0 test_glibc.out(6026):<-_fini

```

## Conclusion

Based on the lack of probed functions systemtap does not seem to be the right candidate. The
lack of sufficient probes was also the reason to suspend runtime tests.

# Links

[1] https://sourceware.org/systemtap/wiki/glibcMarkers    
[2] http://manpages.ubuntu.com/manpages/bionic/man7/error::buildid.7stap.html    


