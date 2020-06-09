# perf

## Preparations

glibc needs to be compiled according the requirements of perf. Three options for
call graph generation are implemented: dwarf, fp and lbr. lbr is a technology
only available in new intel 

## Use dwarf option

glibc needs to compiled with dwarf debug information. Configure glib with the following flags:

```
 CFLAGS "-g -ggdb"
```

Record data with perf

```
perf record -g --call-graph=dwarf \
    --library-path /path_to_glibc/glibc_install ./test_glibc.out
```
### Result dwarf option

Several functions where missing: e.g. malloc, calloc and more

## Use fp option

Compile glibc with 

```
CFLAGS="-O3 -fno-omit-frame-pointer -g -ggdb"
```

Record data with perf:

```
perf record -g --call-graph=fp  ./test_glibc.out
```
### Result fp option

Several functions where missing: e.g getpid, mq\_open and more

Explanation from [1]

You can specify some of call stack sampling method in --call-graph option (dwarf/lbr/fp), and they may have some limitations. Sometimes methods (especially fp) may fail to extract parts of call stack. -fno-omit-frame-pointer option may help, but when it is used in your executable but not in some library with callback, then call stack will be extracted partially. Some very long call chains may be not extracted too by some methods. Or perf report may fail to handle some cases.

## Conclusion

Perf does not seem capture all functions as we supposed. Using lbr flag is still
open.


[1] https://stackoverflow.com/questions/59307540/profiling-my-program-with-linux-perf-and-different-call-graph-modes-gives-differ
[2] http://sorami-chi.hateblo.jp/entry/2017/12/17/230000
