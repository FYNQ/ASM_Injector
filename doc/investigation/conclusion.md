
# Conclusion evaluation
## uftrace

userspace tracer without libc only. libc cannot be compiled with -mfentry (yes)
and -mnop-mcount (no). libc cannon compiled with -finstrument-functions

## perf

test with glibc compiled with -g -gdb and -fno-omit-frame-pointer

using perf arguments:
-g --call-graph=fp
-g --call-graph=dwarf

In both cases various function calls were missing. Still open a test with the
arguments -g --call-graph=lbr due to lack of a CPU with lbr technology.

# __cyg_profile_func_{enter,exit}

Not possible because glibc cannot compiled with -finstrument-functions flags


## valgrind

Seems to work as expected, though to execution times (approx 14 slower) ONLY
be usable for validation.

## systemtap

Not enough probes to cover all functions. To add probes the glibc code needs to modified.

## LD\_AUTID

Only usable for functions binding with libraries. Not usable to resolve
internal libc calls.

