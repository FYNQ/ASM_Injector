--- 
pandoc-latex-fontsize: 
  - classes: [smallcontent] 
    size: small 
  - classes: [tinycontent] 
    size: tiny
  - classes: [largecontent, important] 
    size: huge 
--- 


# \_\_cyg\_profile\_{entry,exit} functions

## Note

This mechanism takes advantage of \_\_cyg_profile\_func\_{enter,exit} functions.
Programs need to compiled with -finstrument-functions flags to use the \_\_cyg\_profile\_func\_{enter,exit} functions.

## compile glibc with: -finstrument-functions

```
../configure CFLAGS="-O3 -finstrument-functions" \
        --prefix=/path_to_glibc/glibc_install
```

### Result 1

Configure failed with the following message:

```smallcontent
checking whether to use .ctors/.dtors header and trailer... configure: error: missing __attribute__ ((constructor)) support??
```

## compile glibc with: -finstrument-functions libc\_cv\_ctors\_header=yes

```smallcontent
../configure CFLAGS="-O3 -finstrument-functions" \
    --prefix=/path_to_glibc/glibc_install libc_cv_ctors_header=yes
```

### Result 2

```tinycontent
In file included from ../sysdeps/unix/sysv/linux/x86/elision-lock.c:22:
../sysdeps/unix/sysv/linux/x86/hle.h: In function ‘_xabort’:
../sysdeps/unix/sysv/linux/x86/hle.h:64:3: warning: asm operand 0 probably doesn’t match constraints
   asm volatile (".byte 0xc6,0xf8,%P0" :: "i" (status) : "memory");
   ^~~
../sysdeps/unix/sysv/linux/x86/hle.h:64:3: error: impossible constraint in ‘asm’
```

## add files to -finstrument-functions-exclude-file-list

```smallcontent
../configure CFLAGS="-O3 -finstrument-functions \
    -finstrument-functions-exclude-file-list=\
        sysdeps/unix/sysv/linux/x86/hle.h,include/alloc_buffer.h,
        sysdeps/generic/ldsodefs.h" \
        --prefix=/path_to_glibc/glibc_install libc_cv_ctors_header=yes
```

```tinycontent
gcc   -nostdlib -nostartfiles -r -o /home/markus/work_ot/c_analysis/glibc/build/elf/librtld.map.o -Wl,--defsym='__stack_chk_fail=0' -Wl,--defsym='__stack_chk_fail_local=0' \
	'-Wl,-(' /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a -lgcc '-Wl,-)' -Wl,-Map,/home/markus/work_ot/c_analysis/glibc/build/elf/librtld.mapT
/usr/bin/ld: /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a(dl-error.os): in function `__GI__dl_signal_exception':
dl-error.c:(.text+0xd0): multiple definition of `_dl_signal_exception'; /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os:(.text+0x244c0): first defined here
/usr/bin/ld: /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a(dl-error.os): in function `__GI__dl_signal_error':
dl-error.c:(.text+0x140): multiple definition of `_dl_signal_error'; /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os:(.text+0x24520): first defined here
/usr/bin/ld: /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a(dl-error.os): in function `__GI__dl_catch_exception':
dl-error.c:(.text+0x1c0): multiple definition of `_dl_catch_exception'; /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os:(.text+0x24760): first defined here
/usr/bin/ld: /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a(dl-error.os): in function `__GI__dl_catch_error':
dl-error.c:(.text+0x290): multiple definition of `_dl_catch_error'; /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os:(.text+0x24830): first defined here
/usr/bin/ld: /home/markus/work_ot/c_analysis/glibc/build/libc_pic.a(init-first.os):(.data+0x0): multiple definition of `__libc_multiple_libcs'; /home/markus/work_ot/c_analysis/glibc/build/elf/dl-allobjs.os:(.bss+0xe0): first defined here
collect2: error: ld returned 1 exit status
make[2]: *** [Makefile:447: /home/markus/work_ot/c_analysis/glibc/build/elf/librtld.map] Error 1
make[2]: Leaving directory '/home/markus/work_ot/c_analysis/glibc/elf'
make[1]: *** [Makefile:258: elf/subdir_lib] Error 2
make[1]: Leaving directory '/home/markus/work_ot/c_analysis/glibc'
make: *** [Makefile:9: all] Error 2
```

# Conclusion

At the moment compiling glibc with -finstrument-functions flags seems NOT to be possible. The libc-help@sourceware.org
mailing list was consulted without any satisfying answer to resolve this case.

