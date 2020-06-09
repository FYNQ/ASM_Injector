# uftrace

## Preparations

Study information from github web page [1]:

For recording, the executable needs to be compiled with the -pg (or
-finstrument-functions) option which generates profiling code (calling
mcount or \_\_cyg\_profile\_func\_enter/exit) for each function.

But:

Note that, there's an experimental support for dynamic tracing on x86\_64 and
AArch64(ARM64) which doesn't require such (re-)compilations. Also recent
compilers have some options to help uftrace to reduce tracing overhead with
similar way (although it still needs recompilation of your program). Please
see dynamic tracing section for more details.

So clone repo from github [1]

```
$ git clone https://github.com/namhyung/uftrace.git
$ git checkout remotes/origin/review/dynamic-x86-call-v1
$ ./configure --prefix=/usr/local/bin
$ make
$ make install
```

Missing dependencies installed with apt-get from debian apt repo

```
...         prefix: /usr/local/bin
...         libelf: [ OFF ] - more flexible ELF data handling
...          libdw: [ OFF ] - DWARF debug info support
...      libpython: [ on  ] - python scripting support
...      libluajit: [ OFF ] - luajit scripting support
...    libncursesw: [ OFF ] - TUI support
...   cxa_demangle: [ on  ] - full demangler support with libstdc++
...     perf_event: [ on  ] - perf (PMU) event support
...       schedule: [ on  ] - scheduler event support
...       capstone: [ OFF ] - full dynamic tracing support

```

Install dependencies

```
apt-get install libelf-dev libdwarf-dev libcapstone3 libdw-dev
```

```
...         prefix: /usr/local/bin
...         libelf: [ on  ] - more flexible ELF data handling
...          libdw: [ on  ] - DWARF debug info support
...      libpython: [ on  ] - python scripting support
...      libluajit: [ OFF ] - luajit scripting support
...    libncursesw: [ OFF ] - TUI support
...   cxa_demangle: [ on  ] - full demangler support with libstdc++
...     perf_event: [ on  ] - perf (PMU) event support
...       schedule: [ on  ] - scheduler event support
...       capstone: [ on  ] - full dynamic tracing support

```

## Test uftrace

```
$ /usr/local/bin/uftrace -P record mqueues_send_rev_1.run-test > log.txt
$ more log.txt
Enter into child process...
Prepare to receive [1] messages...
process 4697 receive message 'msg test 1' from process 4696
Prepare to receive [2] messages...
process 4697 receive message 'msg test 2' from process 4696
Prepare to receive [3] messages...
process 4697 receive message 'msg test 3' from process 4696
[1] s_msg_ptr is 'msg test 1'
Prepare to send message...
Process 4699 send message 'msg test 1' to process 0
[2] s_msg_ptr is 'msg test 2'
Prepare to send message...
Process 4699 send message 'msg test 2' to process 0
[3] s_msg_ptr is 'msg test 3'
Prepare to send message...
Process 4699 send message 'msg test 3' to process 0
# DURATION     TID     FUNCTION
   1.208 us [  4697] | memset();
   6.768 us [  4697] | mq_open();
 118.373 us [  4697] | fork();
  16.811 us [  4697] | puts();
   1.285 us [  4697] | mq_getattr();
   4.415 us [  4697] | printf();
            [  4697] | mq_receive() {
            [  4697] |   /* linux:sched-out */
            [  4699] | } /* fork */
   1.439 us [  4699] | mq_getattr();
  10.887 us [  4699] | printf();
   0.789 us [  4699] | puts();
   3.219 us [  4699] | mq_send();
   0.701 us [  4699] | getpid();
   0.469 us [  4699] | printf();
   0.199 us [  4699] | printf();
   0.113 us [  4699] | puts();
   0.734 us [  4699] | mq_send();
   0.291 us [  4699] | getpid();
   0.256 us [  4699] | printf();
   0.148 us [  4699] | printf();
   0.076 us [  4699] | puts();
   0.713 us [  4699] | mq_send();
   0.282 us [  4699] | getpid();
   0.188 us [  4699] | printf();
   1.095 us [  4699] | wait();
   0.901 us [  4699] | mq_close();
   2.086 us [  4699] | mq_unlink();
 153.461 us [  4697] |   /* linux:sched-in */
 158.236 us [  4697] | } /* mq_receive */
   1.827 us [  4697] | getppid();
   0.680 us [  4697] | getpid();
   1.191 us [  4697] | printf();
   0.211 us [  4697] | printf();
   1.104 us [  4697] | mq_receive();
   0.299 us [  4697] | getppid();
   0.281 us [  4697] | getpid();
   0.271 us [  4697] | printf();
   0.126 us [  4697] | printf();
   0.742 us [  4697] | mq_receive();
   0.286 us [  4697] | getppid();
   0.279 us [  4697] | getpid();
   0.196 us [  4697] | printf();
            [  4697] | exit() {
            [  4697] |   /* linux:task-exit */

uftrace stopped tracing with remaining functions
task: 4697
[0] exit
```

## Conclusion

Looks better but there should be some nesting, we only see entry functions
into glibc

uftrace needs -mfentry and -mnop-mcount for dynamic tracing but glibc cannot
be linked with mnop_mcount because of default glibc PIE flag

## Links

[1]  https://github.com/namhyung/uftrace
