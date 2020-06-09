# Valgrind

## Install

First test with version part of debian repositories.

```
apt-get install valgrind
```

## Using valgrind

```
valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes \
         --trace-children=yes ./mqueues_send_rev_1.run-test
```

Extract information of logfile with held of graf2dot python script (available in pip3 repos)

```
gprof2dot -n0 -e0 ./callgrind.out.32317 -f callgrind > out\_32317.dot
```

## Runtime behaviour

In a stackoverflow thread [1] execution time where discussed and the following
section was cited:

```
(wikipedia) Valgrind is in essence a virtual machine using just-in-time (JIT)
compilation techniques, including dynamic recompilation. Nothing from the
original program ever gets run directly on the host processor. Instead,
Valgrind first translates the program into a temporary, simpler form called
Intermediate Representation (IR), which is a processor-neutral, SSA-based
form. After the conversion, a tool (see below) is free to do whatever
transformations it would like on the IR, before Valgrind translates the
IR back into machine code and lets the host processor run it.
```

### Simple test case

Test using:

```
ls -ltR /usr

Runtime was without 4.46205687523
Runtime was with valgrind 62.5232889652
```

## Conclusion

The simple test was executed 14 Times slower and is a result of this high number
not usable for our intentions.

## Links

[1] https://stackoverflow.com/questions/48573177/minimum-callgrind-command-for-callgraph-generation-and-profiling

