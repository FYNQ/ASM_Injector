# Introduction

This report covers the evaluation of available tools for tracing and
their suitability or re-usability at the technology level
to build a glibc tracer comparable to ftrace. Note that while there
are a number of tracers available for user-space applications there
is no such tracer for glibc it self. Thus the main goal of his evaluation
is to select the most promising set of technologies suitable to 
implement a glibc trace infrastructure. As this can be assumed to
be relevant for glibc developers as well we would strongly urge to 
push results back to the glibc community under a suitable license.
Feedback from the glibc developers would be highly instrumental to achieve
the necessary assurance in such a tooling.

The goal of the tool is to provide a call graph generator for glibc 
that allows to extract patch coverage as well as an estimate of the
unseen paths. Note that the overall complexity of glibc is significantly
lower than the Linux kernel (10k functions respectively 380k functions)
so the data side as well as the statistics is not so much a risk as
is the call graph generator it self. 

# General limitations 

Main potential issues currently identified:

- Execution time overhead 
- Behavioral change induced by modifications/injections (for FTrace in
  the kernel adequate assurance data since early 2.6 kernels is available
  to justify reliance on the CFGs - not so with a new tool)

# Setup

System setup for the evaluation - we do not expect this to 
be in any significant way specific for the selected target
for ease of reproducing results we would though suggest to
start with the identical setup:

- System: Debian stable - buster
- gcc version 8.3.0
- GLIBC 2.28-10

- Testfile: send\_rev\_1.c
- Origin: LTP - Linux Test Project
- Path: ltp/testcases/open\_posix\_testsuite/functional/mqueues

# Tested programs

Technologies selected for testing were derived from simply
searching literature and the internet as well as from some
previous experiences with kernel level tracers (KFT) and 
work on GDB extensions. While we are not claiming completeness here
we do think that the majority of available options was covered
and most likely any further option found would be utilizing
one of the underlying technologies found in the studied set.

- cyg\_profile\_func\_{entry,exit}
- etrace
- gprof
- LD\_AUDIT
- perf
- systemtav
- uftrace
- valgrind

One open candidate at this point is 

- GDB based tracer (gdb tracepoints)

Candidates dropped after a first high-level review include

- LTTng
- LD\_PRELOAD libraries 
