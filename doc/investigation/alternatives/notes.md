# Use of GCC-Plugin

With help of a GCC C Plugin instrument function {entry, exits} by adding a call
to a locally created function at the beginning and the end of each function. This
function prints via syscall the function name and the current instruction pointer.
At this point only GCC builtin functions and ASM code can be used.

