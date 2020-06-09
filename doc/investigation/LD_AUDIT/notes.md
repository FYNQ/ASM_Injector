# Notes LD\_AUDIT

from [1] description:

   The GNU dynamic linker (run-time linker) provides an auditing API
   that allows an application to be notified when various dynamic
   linking events occur.  This API is very similar to the auditing
   interface provided by the Solaris run-time linker.  The necessary
   constants and prototypes are defined by including <link.h>.

   To use this interface, the programmer creates a shared library that
   implements a standard set of function names.  Not all of the
   functions need to be implemented: in most cases, if the programmer is
   not interested in a particular class of auditing event, then no
   implementation needs to be provided for the corresponding auditing
   function.

   To employ the auditing interface, the environment variable LD\_AUDIT
   must be defined to contain a colon-separated list of shared
   libraries, each of which can implement (parts of) the auditing API.
   When an auditable event occurs, the corresponding function is invoked
   in each library, in the order that the libraries are listed.


la\_symbind\*()

   The dynamic linker invokes one of these functions when a symbol
   binding occurs between two shared objects that have been marked for
   auditing notification by la\_objopen(). The la\_symbind32() function
   is employed on 32-bit platforms; the la\_symbind64() function is
   employed on 64-bit platforms.


Basic implementation was done here [2] and here [3]. As I understand
la\_symbind\*() is invoked only between binding of symbols. Calls in the shared
lib won't invoke the la\_symbind\*() function.


[1] http://man7.org/linux/man-pages/man7/rtld-audit.7.html    
[2] https://github.com/je-nunez/a\_gnu\_libc\_interceptor\_via\_rtld\_audit    
[3] https://github.com/sos22/elf-audit   
