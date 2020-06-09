pandoc -V geometry:margin=2cm \
      -V fontsize=12pt \
      -V papersize:a4paper \
      --number-sections \
      --filter pandoc-latex-fontsize \
      ./general.md \
      ./uftrace/notes.md \
      ./perf/notes.md \
      ./cyg_profile_func/notes.md \
      ./valgrind/notes.md \
      ./systemtab/notes.md \
      ./LD_AUDIT/notes.md \
      ./conclusion.md \
      ./alternatives/notes.md \
      -o tracer.pdf
