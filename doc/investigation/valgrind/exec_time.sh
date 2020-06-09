
#!/bin/bash
start1=$(date +%s.%N)

ls -ltR on /usr

end1=$(date +%s.%N)
runtime1=$(python -c "print(${end1} - ${start1})")

start2=$(date +%s.%N)
valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes --trace-children=yes /usr/bin/ls -ltR on /usr

end2=$(date +%s.%N)
runtime2=$(python -c "print(${end2} - ${start2})")




echo "Runtime was without $runtime1"
echo "Runtime was with valgrind $runtime2"
