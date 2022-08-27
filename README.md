# mmalloc

## Compiling Stage 1

gcc -fno-stack-protector -O0 -g -o stage1 stage1.c

## Compiling Stage 2

gcc -fno-stack-protector -O0 -g -o stage2 stage2.c

## Compiling Stage 3

gcc -c -fPIC libmmalloc.c
gcc -shared -o libmmalloc.so libmmalloc.o
gcc -L/root/heap/malloc -g -fno-stack-protector -o sample sample.c -lmmalloc -Wl,-z,norelro
