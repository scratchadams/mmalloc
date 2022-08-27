#include <stdio.h>
#include <stdlib.h>
#include "libmmalloc.h"


int main(int argc, char *argv[]) {
    void *test, *test2, *test3, *test4;
    void *functest;
    
    test = mmalloc(32);
    memset(test, 0x41, 32);
    print_top();
    print_chunks();

    test2 = mmalloc(32);
    memset(test2, 0x42, 32);
    print_top();
    
    test3 = mmalloc(32);
    memset(test3, 0xFF, 48);
    print_top();
    
    test4 = mmalloc(0xFFFFFFFFFFFFF2F8);
    //print_top();
    
    functest = mmalloc(64);
    strcpy(functest, "\x99\x32\xfc\xf7\xff\x7f");
    printf("address of functest: %p\n", functest);
    memset(functest, 0x41, 1);
    
    print_chunks();

    return 0;
}
