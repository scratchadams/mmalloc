#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

struct chunk_data {
    size_t size;
    struct chunk_data *next;
    int free;
    int magic;
};

#define CHUNK_SZ sizeof(struct chunk_data)

void *global_base = NULL;


/*
find_free_chunk enumerates through the link list of previously allocated chunks and evaluates
the chunk address, the free flag, and the size of the current chunk to determine whether or not
that chunk can be re-used during the allocation process
*/
struct chunk_data *find_free_chunk(struct chunk_data **last, size_t size) {
    struct chunk_data *current = global_base;
        
    while(current && !(current->free && current->size >= size)) {
        printf("current: %p next: %p\n", current, current->next);
        *last = current;
        current = current->next;
    }

    return current;
}

/*
print_chunks is used to print out information about the allocated/free chunks for troubleshooting
and demonstration purposes
*/
void print_chunks() {
    struct chunk_data *current = global_base;

    if(!global_base) {
        printf("No Chunks\n");
        return;
    }

    while(current) {
        printf("--------------------------\n");
        printf("chunk addr: %p\n", current);
        printf("chunk size: %ld\n", current->size);
        printf("next chunk: %p\n", current->next);
        printf("chunk free: %d\n", current->free);
        printf("magic number: %x\n", current->magic);
        printf("--------------------------\n\n\n");

        current = current->next;
    }

    return;
}


/*
req_space is used to obtain more space from the kernel by using the sbrk() syscall.
This function also populates the chunk header information which is stored prior to
the chunk in allocated memory
*/
struct chunk_data *req_space(struct chunk_data *last, size_t size) {
    struct chunk_data *chunk;
    chunk = sbrk(0);

    void *req = sbrk(size + CHUNK_SZ);
    assert((void*)chunk == req);
    
    if(req == (void*)-1) {
        return NULL;
    }

    if(last) {
        last->next = chunk;
    }

    chunk->size = size;
    chunk->next = NULL;
    chunk->free = 0;
    chunk->magic = 0x12345678;

    return chunk;
}

/*
mmalloc is our main memory allocation function. It evaluates the value of global_base
in order to determine if the process has already allocated memory, as well as calling
find_free_chunk to search through previously allocated chunks to determine if a chunk can be 
re-used or if more memory needs to be requested from the kernel.

mmalloc ultimately returns (chunk+1) as the address returned by re_space and find_free_chunk
includes the header information, so the +1 provides an address directly after that header which
is writeable memory
*/
void *mmalloc(size_t size) {
    struct chunk_data *chunk;

    if (size <= 0) {
        return NULL;
    }

    if(!global_base) {
        chunk = req_space(NULL, size);

        if(!chunk) {
            return NULL;
        }
        global_base = chunk;
    
    } else {
        struct chunk_data *last = global_base;
        chunk = find_free_chunk(&last, size);
        printf("chunk addr: %p\nglobal_base addr: %p\n\n", chunk, global_base);

        if(!chunk) {
            chunk = req_space(last, size);
            
            if(!chunk) {
                return NULL;
            }
        } else {
            chunk->free = 0;
            chunk->magic = 0x87654321;
        }
    }

    return(chunk+1);
}

struct chunk_data *get_chunk_ptr(struct chunk_data *ptr) {
    if(!ptr) {
        return NULL;
    }

    return (ptr-1);
}

int mfree(struct chunk_data *chunk) {
    if(!chunk) {
        return -1;
    }

    struct chunk_data *ptr = get_chunk_ptr(chunk);

    ptr->free = 1;
    ptr->magic = 0xFFFFFFFF;

    return 0;
}

int good_print() {
    printf("This should be printed!\n");

    return 0;
}

int bad_print() {
    printf("This should NOT be printed!\n");

    return 0;
}

typedef int print_func();

int main(int argc, char *argv[]) {
    void *test, *test2, *test3;
    void *functest;

    print_func *jmp_table[2] = {
        good_print,
        bad_print
    };

    test = mmalloc(24);
    test2 = mmalloc(24);
    test3 = mmalloc(32);
    
    //printf("test: %p\ntest2: %p\ntest3: %p\n", test, test2, test3);
    printf("chunk header size: %ld\n", sizeof(struct chunk_data));

    memset(test, 0x41, 16);
    memset(test2, 0x42, 24);
    memset(test3, 0x43, 32);

    print_chunks();

    mfree(test2);
    print_chunks();

    test2 = mmalloc(24);
    print_chunks();

    memset(test2, 0x44, 32);
    //memset((test2+32), 0x4142434546474849, 8);
    strcpy((test2+32), "\x28\xe4\xff\xff\xff\x7f");
    //strcpy((test2+32), (char *)jmp_table);
    //print_chunks();
   
    functest = mmalloc(24);
    //memset(functest, 0x45, 24);
    strcpy(functest, "\x60\x55\x55\x55\x55\x55");

    jmp_table[0]();

    return 0;
}



