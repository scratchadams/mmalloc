#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "libmmalloc.h"

struct mmalloc_state ma = {NULL, {NULL}, NULL, NULL};
struct mmalloc_state *main_arena = &ma;


void print_top() {
    printf("chunk size: %ld\n", CHUNK_SZ);
    printf("top: %p\n", main_arena->top);
    printf("top size: %ld\n", main_arena->top->size);
    printf("top fd: %p\n", main_arena->top->fd);

    return;
}
    

/*
print_chunks is used to print out information about the allocated/free chunks for troubleshooting
and demonstration purposes
*/
void print_chunks() {
    struct chunk_data *current;

    for(int i=0; i<NFASTBINS;i++) {
        if(!main_arena->fastbins[i]) {
            continue;
        }

        current = main_arena->fastbins[i];
        printf("fastbin size %d\n", (i+1)<<3 );

        while(current) {
            printf("--------------------------\n");
            printf("chunk addr: %p\n", current);
            printf("chunk size: %ld\n", current->size);
            printf("fd chunk: %p\n", current->fd);
            printf("bk chunk: %p\n", current->bk);
            printf("--------------------------\n\n\n");

            current = current->fd;
        }
    }

    current = main_arena->sortedbins;
    if(!main_arena->sortedbins) {
        printf("sorted bin empty\n");
    } else {
        printf("sorted bin\n");

        while(current) {
            printf("--------------------------\n");
            printf("chunk addr: %p\n", current);
            printf("chunk size: %ld\n", current->size);
            printf("fd chunk: %p\n", current->fd);
            printf("bk chunk: %p\n", current->bk);
            printf("--------------------------\n\n\n");

            current = current->fd;
        }
    }

    return;
}

struct chunk_data *create_topchunk(size_t size) {
    struct chunk_data *top;
    top = sbrk(0);
    
    void *req = sbrk(size);
    assert((void *)top == req);
    
    if(req == (void *)-1) {
        return NULL;
    }
    
    top->size = (size - ALLOC_SZ);
    top->fd = NULL;
    
    return top;
}

struct chunk_data *split_topchunk(size_t size) {
    struct chunk_data *chunk;
    size_t top_sz = main_arena->top->size;
    
    chunk = main_arena->top;
    chunk->size = size;
    
    printf("the size: %ld\n", size);
    printf("chunk address: %p\n", chunk);
    printf("new top: %p\n", (void *)chunk + (size + ALLOC_SZ));
    
    main_arena->top = (void *)chunk + (size + ALLOC_SZ);
    main_arena->top->size = top_sz - (size + ALLOC_SZ);
    main_arena->top->fd = NULL;
    
    printf("confirmation\n");
    
    return chunk;
}

int extend_heap(size_t size) {
    //add functionality to add space to top chunk
    printf("extending heap\n");
    printf("heap size: %ld\n", main_arena->top->size);
    void *top = sbrk(0);
    void *req = sbrk((size + ALLOC_SZ));
    
    assert(top == req);
    
    if(req == (void *)-1) {
        return -1;
    }
    
    main_arena->top->size += (size + ALLOC_SZ);
    printf("heap size: %ld\n", main_arena->top->size);
    
    return 0;
}    

/*
req_space is used to obtain more space from the kernel by using the sbrk() syscall.
This function also populates the chunk header information which is stored prior to
the chunk in allocated memory
*/
struct chunk_data *req_space(size_t size) {
    struct chunk_data *chunk = NULL;
    
    if(!main_arena->top) {
        main_arena->top = create_topchunk(TOP_SZ);
    }
    
    if(main_arena->top->size > (size + CHUNK_SZ)) {
        chunk = split_topchunk(size);
    } else {
        extend_heap(size);
        chunk = split_topchunk(size);
    }
    
    return chunk;
}

struct chunk_data *reuse_fastchunk(size_t size) {
    if(main_arena->fastbins[size]) {
        struct chunk_data *current = main_arena->fastbins[size];
        if(current->fd) {
            main_arena->fastbins[size] = current->fd;
        } else {
            main_arena->fastbins[size] = NULL;
        }
        
        return current;
    }

    return NULL;
}

struct chunk_data *reuse_chunk(binptr *bin, size_t size) {
    struct chunk_data *current = *bin;

    if(bin) {
        while(current && !(current->size >= size)) {
            current = current->fd;
        }

        if(current) {
            struct chunk_data *last = current->bk;
            
            if(last && current->fd) {
                last->fd = current->fd;
                current->fd->bk = last;
            } else if(!(last) && current->fd) {
                *bin = current->fd;
                current->bk = NULL;
            } else if(current && !(current->fd && current->bk)) {
                last->fd = NULL;
            } else {
                *bin = NULL;
            }
        }
    }

    return current;
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
    struct chunk_data *chunk = NULL;
    size_t aligned_size = ALIGN_SZ(size);
    size_t index = FASTBIN_IDX(aligned_size);
    
    struct chunk_data *bin = NULL;

    if (size <= 0) {
        return NULL;
    }
    
    if(aligned_size < CHUNK_SZ) {
        aligned_size = CHUNK_SZ;
    }

    if(!main_arena->top) {      
        chunk = req_space(aligned_size);

        if(!chunk) {
            return NULL;
        }
    
    } else {
        printf("fastbin index: %ld\n", FASTBIN_IDX(aligned_size));
        
        if((index <= 8) && main_arena->fastbins[index]) {
            chunk = reuse_fastchunk(FASTBIN_IDX(aligned_size));

        } else if(main_arena->sortedbins) {
            chunk = reuse_chunk(&main_arena->sortedbins, aligned_size);
        }

        if(!chunk) {
            chunk = req_space(aligned_size);
            
            if(!chunk) {
                return NULL;
            }
        }
    }

    return &chunk->fd;
}

struct chunk_data *get_chunk_ptr(void *ptr) {
    if(!ptr) {
        return NULL;
     }

    return (ptr-(sizeof(size_t)*2));
}

int sortbin_add(struct chunk_data *chunk) {
    struct chunk_data *current;

    if(main_arena->sortedbins) {
        current = main_arena->sortedbins;
        struct chunk_data *last;

        while(current) {
            last = current->bk;

            if((current->size >= chunk->size) && !(current->bk)) {
                chunk->bk = NULL;
                chunk->fd = current;
                current->bk = chunk;

                main_arena->sortedbins = chunk;

                return 0;
            } else if((current->size >= chunk->size) && current->bk) {

                chunk->bk = last;
                chunk->fd = current;
                current->bk = chunk;
                last->fd = chunk;

                return 0;
            }
           
            last = current;
            current = current->fd;
        }

        last->fd = chunk;
        chunk->bk = last;
        chunk->fd = NULL;
    } else {
        main_arena->sortedbins = chunk;
        chunk->bk = NULL;
        chunk->fd = NULL;
    }
    
    return 0;
}

int fastbin_add(struct chunk_data *chunk) {

    if(main_arena->fastbins[FASTBIN_IDX(chunk->size)]) {
        chunk->fd = main_arena->fastbins[FASTBIN_IDX(chunk->size)];
        main_arena->fastbins[FASTBIN_IDX(chunk->size)] = chunk;
    } else {
        main_arena->fastbins[FASTBIN_IDX(chunk->size)] = chunk;
        chunk->fd = NULL;
    }

    return 0;
}
 
int mfree(struct chunk_data *chunk) {
    int added = 0;

    if(!chunk) {
        return -1;
    }

    struct chunk_data *ptr = get_chunk_ptr(chunk);

    if(ptr->size <= 64) {
        fastbin_add(ptr);
    } else {
        sortbin_add(ptr);
    }

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
/*
int main(int argc, char *argv[]) {
    void *test, *test2, *test3, *test4;
    void *functest;

    print_func *jmp_table[2] = {
        good_print,
        bad_print
    };

    
    test = mmalloc(32);
    memset(test, 0x41, 32);
    print_top();

    test2 = mmalloc(32);
    memset(test2, 0x42, 32);
    print_top();
    
    test3 = mmalloc(32);
    memset(test3, 0xFF, 48);
    print_top();

    return 0;
}
*/


