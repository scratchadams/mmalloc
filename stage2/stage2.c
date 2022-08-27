#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define NFASTBINS 8

#define ALIGN_SZ(x) ((x+7) >> 3) << 3
#define FASTBIN_IDX(x) ((x+7) >> 3) - 1
#define CHUNK_SZ sizeof(struct chunk_data)

struct chunk_data {
    size_t prev_size;
    size_t size;

    struct chunk_data *fd;
    struct chunk_data *bk;
};

typedef struct chunk_data *binptr;

binptr sortedbins = NULL;
binptr fastbins[NFASTBINS] = {NULL};

void *global_base = NULL;


/*
print_chunks is used to print out information about the allocated/free chunks for troubleshooting
and demonstration purposes
*/
void print_chunks() {
    struct chunk_data *current;

    for(int i=0; i<NFASTBINS;i++) {
        if(!fastbins[i]) {
            continue;
        }

        current = fastbins[i];
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

    current = sortedbins;
    if(!sortedbins) {
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


/*
req_space is used to obtain more space from the kernel by using the sbrk() syscall.
This function also populates the chunk header information which is stored prior to
the chunk in allocated memory
*/
struct chunk_data *req_space(size_t size) {
    struct chunk_data *chunk;
    chunk = sbrk(0);

    void *req = sbrk(size + CHUNK_SZ);
    assert((void*)chunk == req);
    
    if(req == (void*)-1) {
        return NULL;
    }

    chunk->size = size;
    chunk->fd = NULL;

    return chunk;
}

struct chunk_data *reuse_fastchunk(size_t size) {
    if(fastbins[size]) {
        struct chunk_data *current = fastbins[size];
        if(current->fd) {
            fastbins[size] = current->fd;
        } else {
            fastbins[size] = NULL;
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
    struct chunk_data *bin = NULL;

    if (size <= 0) {
        return NULL;
    }

    if(!global_base) {
        chunk = req_space(aligned_size);

        if(!chunk) {
            return NULL;
        }
        global_base = chunk;
    
    } else {
        if(fastbins[FASTBIN_IDX(aligned_size)]) {
            chunk = reuse_fastchunk(FASTBIN_IDX(aligned_size));

        } else if(sortedbins) {
            chunk = reuse_chunk(&sortedbins, aligned_size);
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

    if(sortedbins) {
        current = sortedbins;
        struct chunk_data *last;

        while(current) {
            last = current->bk;

            if((current->size >= chunk->size) && !(current->bk)) {
                chunk->bk = NULL;
                chunk->fd = current;
                current->bk = chunk;

                sortedbins = chunk;

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
        sortedbins = chunk;
        chunk->bk = NULL;
        chunk->fd = NULL;
    }
    
    return 0;
}

int fastbin_add(struct chunk_data *chunk) {

    if(fastbins[FASTBIN_IDX(chunk->size)]) {
        chunk->fd = fastbins[FASTBIN_IDX(chunk->size)];
        fastbins[FASTBIN_IDX(chunk->size)] = chunk;
    } else {
        fastbins[FASTBIN_IDX(chunk->size)] = chunk;
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

int main(int argc, char *argv[]) {
    void *test, *test2, *test3, *test4;
    void *functest;

    print_func *jmp_table[2] = {
        good_print,
        bad_print
    };

    /*test = mmalloc(1000);
    test2 = mmalloc(2000);
    test3 = mmalloc(3000);
    
    mfree(test);
    mfree(test2);
    mfree(test3);

    print_chunks();

    test = mmalloc(3000);
    print_chunks();
    */
    test = mmalloc(16);
    memset(test, 0x41, 16);

    test2 = mmalloc(16);
    test3 = mmalloc(16);

    mfree(test);
    mfree(test2);
    mfree(test3);

    print_chunks();
    
    strcpy(test3, "\x20\xe4\xff\xff\xff\x7f");
    //print_chunks();

    test4 = mmalloc(16);
    functest = mmalloc(16);
    printf("functest : %p\n", functest);
    strcpy(functest, "\xcf\x59\x55\x55\x55\x55");

    //print_chunks();
    jmp_table[0]();
   
    return 0;
}



