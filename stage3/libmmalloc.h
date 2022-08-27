#include <string.h>
#include <stddef.h>

#define NFASTBINS 8
#define TOP_SZ 32000

#define ALIGN_SZ(x) ((x+7) >> 3) << 3
#define FASTBIN_IDX(x) ((x+7) >> 3) - 1

#define CHUNK_SZ sizeof(struct chunk_data)
#define ALLOC_SZ sizeof(size_t) * 2

struct chunk_data {
    size_t prev_size;
    size_t size;

    struct chunk_data *fd;
    struct chunk_data *bk;
};

typedef struct chunk_data *binptr;
typedef struct chunk_data *chunkptr;

struct mmalloc_state {
    binptr sortedbins;
    binptr fastbins[NFASTBINS];

    chunkptr top;

    struct mmalloc_state *next;
};


extern int mfree(struct chunk_data *chunk);
extern void *mmalloc(size_t size);
extern void print_top();
extern void print_chunks();

