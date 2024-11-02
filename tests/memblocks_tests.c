#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "../src/defs.h"
#include "../src/memblocks.c"
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h> /* sleep(), usleep() */

#define TEST(cond) assert(cond)
#define END_TEST   printf("Test %s succeeded\n", BOOST_CURRENT_FUNCTION)

void basictest_public_functionality() {
    constexpr size_t chunk_size = 2 * KB;
    constexpr auto   MAX_ALLOC_SIZE = chunk_size;

    struct memblock_allocator *allocator = new_memblock_allocator(chunk_size);
    struct block_data         *block;

    struct memchunk *chunk1 = allocator->cur_chunk;

    /* can't allocate contiguous memory of size bigger than chunk size */
    TEST(memblock_alloc(allocator, chunk_size + 1) == nullptr);

    /* use up all memory in pool */
    char *mem1 = memblock_alloc(allocator, MAX_ALLOC_SIZE);
    TEST(mem1 != nullptr);

    /* allocate new chunk */
    char *mem2 = memblock_alloc(allocator, MAX_ALLOC_SIZE);
    TEST(mem2 != nullptr);

    /* make sure its a different chunk */
    TEST(allocator->cur_chunk != chunk1);
    TEST(mem1 != mem2);

    /* chunks should be contained in a linked list */
    struct memchunk *chunk2 = allocator->cur_chunk;
    TEST(chunk2->entry.next == &chunk1->entry);

    memblock_dealloc(allocator, mem1);
    memblock_dealloc(allocator, mem2);

    struct bucket_node *first_node =
        *get_module_bucket(allocator, MAX_ALLOC_SIZE);
    TEST(get_memblock_startaddr(first_node->blocks[0]) == (mem *)mem1);

    TEST(get_memblock_startaddr(first_node->blocks[1]) == (mem *)mem2);

    /* make sure allocating the same size again re-uses allocated blocks,
     * implementation details make this reverse-order */
    TEST(memblock_alloc(allocator, MAX_ALLOC_SIZE) == mem2);
    TEST(memblock_alloc(allocator, MAX_ALLOC_SIZE) == mem1);

    destroy_memblock_allocator(allocator);

    END_TEST;
}

void intermediatetest_public_functionality() {
    constexpr auto             chunk_size = 1 * KB;
    constexpr auto             allocation_size = 32;
    constexpr auto             num_allocations = 33;
    struct memblock_allocator *allocator = new_memblock_allocator(chunk_size);
    void                      *allocated_mem[num_allocations];

    /* allocate one at a time */
    for ( int i = 0; i < num_allocations; i++ ) {
        allocated_mem[i] = memblock_alloc(allocator, allocation_size);
    }

    /* deallocate one at a time */
    for ( int i = 0; i < num_allocations; i++ ) {
        memblock_dealloc(allocator, allocated_mem[i]);
    }

    /* allocate and deallocate one at a time */
    for ( int i = 0; i < num_allocations; i++ ) {
        memblock_dealloc(allocator, memblock_alloc(allocator, allocation_size));
    }

    destroy_memblock_allocator(allocator);

    END_TEST;
}

void test_bucket_nodes() {
    constexpr auto             chunk_size = 0;
    struct memblock_allocator *allocator = new_memblock_allocator(chunk_size);
}

void *alloc_only_thread(void *arg) {
    struct memblock_allocator *allocator = arg;
    constexpr auto             num_elem_allocated = 20;
    constexpr auto             size_mem_allocated = 32 * B;

    pthread_t     this_thrd_id = pthread_self();
    unsigned char canary = (unsigned char)((uintptr_t)this_thrd_id % UCHAR_MAX);

    pthread_t **allocated_elems =
        (pthread_t **)malloc(num_elem_allocated * sizeof(*allocated_elems));

    for ( unsigned int i = 0; i < num_elem_allocated; i++ ) {
        allocated_elems[i] =
            (pthread_t *)memblock_alloc(allocator, size_mem_allocated);
        if ( allocated_elems[i] == nullptr ) {
            printf("can't allocate memory\n");
            exit(1);
        }
        /* zero-out unused memory */
        memset((char *)allocated_elems[i], canary, size_mem_allocated);

        *allocated_elems[i] = this_thrd_id;
    }

    /* sleep for 1 sec, hopefully all threads finish allocating and copying into
     * their memory by then */
    sleep(1);

    /* make sure no allocated memory was overwritten */
    for ( unsigned int i = 0; i < num_elem_allocated; i++ ) {
        TEST(*allocated_elems[i] == this_thrd_id);

        unsigned char canary_arr[size_mem_allocated];
        memset(canary_arr, canary, size_mem_allocated);

        memset((char *)allocated_elems[i], canary, sizeof(this_thrd_id));

        TEST(memcmp((const char *)allocated_elems[i], canary_arr,
                    size_mem_allocated) == 0);
    }

    for ( unsigned int i = 0; i < num_elem_allocated; i++ ) {
        memblock_dealloc(allocator, (void *)allocated_elems[i]);
    }

    free((void *)allocated_elems);
    return nullptr;
}

void test_multithreaded_alloc_only() {
    constexpr int              numthreads = 2000;
    pthread_t                  thrd_id[numthreads];
    struct memblock_allocator *allocator = new_memblock_allocator(1 * KB);
    for ( int i = 0; i < numthreads; i++ ) {
        if ( pthread_create(&thrd_id[i], nullptr, alloc_only_thread,
                            allocator) != 0 )
            printf("thread creation failed\n");
    }

    for ( int i = 0; i < numthreads; i++ ) {
        if ( pthread_join(thrd_id[i], nullptr) != 0 )
            printf("thread join failed\n");
    }
    END_TEST;
}

void test_multithreaded_alloc_reuse() {
    // TODO
}

int main() {
    basictest_public_functionality();
    intermediatetest_public_functionality();
    test_multithreaded_alloc_only();
}
