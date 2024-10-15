#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "../src/freelist.c"
#include "../src/freelist.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST(cond) assert((cond))

#define ASSERT_LIST_STATE_VALID(fl_ptr)                                        \
    TEST(0 <= (fl_ptr)->head && (fl_ptr)->head <= (fl_ptr)->array_len)

#define END_TEST printf("Test %s succeeded\n", BOOST_CURRENT_FUNCTION)

void freelist_fill_and_remove() {           // NOLINT(*cognitive-complexity)
    constexpr int   listlen = 5;
    struct freelist list, *listptr = &list; // NOLINT
    int             intlist[listlen];
    int             elem_list[] = {1, 2, 3, 4, 5, 6};

    freelist_init(&list, intlist, listlen);

    TEST(list.top == 0 && list.head == listlen);
    TEST(freelist_insert(listptr, &elem_list[4]) == &intlist[0]);
    TEST(list.top == 1 && list.head == listlen);
    TEST(freelist_insert(listptr, &elem_list[3]) == &intlist[1]);
    TEST(list.top == 2 && list.head == listlen);
    TEST(freelist_insert(listptr, &elem_list[2]) == &intlist[2]);
    TEST(list.top == 3 && list.head == listlen);
    TEST(freelist_insert(listptr, &elem_list[1]) == &intlist[3]);
    TEST(list.top == 4 && list.head == listlen);
    TEST(freelist_insert(listptr, &elem_list[0]) == &intlist[4]);
    TEST(list.top == 5 && list.head == listlen);

    // NOLINTBEGIN
    TEST(intlist[0] == elem_list[4]);
    TEST(intlist[1] == elem_list[3]);
    TEST(intlist[2] == elem_list[2]);
    TEST(intlist[3] == elem_list[1]);
    TEST(intlist[4] == elem_list[0]);
    // NOLINTEND

    TEST(freelist_insert(listptr, &elem_list[5]) == nullptr);
    TEST(list.top >= listlen && list.head == listlen);

    // NOLINTBEGIN
    TEST(intlist[0] == elem_list[4]);
    TEST(intlist[1] == elem_list[3]);
    TEST(intlist[2] == elem_list[2]);
    TEST(intlist[3] == elem_list[1]);
    TEST(intlist[4] == elem_list[0]);
    // NOLINTEND

    freelist_rm(listptr, &intlist[2]);
    TEST(list.head == 2 && *get_next_empty(listptr, list.head) == listlen);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(((struct freelist_data *)&intlist[2])->next_index == listlen);
    TEST(intlist[3] == 2);
    TEST(intlist[4] == 1);
    // NOLINTEND

    freelist_rm(listptr, &intlist[3]);
    TEST(list.head == 3 && *get_next_empty(listptr, listptr->head) == 2);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(((struct freelist_data *)&intlist[2])->next_index == listlen);
    TEST(((struct freelist_data *)&intlist[3])->next_index == 2);
    TEST(intlist[4] == 1);
    // NOLINTEND

    END_TEST;
}

void freelist_fill_nonfull_and_remove() {   // NOLINT(*cognitive-complexity)
    const int       listlen = 5;
    struct freelist list, *listptr = &list; // NOLINT
    int             intlist[listlen];
    int             elem_list[] = {1, 2, 3, 4, 5};

    freelist_init(&list, intlist, listlen);

    TEST(list.top == 0 && list.head == listlen);
    freelist_insert(listptr, &elem_list[4]); // 5
    TEST(list.top == 1 && list.head == listlen);
    freelist_insert(listptr, &elem_list[3]); // 4
    TEST(list.top == 2 && list.head == listlen);
    freelist_insert(listptr, &elem_list[2]); // 3
    TEST(list.top == 3 && list.head == listlen);

    freelist_rm(listptr, &intlist[1]); /* rm value 4 */
    TEST(list.top == 3 && list.head == 1);
    TEST(*get_next_empty(listptr, list.head) == listlen);

    freelist_rm(listptr, &intlist[0]); /* rm value 5 */
    TEST(list.top == 3 && list.head == 0);
    TEST(*get_next_empty(listptr, list.head) == 1);

    freelist_insert(listptr,
                    &elem_list[3]); /* add 4 at position 0 (previously 5) */
    TEST(list.top == 4 && list.head == 0);
    TEST(*get_next_empty(listptr, list.head) == 1);
    TEST(intlist[3] == elem_list[3]); // NOLINT

    freelist_insert(listptr,
                    &elem_list[4]);   /* add 5 at position 1 (previously 4) */
    TEST(list.top == 5 && list.head == 0);
    TEST(intlist[4] == elem_list[4]); // NOLINT

    freelist_insert(listptr, &elem_list[1]);
    TEST(list.top >= 5 && list.head == 1);
    TEST(intlist[0] == elem_list[1]); // NOLINT

    freelist_insert(listptr, &elem_list[0]);
    TEST(list.top >= 5 && list.head == listlen);
    TEST(intlist[1] == elem_list[0]); // NOLINT

    END_TEST;
}

void *freelist_thread(void *arg) {
    usleep(1);
    struct freelist *list = arg;
    constexpr int    num_elem_allocated = 2;
    pthread_t        this_thrd_id = pthread_self();
    void            *allocated_elems[num_elem_allocated];

    for ( int i = 0; i < num_elem_allocated; i++ ) {
        do {
            allocated_elems[i] = freelist_insert(list, (void *)&this_thrd_id);
        } while ( allocated_elems[i] == nullptr );
    }

    for ( int i = 0; i < num_elem_allocated; i++ ) {
        TEST(*(pthread_t *)allocated_elems[i] == this_thrd_id);
    }

    for ( int i = 0; i < num_elem_allocated; i++ ) {
        freelist_rm(list, allocated_elems[i]);
        /* rm should insert an index in the now-free location, so the thread id
         * should be different - very slight chance this assertion will fail, if
         * inserted index is the same as the lower 4 bytes of this_thrd_id */
        TEST(allocated_elems[i] != this_thrd_id);
    }

    return nullptr;
}

void freelist_multithreaded() {
    constexpr int   numthreads = 20;
    constexpr int   listlen = 10;
    pthread_t       thrd_id[numthreads];
    pthread_t       fl_arr[listlen];
    struct freelist list;

    freelist_init(&list, fl_arr, listlen);

    ASSERT_LIST_STATE_VALID(&list);

    for ( int i = 0; i < numthreads; i++ ) {
        pthread_create(&thrd_id[i], nullptr, freelist_thread, &list);
        ASSERT_LIST_STATE_VALID(&list);
    }

    ASSERT_LIST_STATE_VALID(&list);

    for ( int i = 0; i < numthreads; i++ ) {
        pthread_join(thrd_id[i], nullptr);
        ASSERT_LIST_STATE_VALID(&list);
    }

    TEST(list.top >= listlen);
    END_TEST;
}

int main(void) {
    freelist_fill_and_remove();
    freelist_fill_nonfull_and_remove();
    freelist_multithreaded();
    END_TEST;
}
