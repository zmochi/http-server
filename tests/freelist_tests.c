#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "../src/freelist.c"
#include <assert.h>

#define TEST(cond) assert(cond)

#define END_TEST printf("Test %s succeeded\n", BOOST_CURRENT_FUNCTION)

void freelist_fill_and_remove() {           // NOLINT(*cognitive-complexity)
    constexpr int   listlen = 5;
    struct freelist list, *listptr = &list; // NOLINT
    int             intlist[listlen];
    int             elem_list[] = {1, 2, 3, 4, 5, 6};

    if ( freelist_init(&list, (void *)intlist, listlen, sizeof(int)) !=
         FREELIST_SUCCESS )
        printf("bad array element size");

    TEST(list.top == 0 && list.head == 0);
    freelist_insert(listptr, &elem_list[4]);
    TEST(list.top == 1 && list.head == 1);
    freelist_insert(listptr, &elem_list[3]);
    TEST(list.top == 2 && list.head == 2);
    freelist_insert(listptr, &elem_list[2]);
    TEST(list.top == 3 && list.head == 3);
    freelist_insert(listptr, &elem_list[1]);
    TEST(list.top == 4 && list.head == 4);
    freelist_insert(listptr, &elem_list[0]);
    TEST(list.top == 5 && list.head == 5);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(intlist[2] == 3);
    TEST(intlist[3] == 2);
    TEST(intlist[4] == 1);
    // NOLINTEND

    TEST(freelist_insert(listptr, &elem_list[5]) == FREELIST_FULL);
    TEST(list.top == 5 && list.head == 5);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(intlist[2] == 3);
    TEST(intlist[3] == 2);
    TEST(intlist[4] == 1);
    // NOLINTEND

    freelist_rm(listptr, 2);
    TEST(list.head == 2 && get_next_empty(listptr) == 5);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(intlist[3] == 2);
    TEST(intlist[4] == 1);
    // NOLINTEND

    freelist_rm(listptr, 3);
    TEST(list.head == 3 && get_next_empty(listptr) == 2);

    // NOLINTBEGIN
    TEST(intlist[0] == 5);
    TEST(intlist[1] == 4);
    TEST(intlist[4] == 1);
    // NOLINTEND

    END_TEST;
}

void freelist_fill_nonfull_and_remove() {
    const int       listlen = 5;
    struct freelist list, *listptr = &list; // NOLINT
    int             intlist[listlen];
    int             elem_list[] = {1, 2, 3, 4, 5};

    if ( freelist_init(&list, (void *)intlist, listlen, sizeof(int)) !=
         FREELIST_SUCCESS )
        printf("bad array element size");

    TEST(list.top == 0 && list.head == 0);
    freelist_insert(listptr, &elem_list[4]); // 5
    TEST(list.top == 1 && list.head == 1);
    freelist_insert(listptr, &elem_list[3]); // 4
    TEST(list.top == 2 && list.head == 2);
    freelist_insert(listptr, &elem_list[2]); // 3
    TEST(list.top == 3 && list.head == 3);

    freelist_rm(listptr, 1); /* rm value 4 */
    TEST(list.top == 3 && list.head == 1);
    TEST(get_next_empty(listptr) == 3);

    freelist_rm(listptr, 0); /* rm value 5 */
    TEST(list.top == 3 && list.head == 0);
    TEST(get_next_empty(listptr) == 1);

    freelist_insert(listptr,
                    &elem_list[3]); /* add 4 at position 0 (previously 5) */
    TEST(list.top == 3 && list.head == 1);
    TEST(intlist[0] == 4);          // NOLINT

    freelist_insert(listptr,
                    &elem_list[4]); /* add 5 at position 1 (previously 4) */
    TEST(list.top == 3 && list.head == 3);
    TEST(intlist[1] == 5);          // NOLINT

    freelist_insert(listptr, &elem_list[1]);
    TEST(list.top == 4 && list.head == 4);
    TEST(intlist[3] == 2); // NOLINT

    END_TEST;
}

int main(void) {
    freelist_fill_and_remove();
    freelist_fill_nonfull_and_remove();
    END_TEST;
}
