#include <sys/types.h>

int is_integer(char *str, size_t str_len);

/**
 * @brief Checks if `str` is an integer in a decimal base
 *
 * @param str Pointer to the string. String doesn't have to be delimited by a
 * NULL byte
 * @param str_len Length of str
 * @return 0 for not integer (Any non-decimal-digit byte is present).
 * 1 for valid integer.
 */
int is_integer(char str[], size_t str_len) {
    // 0 = 0x30, 9 = 0x39
    // Attempting to use SIMD instructions, should work when compiled with -O3

    for ( int i = 0; i < str_len; i++ ) {
        if ( str[i] < 0x30 ) {
            return 0;
        }
    }

    for ( int i = 0; i < str_len; i++ ) {
        if ( str[i] > 0x39 ) {
            return 0;
        }
    }

    return 1;
}
