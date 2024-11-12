/**
 * @file logger.h
 * @brief logger module
 */
#include <libs/boost/CURRENT_FUNCTION.hpp>

#ifdef DEBUG

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG_DEBUG(fmt, ...)                                                    \
    printf("DEBUG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)

#define LOG_ERR_DEBUG(fmt, ...)                                                \
    (void)fprintf(stderr, "DEBUG: ERROR: %s: " fmt "\n",                       \
                  BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)
#else

#define LOG_DEBUG(fmt, ...)     ((void)0)
#define LOG_ERR_DEBUG(fmt, ...) ((void)0)

#endif

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG(fmt, ...)                                                          \
    printf("LOG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...)                                                      \
    (void)fprintf(stderr, "ERROR: %s: line %d: " fmt "\n",                     \
                  BOOST_CURRENT_FUNCTION, __LINE__, ##__VA_ARGS__)

#define LOG_ABORT(fmt, ...)                                                    \
    do {                                                                       \
        LOG_ERR(fmt, ##__VA_ARGS__);                                           \
        exit(1);                                                               \
    } while ( 0 )

/* exit() call should not be removed here, will break code */
#define LOGIC_ERR(err_fmt, ...)                                                \
    do {                                                                       \
        LOG_ERR(err_fmt, ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    } while ( 0 )
