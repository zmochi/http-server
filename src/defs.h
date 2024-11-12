/**
 * @file defs.h
 * @brief syntax definitions such as __nullable, useful typedefs etc
 */
#ifndef __MACROS_H
#define __MACROS_H

#define B  (1ULL)
#define KB (1ULL << 10)
#define MB (1ULL << 20)
#define GB (1ULL << 30)

/* nullable and nonnull attributes, relevant to clang and gcc. adds compiler
 * warnings if compiler supports, or does nothing if not */
#ifndef _Nullable
#define _Nullable
#endif

#ifndef _Nonnull
#define _Nonnull
#endif

#if __GNUC__ >= 3 || defined(__clang__)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#endif /* __MACROS_H */
