#ifndef NOKNOW_DEBUG_H
#define NOKNOW_DEBUG_H

#include <time.h>

#ifndef DEBUG
#define DEBUG_WAS_DEFINED 0
#define DEBUG 0
#else
#define DEBUG_WAS_DEFINED 1
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

#if DEBUG == 1
#define debugf(...) \
        do { if(DEBUG){ fprintf(stderr, "%s:%d:%s(): ",__FILE__, __LINE__, __func__);\
             fprintf(stderr, __VA_ARGS__); \
             fflush(stderr); }} while (0)
#else
#define debugf(...)
#endif

#if DEBUG_WAS_DEFINED == 0
#undef DEBUG
#endif

#endif//NOKNOW_DEBUG_H
