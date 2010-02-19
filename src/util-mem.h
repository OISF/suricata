/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Add wrappers for functions that allocate/free memory here.
 * Currently we have malloc, calloc, realloc, strdup and free,
 * but there are more.
 */

//#ifndef __UTIL_MEM_H__
//#define __UTIL_MEM_H__

/* Use this only if you want to debug memory allocation and free()
 * It will log a lot of lines more, so think that is a performance killer */

/* Uncomment this if you want to print memory allocations and free's() */
//#define DBG_MEM_ALLOC

/* Uncomment this if you want to print mallocs at the startup (recommended) */
//#define DBG_MEM_ALLOC_SKIP_STARTUP

#ifdef DBG_MEM_ALLOC

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    extern uint64_t global_mem; \
    extern uint8_t print_mem_flag; \
    ptrmem = malloc(a); \
    if (ptrmem == NULL && a > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "Malloc of size %"PRIu64" failed! exiting.", (uint64_t)a); \
        exit(EXIT_FAILURE); \
    } \
    global_mem += a; \
    if (print_mem_flag == 1) \
        SCLogInfo("SCMalloc return at %p of size %"PRIu64, ptrmem, (uint64_t)a); \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    extern uint64_t global_mem; \
    extern uint8_t print_mem_flag; \
    ptrmem = realloc(x, a); \
    if (ptrmem == NULL && a > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "Realloc of size %"PRIu64" failed! exiting.", (uint64_t)a); \
        exit(EXIT_FAILURE); \
    } \
    global_mem += a; \
    if (print_mem_flag == 1) \
        SCLogInfo("SCRealloc return at %p (old:%p) of size %"PRIu64, ptrmem, x, (uint64_t)a); \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    extern uint64_t global_mem; \
    extern uint8_t print_mem_flag; \
    ptrmem = calloc(nm, a); \
    if (ptrmem == NULL && a > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "Calloc of size %"PRIu64" failed! exiting.", (uint64_t)a); \
        exit(EXIT_FAILURE); \
    } \
    global_mem += a*nm; \
    if (print_mem_flag == 1) \
        SCLogInfo("SCCalloc return at %p of size %"PRIu64" nm %"PRIu64, ptrmem, (uint64_t)a, (uint64_t)nm); \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    extern uint64_t global_mem; \
    extern uint8_t print_mem_flag; \
    size_t len = strlen(a); \
    ptrmem = strdup(a); \
    if (ptrmem == NULL && len > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "Strdup of size %"PRIu64" failed! exiting.", (uint64_t)len); \
        exit(EXIT_FAILURE); \
    } \
    global_mem += len; \
    if (print_mem_flag == 1) \
        SCLogInfo("SCStrdup return at %p of size %"PRIu64, ptrmem, (uint64_t)len); \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    extern uint8_t print_mem_flag; \
    if (print_mem_flag == 1) \
        SCLogInfo("SCFree at %p", a); \
    free(a); \
})

#else

/* Replace them with the normal calls, so we get no performance penalty */
#define SCMalloc(a)         malloc(a)
#define SCCalloc(nm,a)      calloc(nm,a)
#define SCRealloc(x,a)      realloc(x,a)
#define SCStrdup(a)         strdup(a)
#define SCFree(a)           free(a)

#endif

//#endif /* __UTIL_MEM_H__ */

