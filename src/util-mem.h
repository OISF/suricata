/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Utility Macros for memory management
 *
 * \todo Add wrappers for functions that allocate/free memory here.
 * Currently we have malloc, calloc, realloc, strdup and free,
 * but there are more.
 */

#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

#include "util-atomic.h"

#if CPPCHECK==1
#define SCMalloc malloc
#define SCCalloc calloc
#define SCRealloc realloc
#define SCFree free
#define SCStrdup strdup
#define SCMallocAligned _mm_malloc
#define SCFreeAligned _mm_free
#else /* CPPCHECK */


#if defined(_WIN32) || defined(__WIN32)
#include "mm_malloc.h"
#endif

#if defined(__tile__)
/* Need to define __mm_ function alternatives, since these are SSE only.
 */
#include <malloc.h>
#define _mm_malloc(a,b) memalign((b),(a))
#define _mm_free(a) free((a))
#endif /* defined(__tile__) */

SC_ATOMIC_EXTERN(unsigned int, engine_stage);

/* Use this only if you want to debug memory allocation and free()
 * It will log a lot of lines more, so think that is a performance killer */

/* Uncomment this if you want to print memory allocations and free's() */
//#define DBG_MEM_ALLOC

#ifdef DBG_MEM_ALLOC

/* Uncomment this if you want to print mallocs at the startup (recommended) */
#define DBG_MEM_ALLOC_SKIP_STARTUP

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                               \
        SCLogInfo("SCMalloc return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)(a)); \
    }                                \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                                         \
        SCLogInfo("SCRealloc return at %p (old:%p) of size %"PRIuMAX, \
            ptrmem, (x), (uintmax_t)(a)); \
    }                                     \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)a); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a)*(nm); \
    if (print_mem_flag == 1) {                                          \
        SCLogInfo("SCCalloc return at %p of size %"PRIuMAX" (nm) %"PRIuMAX, \
            ptrmem, (uintmax_t)(a), (uintmax_t)(nm)); \
    }                                                 \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    size_t len = strlen((a)); \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += len; \
    if (print_mem_flag == 1) {                              \
        SCLogInfo("SCStrdup return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)len); \
    }                                \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    extern uint8_t print_mem_flag; \
    if (print_mem_flag == 1) {          \
        SCLogInfo("SCFree at %p", (a)); \
    }                                   \
    free((a)); \
})

#else /* !DBG_MEM_ALLOC */

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            uintmax_t scmalloc_size_ = (uintmax_t)(a); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), scmalloc_size_); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            size_t _scstrdup_len = strlen((a)); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)_scstrdup_len); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    free(a); \
})

#if defined(__WIN32) || defined(_WIN32)

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
	ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)(a), (uintmax_t)(b)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    _mm_free(a); \
})

#else /* !win */

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
    int r = posix_memalign(&ptrmem, (b), (a)); \
    if (r != 0 || ptrmem == NULL) { \
        if (ptrmem != NULL) { \
            free(ptrmem); \
            ptrmem = NULL; \
        } \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)a, (uintmax_t)b); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    free(a); \
})

#endif /* __WIN32 */

#endif /* DBG_MEM_ALLOC */

#endif /* CPPCHECK */

#endif /* __UTIL_MEM_H__ */

