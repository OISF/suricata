/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata.h"
#include "util-atomic.h"

#if defined(_WIN32) || defined(__WIN32)
#include <mm_malloc.h>
#endif

SC_ATOMIC_EXTERN(unsigned int, engine_stage);

void *SCMallocFunc(const size_t sz)
{
    void *ptrmem = malloc(sz);
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            uintmax_t scmalloc_size_ = (uintmax_t)sz;
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes", strerror(errno), scmalloc_size_);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
    return ptrmem;
}

void *SCReallocFunc(void *ptr, const size_t size)
{
    void *ptrmem = realloc(ptr, size);
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)size);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
    return ptrmem;
}

void *SCCallocFunc(const size_t nm, const size_t sz)
{
    void *ptrmem = calloc(nm, sz);
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)nm*sz);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
    return ptrmem;
}

char *SCStrdupFunc(const char *s)
{
    char *ptrmem = strdup(s);
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            size_t _scstrdup_len = strlen(s);
            SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)_scstrdup_len);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
    return ptrmem;
}

char *SCStrndupFunc(const char *s, size_t n)
{
#ifdef HAVE_STRNDUP
    char *ptrmem = strndup(s, n);
#else
    const size_t sz = n + 1;
    char *ptrmem = (char *)malloc(sz);
    if (likely(ptrmem != NULL)) {
        strlcpy(ptrmem, s, sz);
    }
#endif
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCStrndup failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(n + 1));
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
    return ptrmem;
}

void *SCMallocAlignedFunc(const size_t size, const size_t align)
{
#if defined(__WIN32) || defined(_WIN32)
    void *ptrmem = _mm_malloc(size, align);
    if (unlikely(ptrmem == NULL)) {
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)size, (uintmax_t)align);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
#else
    void *ptrmem = NULL;
    int r = posix_memalign(&ptrmem, align, size);
    if (unlikely(r != 0 || ptrmem == NULL)) {
        if (ptrmem != NULL) {
            free(ptrmem);
            ptrmem = NULL;
        }
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying "
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)size, (uintmax_t)align);
            FatalError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting...");
        }
    }
#endif
    return ptrmem;
}

void SCFreeAlignedFunc(void *ptr)
{
#if defined(__WIN32) || defined(_WIN32)
    _mm_free(ptr);
#else
    free(ptr);
#endif
}
