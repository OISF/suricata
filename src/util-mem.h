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

/**
 * \file
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Bill Meeks <billmeeks8@gmail.com>
 *
 * Utility Macros for memory management
 *
 * \todo Add wrappers for functions that allocate/free memory here.
 * Currently we have malloc, calloc, realloc, strdup, strndup and
 * free, but there are more.
 */

#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

#if CPPCHECK==1 || defined(__clang_analyzer__)
#define SCMalloc malloc
#define SCCalloc calloc
#define SCRealloc realloc
#define SCFree free
#define SCStrdup strdup
#define SCStrndup strndup
#define SCMallocAligned _mm_malloc
#define SCFreeAligned _mm_free
#else /* CPPCHECK */


void *SCMallocFunc(const size_t sz);
#define SCMalloc(sz) SCMallocFunc((sz))

void *SCReallocFunc(void *ptr, const size_t size);
#define SCRealloc(ptr, sz) SCReallocFunc((ptr), (sz))

void *SCCallocFunc(const size_t nm, const size_t sz);
#define SCCalloc(nm, sz) SCCallocFunc((nm), (sz))

char *SCStrdupFunc(const char *s);
#define SCStrdup(s) SCStrdupFunc((s))

char *SCStrndupFunc(const char *s, size_t n);
#define SCStrndup(s, n) SCStrndupFunc((s), (n))

#define SCFree(p) free((p))

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
void *SCMallocAlignedFunc(const size_t size, const size_t align);
#define SCMallocAligned(size, align) SCMallocAlignedFunc((size), (align))

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
void SCFreeAlignedFunc(void *ptr);
#define SCFreeAligned(p) SCFreeAlignedFunc((p))

#endif /* CPPCHECK */

#endif /* __UTIL_MEM_H__ */

