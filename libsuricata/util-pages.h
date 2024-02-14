/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#ifndef __UTIL_PAGES_H__
#define __UTIL_PAGES_H__

#include "suricata-common.h"

#ifdef __OpenBSD__
    /* OpenBSD won't allow for this test:
     * "suricata(...): mprotect W^X violation" */
    #define PageSupportsRWX() 0
    #define HAVE_PAGESUPPORTSRWX_AS_MACRO 1
#else
    #ifndef HAVE_SYS_MMAN_H
        #define PageSupportsRWX() 1
        #define HAVE_PAGESUPPORTSRWX_AS_MACRO 1
    #else
        int PageSupportsRWX(void);
    #endif /* HAVE_SYS_MMAN_H */
#endif

#endif /* __UTIL_PAGES_H__ */
