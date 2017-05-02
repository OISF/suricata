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
 * Page util functions
 */

#include "suricata-common.h"
#include "util-pages.h"

#ifndef HAVE_PAGESUPPORTSRWX_AS_MACRO

/** \brief check if OS allows for RWX pages
 *
 *  Some OS' disallow RWX pages for security reasons. This function mmaps
 *  some memory RW and then tries to turn it into RWX. If this fails we
 *  assume that the OS doesn't allow for this.
 *
 *  Thanks to Shawn Webb from HardenedBSD for the suggestion.
 *
 *  \retval 1 RWX supported
 *  \retval 0 not supported
 */
int PageSupportsRWX(void)
{
    int retval = 1;
    void *ptr;
    ptr = mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    if (ptr != MAP_FAILED) {
        if (mprotect(ptr, getpagesize(), PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
            SCLogConfig("RWX pages denied by OS");
            retval = 0;
        }
        munmap(ptr, getpagesize());
    }
    return retval;
}
#endif /* HAVE_PAGESUPPORTSRWX_AS_MACRO */

