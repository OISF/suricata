/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 */

#ifndef __UTIL_ERROR_H__
#define __UTIL_ERROR_H__

/* different error types */
typedef enum {
    SC_OK,

    SC_ENOMEM,
    SC_EINVAL,
    SC_ELIMIT,
    SC_EEXIST,

    SC_ERR_MAX
} SCError;

const char *SCErrorToString(SCError);

#include "threads.h"

extern thread_local SCError sc_errno;

#endif /* __UTIL_ERROR_H__ */
