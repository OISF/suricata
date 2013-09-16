/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect.h"

#include "util-var.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"

#include "util-debug.h"

static unsigned int valgrind_errors = 0;
static SCMutex valgrind_errors_lock = PTHREAD_MUTEX_INITIALIZER;

int ValgrindError(void) {
    int ret = 0;
    if (RUNNING_ON_VALGRIND) {
        SCMutexLock(&valgrind_errors_lock);
        unsigned int errors = VALGRIND_COUNT_ERRORS;
        if (errors != valgrind_errors) {
            ret = 1;
            valgrind_errors = errors;
        }
        SCMutexUnlock(&valgrind_errors_lock);
    }
    return ret;
}

