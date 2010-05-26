/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Information about hosts for ip reputation.
 */

#include "suricata-common.h"
#include "util-debug.h"
#include "host.h"

Host *HostAlloc(void) {
    Host *h = SCMalloc(sizeof(Host));
    if (h == NULL)
        goto error;

    return h;

error:
    return NULL;
}

void HostFree(Host *h) {
    SCFree(h);
}

Host *HostNew(Address *a) {
    Host *h = HostAlloc();
    if (h == NULL)
        goto error;

    /* copy address */

    /* set os and reputation to 0 */
    h->os = HOST_OS_UNKNOWN;
    h->reputation = HOST_REPU_UNKNOWN;

    return h;

error:
    return NULL;
}

