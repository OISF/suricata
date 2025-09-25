/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Victor Julien <vjulien@oisf.net>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-debug.h"
#include "util-fopen.h"

/** \brief fopen like function to open with explict permissions
 *  \note permissions in mode will be limited by process wide `umask` settings
 */
FILE *SCFopen(const char *path, const char *m, mode_t mode)
{
    int flags;
    if (strcmp(m, "r") == 0) {
        flags = O_RDONLY;
    } else if (strcmp(m, "w") == 0) {
        flags = O_WRONLY | O_CREAT | O_TRUNC;
    } else {
        return NULL;
    }

    int fd = open(path, flags, mode);
    if (fd < 0)
        return NULL;

    FILE *fp = fdopen(fd, m);
    if (fp == NULL) {
        close(fd);
        return NULL;
    }
    return fp;
}
