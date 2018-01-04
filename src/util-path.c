/* Copyright (C) 2007-2012 Open Information Security Foundation
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
#include "suricata.h"
#include "debug.h"
#include "util-debug.h"
#include "util-path.h"

/**
 *  \brief Check if a path is absolute
 *
 *  \param path string with the path
 *
 *  \retval 1 absolute
 *  \retval 0 not absolute
 */
int PathIsAbsolute(const char *path)
{
    if (strlen(path) > 1 && path[0] == '/') {
        return 1;
    }

#if (defined OS_WIN32 || defined __CYGWIN__)
    if (strlen(path) > 2) {
        if (isalpha((unsigned char)path[0]) && path[1] == ':') {
            return 1;
        }
    }
#endif

    return 0;
}

/**
 *  \brief Check if a path is relative
 *
 *  \param path string with the path
 *
 *  \retval 1 relative
 *  \retval 0 not relative
 */
int PathIsRelative(const char *path)
{
    return PathIsAbsolute(path) ? 0 : 1;
}

/** \brief Recursively create missing log directories.
 *  \param path path to log file
 *  \retval 0 on success
 *  \retval -1 on error
 */
int SCCreateDirectoryTree(const char *path)
{
    char pathbuf[PATH_MAX];
    char *p;
    size_t len = strlen(path);

    if (len > PATH_MAX - 1) {
        return -1;
    }

    strlcpy(pathbuf, path, sizeof(pathbuf));

    for (p = pathbuf + 1; *p; p++) {
        if (*p == '/') {
            /* Truncate, while creating directory */
            *p = '\0';

            if (SCMkDir(pathbuf, S_IRWXU | S_IRGRP | S_IXGRP) != 0) {
                if (errno != EEXIST) {
                    return -1;
                }
            }

            *p = '/';
        }
    }

    return 0;
}
