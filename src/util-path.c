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

/**
 * \brief Wrapper around SCMkDir with default mode arguments.
 */
int SCDefaultMkDir(const char *path)
{
    return SCMkDir(path, S_IRWXU | S_IRGRP | S_IXGRP);
}

/**
 * \brief Recursively create a directory.
 *
 * \param path Path to create
 * \param final true will create the final path component, false will not
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int SCCreateDirectoryTree(const char *path, const bool final)
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

            if (SCDefaultMkDir(pathbuf) != 0) {
                if (errno != EEXIST) {
                    return -1;
                }
            }

            *p = '/';
        }
    }

    if (final) {
        if (SCDefaultMkDir(pathbuf) != 0) {
            if (errno != EEXIST) {
                return -1;
            }
        }
    }

    return 0;
}

/**
 * \brief Check if a path exists.
 *
 * \param Path to check for existence
 *
 * \retval true if path exists
 * \retval false if path does not exist
 */
bool SCPathExists(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) == 0) {
        return true;
    }
    return false;
}

/**
 *  \brief Renames the specified fully-qualified dotted file path to its
 *   non-dotted equivalent. This function was originally written for
 *   detect-tag-pcap.c, but was moved to util-path.c as its utility is not
 *   restricted to the packet dumping feature.
 *  \param dotted_filepath fully-qualified path to the hidden temporary file
 *   to unmask.
 */
void SCUndotFilepath(const char *dotted_filepath)
{
    char undotted_path[PATH_MAX];

    /*
     * Copy the dotted file path so that it can be modified into the
     * destination undotted path.
     */
    size_t len = strlcpy(undotted_path, dotted_filepath, sizeof(undotted_path));
    if (len >= sizeof(undotted_path)) {
        SCLogError(SC_ERR_INVALID_NUM_BYTES, "Provided buffer size is too "
                                             "small to undot file path: "
                                             "%s\nError: %s",
                   dotted_filepath, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /*
     * Shift characters left by one until a '/' is found. The filename is
     * temporarily hidden, i.e. prefixed with a '.', while packets are being
     * dumped. This shifting is done to find that '.' and remove it so the
     * file is no longer hidden.
     */
    char last_replaced_char = undotted_path[len];
    size_t x = len;
    while (undotted_path[--x] != '/' && x > 0) {
        char tmp = undotted_path[x];
        undotted_path[x] = last_replaced_char;
        last_replaced_char = tmp;
    }

    if (rename(dotted_filepath, undotted_path) != 0) {
        SCLogError(SC_ERR_RENAME, "Failed to rename dotted file: %s to %s: "
                                  "\n Error: %s", dotted_filepath,
                   undotted_path, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

