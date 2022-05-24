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
#include "util-debug.h"
#include "util-path.h"

#ifdef OS_WIN32
#define DIRECTORY_SEPARATOR '\\'
#else
#define DIRECTORY_SEPARATOR '/'
#endif

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
 * \brief Wrapper to join a directory and filename and resolve using realpath
 *   _fullpath is used for WIN32
 *
 * \param out_buf output buffer.  Up to PATH_MAX will be written.  Unchanged on exit failure.
 * \param buf_len length of output buffer
 * \param dir the directory
 * \param fname the filename
 *
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode PathJoin (char *out_buf, uint16_t buf_len, const char *const dir, const char *const fname)
{
    SCEnter();
    uint16_t max_path_len = MAX(buf_len, PATH_MAX);
    int bytes_written = snprintf(out_buf, max_path_len, "%s%c%s", dir, DIRECTORY_SEPARATOR, fname);
    if (bytes_written <= 0) {
        SCLogError(SC_ERR_SPRINTF, "Could not join filename to path");
        SCReturnInt(TM_ECODE_FAILED);
    }
    char *tmp_buf = SCRealPath(out_buf, NULL);
    if (tmp_buf == NULL) {
        SCLogError(SC_ERR_SPRINTF, "Error resolving path: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(out_buf, 0, buf_len);
    strlcpy(out_buf, tmp_buf, max_path_len);
    free(tmp_buf);
    SCReturnInt(TM_ECODE_OK);
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
 * \brief OS independent wrapper for directory check
 *
 * \param dir_entry object to check
 *
 * \retval True if the object is a regular directory, otherwise false.  This directory
 *          and parent directory will return false.
 */
bool SCIsRegularDirectory(const struct dirent *const dir_entry)
{
#ifndef OS_WIN32
    if ((dir_entry->d_type == DT_DIR) &&
        (strcmp(dir_entry->d_name, ".") != 0) &&
        (strcmp(dir_entry->d_name, "..") != 0)) {
        return true;
    }
#endif
    return false;
}
/**
 * \brief OS independent to check for regular file
 *
 * \param dir_entry object to check
 *
 * \retval True if the object is a regular file.  Otherwise false.
 */
bool SCIsRegularFile(const struct dirent *const dir_entry)
{
#ifndef OS_WIN32
    return dir_entry->d_type == DT_REG;
#endif
    return false;
}

/**
 * \brief OS independent wrapper for realpath
 *
 * \param path the path to resolve
 * \param resolved_path the resolved path; if null, a buffer will be allocated
 *
 * \retval the resolved_path; or a pointer to a new resolved_path buffer
 */
char *SCRealPath(const char *path, char *resolved_path)
{
#ifdef OS_WIN32
    return _fullpath(resolved_path, path, PATH_MAX);
#else
    return realpath(path, resolved_path);
#endif
}

/*
 * \brief Return the basename of the provided path.
 * \param path The path on which to compute the basename
 *
 * \retval the basename of the path or NULL if the path lacks a non-leaf
 */
const char *SCBasename(const char *path)
{
    if (!path || strlen(path) == 0)
        return NULL;

    char *final = strrchr(path, DIRECTORY_SEPARATOR);
    if (!final)
        return path;

    if (*(final + 1) == '\0')
        return NULL;

    return final + 1;
}
