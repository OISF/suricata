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

#ifndef SURICATA_UTIL_PATH_H
#define SURICATA_UTIL_PATH_H

#ifdef OS_WIN32
typedef struct _stat SCStat;
#define SCFstatFn(fd, statbuf)      _fstat((fd), (statbuf))
#define SCStatFn(pathname, statbuf) _stat((pathname), (statbuf))
#else
typedef struct stat SCStat;
#define SCFstatFn(fd, statbuf)      fstat((fd), (statbuf))
#define SCStatFn(pathname, statbuf) stat((pathname), (statbuf))
#endif

#if defined OS_WIN32 || defined __CYGWIN__
#define PATH_SEPARATOR_SIZE 2
#else
#define PATH_SEPARATOR_SIZE 1
#endif

#ifndef HAVE_NON_POSIX_MKDIR
    #define SCMkDir(a, b) mkdir(a, b)
#else
    #define SCMkDir(a, b) mkdir(a)
#endif

int PathIsAbsolute(const char *);
int PathIsRelative(const char *);
int PathMerge(char *out_buf, size_t buf_size, const char *const dir, const char *const fname);
char *PathMergeAlloc(const char *const dir, const char *const fname);
int SCDefaultMkDir(const char *path);
int SCCreateDirectoryTree(const char *path, const bool final);
bool SCPathExists(const char *path);
bool SCIsRegularDirectory(const struct dirent *const dir_entry);
bool SCIsRegularFile(const struct dirent *const dir_entry);
char *SCRealPath(const char *path, char *resolved_path);
const char *SCBasename(const char *path);
bool SCPathContainsTraversal(const char *path);

#endif /* SURICATA_UTIL_PATH_H */
