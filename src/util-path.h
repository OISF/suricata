/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __UTIL_PATH_H__
#define __UTIL_PATH_H__

#ifndef HAVE_NON_POSIX_MKDIR
    #define SCMkDir(a, b) mkdir(a, b)
#else
    #define SCMkDir(a, b) mkdir(a)
#endif

int PathIsAbsolute(const char *);
int PathIsRelative(const char *);
TmEcode PathJoin (char *out_buf, uint16_t buf_len, const char *const dir, const char *const fname);
int SCDefaultMkDir(const char *path);
int SCCreateDirectoryTree(const char *path, const bool final);
bool SCPathExists(const char *path);
bool SCIsRegularDirectory(const struct dirent *const dir_entry);
bool SCIsRegularFile(const struct dirent *const dir_entry);
char *SCRealPath(const char *path, char *resolved_path);
const char *SCBasename(const char *path);

#endif /* __UTIL_PATH_H__ */
