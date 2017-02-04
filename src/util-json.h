/* Copyright (C) 2017 Open Information Security Foundation
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

#include <stdbool.h>

#pragma once

typedef struct SCJson_ SCJson;

SCJson *SCJsonNew(void);
SCJson *SCJsonWrap(char *buf, size_t size);
void SCJsonReset(SCJson *js);
void SCJsonFree(SCJson *js);
const char *SCJsonGetBuf(SCJson *js);
bool SCJsonOpenObject(SCJson *js);
bool SCJsonCloseObject(SCJson *js);
bool SCJsonSetString(SCJson *js, const char *key, const char *val);
bool SCJsonSetInt(SCJson *js, const char *key, const intmax_t val);
bool SCJsonSetBool(SCJson *js, const char *key, const bool val);
bool SCJsonStartObject(SCJson *js, const char *key);
bool SCJsonStartList(SCJson *js, const char *key);
bool SCJsonAppendString(SCJson *js, const char *val);
bool SCJsonAppendInt(SCJson *js, const intmax_t val);
bool SCJsonCloseList(SCJson *js);

void SCJsonMark(SCJson *js);
void SCJsonRewind(SCJson *js);

void UtilJsonRegisterTests(void);
