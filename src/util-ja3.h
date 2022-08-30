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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 */

#ifndef __UTIL_JA3_H__
#define __UTIL_JA3_H__

#define JA3_BUFFER_INITIAL_SIZE 128

typedef struct JA3Buffer_ {
    char *data;
    size_t size;
    size_t used;
} JA3Buffer;

JA3Buffer *Ja3BufferInit(void);
void Ja3BufferFree(JA3Buffer **);
int Ja3BufferAppendBuffer(JA3Buffer **, JA3Buffer **);
int Ja3BufferAddValue(JA3Buffer **, uint32_t);
char *Ja3GenerateHash(JA3Buffer *);
int Ja3IsDisabled(const char *);

#endif /* __UTIL_JA3_H__ */

