/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __OUTPUT_JSON_EMAIL_COMMON_H__
#define __OUTPUT_JSON_EMAIL_COMMON_H__

typedef struct OutputJsonEmailCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} OutputJsonEmailCtx;


typedef struct JsonEmailLogThread_ {
    OutputJsonEmailCtx *emaillog_ctx;
    MemBuffer *buffer;
} JsonEmailLogThread;

int JsonEmailLogger(ThreadVars *tv, void *thread_data, const Packet *p);

#endif /* __OUTPUT_JSON_EMAIL_COMMON_H__ */
