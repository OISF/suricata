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
    uint64_t fields;/** Store fields */
} OutputJsonEmailCtx;


#ifdef HAVE_LIBJANSSON
typedef struct JsonEmailLogThread_ {
    OutputJsonEmailCtx *emaillog_ctx;
    MemBuffer *buffer;
} JsonEmailLogThread;

TmEcode JsonEmailLogJson(JsonEmailLogThread *aft, json_t *js, const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id);
json_t *JsonEmailAddMetadata(const Flow *f, uint32_t tx_id);
#endif

void OutputEmailInitConf(ConfNode *conf, OutputJsonEmailCtx *email_ctx);

#endif /* __OUTPUT_JSON_EMAIL_COMMON_H__ */
