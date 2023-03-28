/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __OUTPUT_JSON_HTTP_H__
#define __OUTPUT_JSON_HTTP_H__

#define MAX_SIZE_HEADER_NAME 256
#define MAX_SIZE_HEADER_VALUE 2048

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_REQUEST 2 /* request field */
#define LOG_HTTP_ARRAY 4 /* require array handling */
#define LOG_HTTP_REQ_HEADERS 8
#define LOG_HTTP_RES_HEADERS 16
#define LOG_HTTP_WITH_FILE 32 /* require array handling */
#define LOG_HTTP_REQ_BODY 64 /* require array handling */

#define LOG_HTTP_DIR_DOWNLOAD   "download"
#define LOG_HTTP_DIR_UPLOAD     "upload"


void JsonHttpLogRegister(void);

bool EveHttpAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js);
void EveHttpLogJSONBodyPrintable(JsonBuilder *js, Flow *f, uint64_t tx_id);
void EveHttpLogJSONBodyBase64(JsonBuilder *js, Flow *f, uint64_t tx_id);

#endif /* __OUTPUT_JSON_HTTP_H__ */

