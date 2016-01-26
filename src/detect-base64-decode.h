/* Copyright (C) 2015 Open Information Security Foundation
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

#ifndef __DETECT_BASE64_DECODE_H__
#define __DETECT_BASE64_DECODE_H__

#include "app-layer-template.h"

typedef struct DetectBase64Decode_ {
    uint32_t bytes;
    uint32_t offset;
    uint8_t relative;
} DetectBase64Decode;

void DetectBase64DecodeRegister(void);
int DetectBase64DecodeDoMatch(DetectEngineThreadCtx *, Signature *,
    const SigMatch *, uint8_t *, uint32_t);

#endif /* __DETECT_BASE64_DECODE_H__ */
