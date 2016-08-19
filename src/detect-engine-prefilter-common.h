/* Copyright (C) 2007-2016 Open Information Security Foundation
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

#ifndef __DETECT_ENGINE_PREFILTER_COMMON_H__
#define __DETECT_ENGINE_PREFILTER_COMMON_H__

typedef union {
    uint8_t u8[8];
    uint16_t u16[4];
    uint32_t u32[2];
    uint64_t u64;
} PrefilterPacketHeaderValue;

typedef struct PrefilterPacketHeaderCtx_ {
    PrefilterPacketHeaderValue v1;

    /** rules to add when the flags are present */
    uint32_t sigs_cnt;
    SigIntId *sigs_array;
} PrefilterPacketHeaderCtx;

int PrefilterSetupPacketHeader(SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        _Bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx));

#endif /* __DETECT_ENGINE_PREFILTER_COMMON_H__ */
