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
 */

#ifndef __DETECT_ENGINE_PAYLOAD_H__
#define __DETECT_ENGINE_PAYLOAD_H__

int PrefilterPktPayloadRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx);
int PrefilterPktStreamRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx);

uint8_t DetectEngineInspectPacketPayload(
        DetectEngineCtx *, DetectEngineThreadCtx *, const Signature *, Flow *, Packet *);
int DetectEngineInspectStreamPayload(DetectEngineCtx *,
        DetectEngineThreadCtx *, const Signature *, Flow *,
        Packet *);
uint8_t DetectEngineInspectStream(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

void PayloadRegisterTests(void);

#endif /* __DETECT_ENGINE_PAYLOAD_H__ */

