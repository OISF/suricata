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

#ifndef SURICATA_DETECT_ENGINE_ALERT_H
#define SURICATA_DETECT_ENGINE_ALERT_H

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

void AlertQueueInit(DetectEngineThreadCtx *det_ctx);
void AlertQueueFree(DetectEngineThreadCtx *det_ctx);
void AlertQueueAppend(DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p, uint64_t tx_id,
        uint8_t alert_flags);
void PacketAlertFinalize(const DetectEngineCtx *, DetectEngineThreadCtx *, Packet *);
#ifdef UNITTESTS
int PacketAlertCheck(Packet *, uint32_t);
#endif
void PacketAlertTagInit(void);
void DetectEngineAlertRegisterTests(void);

#endif /* SURICATA_DETECT_ENGINE_ALERT_H */
