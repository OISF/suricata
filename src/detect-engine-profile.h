/* Copyright (C) 2016-2022 Open Information Security Foundation
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

#ifndef _DETECT_ENGINE_PROFILE_H
#define	_DETECT_ENGINE_PROFILE_H

void RulesDumpTxMatchArray(const DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        const Packet *p, const uint64_t tx_id, const uint32_t rule_cnt,
        const uint32_t pkt_prefilter_cnt);
void RulesDumpMatchArray(const DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, const Packet *p);

#endif	/* _DETECT_ENGINE_PROFILE_H */
