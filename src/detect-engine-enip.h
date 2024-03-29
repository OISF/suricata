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

/** \file
 *
 *  \author Kevin Wong <kwong@solananetworks.com>
 */

#ifndef SURICATA_DETECT_ENGINE_ENIP_H
#define SURICATA_DETECT_ENGINE_ENIP_H

uint8_t DetectEngineInspectCIP(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *,
        const struct DetectEngineAppInspectionEngine_ *, const Signature *, Flow *, uint8_t, void *,
        void *, uint64_t);

uint8_t DetectEngineInspectENIP(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *,
        const struct DetectEngineAppInspectionEngine_ *, const Signature *, Flow *, uint8_t, void *,
        void *, uint64_t);

#endif /* SURICATA_DETECT_ENGINE_ENIP_H */
