/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef SURICATA_DETECT_BYTEEXTRACT_H
#define SURICATA_DETECT_BYTEEXTRACT_H

void DetectByteExtractRegister(void);

SigMatch *DetectByteExtractRetrieveSMVar(const char *, int sm_list, const Signature *);
int DetectByteExtractDoMatch(DetectEngineThreadCtx *, const SigMatchData *, const Signature *,
        const uint8_t *, uint32_t, uint64_t *, uint8_t);

#endif /* SURICATA_DETECT_BYTEEXTRACT_H */
