/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 *
 */

#ifndef SURICATA_APP_LAYER_HTP_FILE_H
#define SURICATA_APP_LAYER_HTP_FILE_H

#include "app-layer-htp.h"

int HTPFileOpen(
        HtpState *, HtpTxUserData *, const uint8_t *, uint16_t, const uint8_t *, uint32_t, uint8_t);
int HTPFileOpenWithRange(HtpState *, HtpTxUserData *, const uint8_t *, uint16_t, const uint8_t *,
        uint32_t, const htp_tx_t *, const bstr *rawvalue, HtpTxUserData *htud);
bool HTPFileCloseHandleRange(const StreamingBufferConfig *sbcfg, FileContainer *, const uint16_t,
        HttpRangeContainerBlock *, const uint8_t *, uint32_t);
int HTPFileStoreChunk(HtpTxUserData *, const uint8_t *, uint32_t, uint8_t);

int HTPParseContentRange(const bstr *rawvalue, HTTPContentRange *range);
int HTPFileClose(HtpTxUserData *tx, const uint8_t *data, uint32_t data_len, uint8_t flags,
        uint8_t direction);

void HTPFileParserRegisterTests(void);

#endif /* SURICATA_APP_LAYER_HTP_FILE_H */
