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

#ifndef __APP_LAYER_HTP_FILE_H__
#define __APP_LAYER_HTP_FILE_H__

int HTPFileOpen(HtpState *, HtpTxUserData *, const uint8_t *, uint16_t, const uint8_t *, uint32_t,
        uint64_t, uint8_t);
int HTPParseContentRange(bstr *rawvalue, HTTPContentRange *range);
int HTPFileOpenWithRange(HtpState *, HtpTxUserData *, const uint8_t *, uint16_t, const uint8_t *,
        uint32_t, uint64_t, bstr *rawvalue, HtpTxUserData *htud);
void HTPFileCloseHandleRange(
        FileContainer *, const uint16_t, HttpRangeContainerBlock *, const uint8_t *, uint32_t);
int HTPFileStoreChunk(HtpState *, const uint8_t *, uint32_t, uint8_t);
int HTPFileClose(HtpState *, const uint8_t *, uint32_t, uint8_t, uint8_t);

void HTPFileParserRegisterTests(void);

#endif /* __APP_LAYER_HTP_FILE_H__ */
