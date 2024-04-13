/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Implements the sip.content_length sticky buffer
 */

#define KEYWORD_NAME     "sip.content_length"
#define KEYWORD_DOC      "sip-keywords.html#sip-content-length"
#define BUFFER_NAME      "sip.content_length"
#define BUFFER_DESC      "sip content-length header"
#define HEADER_NAME      "Content-Length"
#define KEYWORD_ID       DETECT_AL_SIP_HEADER_CONTENT_LENGTH
#define KEYWORD_TOSERVER 1
#define KEYWORD_TOCLIENT 1

#include "detect-sip-headers-stub.h"
#include "detect-sip-content-length.h"

void RegisterSipHeadersContentLength(void)
{
    DetectSipHeadersRegisterStub();
}
