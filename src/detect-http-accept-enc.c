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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements http_accept_enc sticky buffer
 */

#define KEYWORD_NAME_LEGACY "http_accept_enc"
#define KEYWORD_NAME "http.accept_enc"
#define KEYWORD_DOC "http-keywords.html#http-accept-enc"
#define BUFFER_NAME "http_accept_enc"
#define BUFFER_DESC "http accept encoding header"
#define HEADER_NAME "Accept-Encoding"
#define KEYWORD_ID DETECT_AL_HTTP_HEADER_ACCEPT_ENC
#define KEYWORD_TOSERVER 1

#include "detect-http-headers-stub.h"
#include "detect-http-accept-enc.h"

void RegisterHttpHeadersAcceptEnc(void)
{
    DetectHttpHeadersRegisterStub();
}
