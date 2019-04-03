/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implements http.location sticky buffer
 *
 * "Location" is an HTTP response-header field used to redirect the recipient to
 * a location other than the Request-URI for request completion.
 */

#define KEYWORD_NAME "http.location"
#define KEYWORD_DOC "http-keywords.html#http-location"
#define BUFFER_NAME "http.location"
#define BUFFER_DESC "http location header"
#define HEADER_NAME "Location"
#define KEYWORD_ID DETECT_AL_HTTP_HEADER_LOCATION
#define KEYWORD_TOCLIENT 1

#include "detect-http-headers-stub.h"
#include "detect-http-location.h"

void RegisterHttpHeadersLocation(void)
{
    DetectHttpHeadersRegisterStub();
}
