/* Copyright (C) 2007-2017 Open Information Security Foundation
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

#include "detect-http-accept.h"
#include "detect-http-accept-enc.h"
#include "detect-http-accept-lang.h"
#include "detect-http-connection.h"
#include "detect-http-content-len.h"
#include "detect-http-content-type.h"
#include "detect-http-location.h"
#include "detect-http-server.h"
#include "detect-http-referer.h"
#include "detect-http-headers.h"

void DetectHttpHeadersRegister(void)
{
    RegisterHttpHeadersAccept();
    RegisterHttpHeadersAcceptEnc();
    RegisterHttpHeadersAcceptLang();
    RegisterHttpHeadersReferer();
    RegisterHttpHeadersConnection();
    RegisterHttpHeadersContentLen();
    RegisterHttpHeadersContentType();
    RegisterHttpHeadersServer();
    RegisterHttpHeadersLocation();
}

