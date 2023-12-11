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

#include "app-layer/http/detect-accept.h"
#include "app-layer/http/detect-accept-enc.h"
#include "app-layer/http/detect-accept-lang.h"
#include "app-layer/http/detect-connection.h"
#include "app-layer/http/detect-content-len.h"
#include "app-layer/http/detect-content-type.h"
#include "app-layer/http/detect-location.h"
#include "app-layer/http/detect-server.h"
#include "app-layer/http/detect-referer.h"
#include "app-layer/http/detect-headers.h"

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
