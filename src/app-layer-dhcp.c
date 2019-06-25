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

/**
 * \file
 *
 * \author Jason Ish <jason.ish@oisf.net>
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "app-layer-parser.h"
#include "app-layer-dhcp.h"

#ifdef HAVE_RUST
#include "rust-bindings.h"
#endif /* HAVE_RUST */

void RegisterDHCPParsers(void)
{
#ifdef HAVE_RUST
    rs_dhcp_register_parser();
#endif /* HAVE_RUST */
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_DHCP,
        DHCPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void DHCPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
