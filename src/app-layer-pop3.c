/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Alex Savage <alexander.savage@cyber.gc.ca>
 *
 * App-layer parser for POP3 protocol
 *
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-pop3.h"
#include "rust.h"

void RegisterPOP3Parsers(void)
{
    SCLogNotice("Registering Rust pop3 parser.");
    rs_pop3_register_parser();
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_POP3, POP3ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void POP3ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
