/* Copyright (C) 2022 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and app-layer-templaterust.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * TemplateRust application layer detector and parser for learning and
 * templaterust purposes.
 *
 * This templaterust implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-template-rust.h"
#include "rust.h"

void RegisterTemplateRustParsers(void)
{
    /* TEMPLATE_START_REMOVE */
    /* Only register if enabled in config. */
    if (ConfGetNode("app-layer.protocols.template-rust") == NULL) {
        return;
    }
    /* TEMPLATE_END_REMOVE */
    SCLogNotice("Registering Rust template parser.");
    rs_template_register_parser();
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_TEMPLATE_RUST,
        TemplateRustParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void TemplateRustParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
