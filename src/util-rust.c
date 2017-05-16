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

/**
 *
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "util-print.h"
#include "util-debug.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "util-rust.h"

#ifndef HAVE_RUST

/* Rust support not available */
void RustInit(void)
{
}

#else /* HAVE_RUST */

static int RustRegisterParser(const struct rust_parser * parser);

static struct rust_config _rcfg = {
    .magic = 0x72757374,
};

// Helper function to discover the ALPROTO identifier from the Rust code
//
// Later, this cpde will be replaced by the dynamic registration of ALPROTO
AppProto crust_register_alproto(const char *proto)
{
    if (strcmp("rust-ntp",proto)==0)
        return ALPROTO_NTP;
    else if (strcmp("rust-tls",proto)==0)
        return ALPROTO_TLS;
    else {
        SCLogError(SC_ERR_INITIALIZATION, "Unknown Rust protocol");
        return -1;
    }

}


static int RustParseToServer(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    int status;
    int direction = 0; /* to server */
    struct rust_parser_state_t *rust_state = state;

    SCLogNotice("Parsing packet to server: len=%"PRIu32, input_len);

    status = r_generic_parse(direction, input, input_len, rust_state);

    // check for events
    if (R_STATUS_HAS_EVENTS(status)) {
        uint32_t event;
        for (;;) {
            event = r_get_next_event(rust_state);
            if (event == R_NO_MORE_EVENTS) break;
            SCLogInfo("Rust decoder event: %d\n", event);
        }
    }

    return (status & R_STATUS_MASK);
}

static int RustParseToClient(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    int status;
    int direction = 1; /* to client */
    struct rust_parser_state_t *rust_state = state;

    SCLogNotice("Parsing packet to client: len=%"PRIu32, input_len);

    status = r_generic_parse(direction, input, input_len, rust_state);

    // check for events
    if (R_STATUS_HAS_EVENTS(status)) {
        uint32_t event;
        for (;;) {
            event = r_get_next_event(rust_state);
            if (event == R_NO_MORE_EVENTS) break;
            SCLogInfo("Rust decoder event: %d\n", event);
        }
    }

    return (status & R_STATUS_MASK);
}



void RustInit(void)
{
    uint32_t index;

    SCLogInfo("Rust parsers init");

    _rcfg.log_level = sc_log_global_log_level;
    _rcfg.log_level = 15;
    rusticata_init(&_rcfg);

    for (index=0; ; index++) {
        const struct rust_parser *parser = rusticata_get_parser(index);
        if (parser == NULL)
            break;

        { // XXX debug
        SCLogNotice("    registering: %s", parser->name);
        SCLogNotice("        ip_proto  : %d", parser->ip_proto);
        SCLogNotice("        def_port  : %s", parser->default_port);
        SCLogNotice("        min_frame_length  : %d", parser->min_frame_length);
        SCLogNotice("        al_proto  : %d", parser->al_proto);
        SCLogNotice("        events    : %p", parser->events);
        SCLogNotice("        probe     : %p", parser->probe);
        SCLogNotice("        parse     : %p", parser->parse);
        SCLogNotice("        new_state : %p", parser->new_state);
        SCLogNotice("        free_state: %p", parser->free_state);
        }

        if (RustRegisterParser(parser) != 0) {
            SCLogError(SC_ERR_INITIALIZATION, "Registration of Rust parser '%s' failed", parser->name);
            continue;
        }
    }
}

static int RustRegisterParser(const struct rust_parser * parser)
{
    AppProto alproto = parser->al_proto;
    const char * ip_proto_str = NULL;

    if (parser->ip_proto == IPPROTO_TCP)
        ip_proto_str = "tcp";
    else if (parser->ip_proto == IPPROTO_UDP)
        ip_proto_str = "udp";
    else {
        SCLogError(SC_ERR_INITIALIZATION, "Unknown Rust IP protocol");
        return -1;
    }

    /* Check if protocol detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str, parser->name)) {

        SCLogNotice("%s/%s protocol detection enabled.", parser->name, ip_proto_str);
        SCLogNotice("alproto: %d", alproto);

        AppLayerProtoDetectRegisterProtocol(alproto, parser->name);

        if (!AppLayerProtoDetectPPParseConfPorts(ip_proto_str, parser->ip_proto,
                    parser->name, alproto, 0, parser->min_frame_length,
                    parser->probe, parser->probe)) {
            SCLogNotice("No Rust app-layer configuration, enabling Rust"
                    " detection %s detection on port %s.",
                    ip_proto_str,
                    parser->default_port);
            AppLayerProtoDetectPPRegister(parser->ip_proto,
                    parser->default_port, alproto, 0,
                    parser->min_frame_length, STREAM_TOSERVER,
                    parser->probe, parser->probe);
        }

        SCLogNotice("Registering Rust protocol parser %s.", parser->name);

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Rust flow. */
        AppLayerParserRegisterStateFuncs(parser->ip_proto, alproto,
                parser->new_state, parser->free_state);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(parser->ip_proto, alproto,
                STREAM_TOSERVER, RustParseToServer);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(parser->ip_proto, alproto,
                STREAM_TOCLIENT, RustParseToClient);
    }
    else {
        SCLogNotice("Protocol detecter and parser disabled for %s.", parser->name);
        return -1;
    }


    return 0;
}

#endif /* HAVE_RUST */
