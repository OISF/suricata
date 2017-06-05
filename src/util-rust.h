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

#ifndef __UTIL_RUST_H__
#define __UTIL_RUST_H__

void RustInit(void);

#ifdef HAVE_RUST

struct rust_config {
    uint32_t magic;
    uint32_t log_level;
};

// Helper function to discover the ALPROTO identifier from the Rust code
//
// Later, this cpde will be replaced by the dynamic registration of ALPROTO
AppProto crust_register_alproto(const char *proto);

// Opaque structure representing a parser state
struct rust_parser_state_t;

struct rust_parser {
    char *name;

    uint16_t ip_proto;
    char *default_port;

    int32_t min_frame_length;

    uint16_t al_proto;

    void * events;

    AppProto (*probe)(uint8_t*, uint32_t, uint32_t*); // input, size, offset
    uint32_t (*parse)(uint8_t, const uint8_t*, uint32_t, const void*); // direction, input, size, parser

    void * (*new_state)(void);
    void (*free_state)(void *);
};

extern int32_t rusticata_init(struct rust_config *);

extern const struct rust_parser * rusticata_get_parser(uint32_t index);

extern uint32_t r_generic_parse(uint8_t, const uint8_t*, uint32_t, const void*); // direction, input, size, parser

#define R_STATUS_EVENTS   0x0100

#define R_STATUS_OK       0x0000
#define R_STATUS_FAIL     0x0001

#define R_STATUS_EV_MASK  0x0f00
#define R_STATUS_MASK     0x00ff

#define R_NO_MORE_EVENTS UINT32_MAX

#define R_STATUS_IS_OK(status) ((status & R_STATUS_MASK)==R_STATUS_OK)
#define R_STATUS_HAS_EVENTS(status) ((status & R_STATUS_EV_MASK)==R_STATUS_EVENTS)

extern uint32_t r_get_next_event(void *state);

#endif /* HAVE_RUST */

#endif /* __UTIL_RUST_H__ */
