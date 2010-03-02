/*
 * Copyright (c) 2009 Open Information Security Foundation
 * app-layer-nbss.h
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef APPLAYERNBSS_H_
#define APPLAYERNBSS_H_
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream.h"
#include <stdint.h>
/*
 http://ubiqx.org/cifs/rfc-draft/rfc1002.html#s4.3
 All session packets are of the following general structure:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      TYPE     |     FLAGS     |            LENGTH             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /               TRAILER (Packet Type Dependent)                 /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The TYPE, FLAGS, and LENGTH fields are present in every session
   packet.
*/
#define NBSS_SESSION_MESSAGE 0x00
#define NBSS_SESSION_REQUEST 0x81
#define NBSS_POSITIVE_SESSION_RESPONSE 0x82
#define NBSS_NEGATIVE_SESSION_RESPONSE 0x83
#define NBSS_RETARGET_SESSION_RESPONSE 0x84
#define NBSS_SESSION_KEEP_ALIVE 0x85

typedef struct nbss_hdr_ {
	uint8_t type;
	uint8_t flags;
	uint32_t length;
}NBSSHdr;
#define NBSS_HDR_LEN 4

#endif /* APPLAYERNBSS_H_ */
