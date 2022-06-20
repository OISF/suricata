/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_NBSS_H__
#define __APP_LAYER_NBSS_H__


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

#define NBSS_SESSION_MESSAGE            0x00
#define NBSS_SESSION_REQUEST            0x81
#define NBSS_POSITIVE_SESSION_RESPONSE  0x82
#define NBSS_NEGATIVE_SESSION_RESPONSE  0x83
#define NBSS_RETARGET_SESSION_RESPONSE  0x84
#define NBSS_SESSION_KEEP_ALIVE         0x85

typedef struct NBSSHdr_ {
	uint8_t type;
	uint8_t flags;
	uint32_t length;
} NBSSHdr;

#define NBSS_HDR_LEN 4

#endif /* __APP_LAYER_NBSS_H__ */
