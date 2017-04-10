/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __APP_LAYER_SSH_H__
#define __APP_LAYER_SSH_H__

/* header flag */
#define SSH_FLAG_VERSION_PARSED              0x01

/* This flags indicate that the rest of the communication
 * must be ciphered, so the parsing finish here */
#define SSH_FLAG_PARSER_DONE                 0x02

/* MSG_CODE */
#define SSH_MSG_NEWKEYS                      21

/** From SSH-TRANSP rfc

    SSH Bunary packet structure:
      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

    So we are going to do a header struct to store
    the lenghts and msg_code (inside payload, if any)
*/

typedef struct SshHeader_ {
    uint32_t pkt_len;
    uint8_t padding_len;
    uint8_t msg_code;
    uint16_t banner_len;
    uint8_t buf[6];
    uint8_t buf_offset;
    uint8_t flags;
    uint32_t record_left;
    uint8_t *proto_version;
    uint8_t *software_version;
    uint8_t *banner_buffer;
} SshHeader;

enum {
    SSH_STATE_IN_PROGRESS,
    SSH_STATE_BANNER_DONE,
    SSH_STATE_FINISHED,
};

/** structure to store the SSH state values */
typedef struct SshState_ {
    SshHeader srv_hdr;
    SshHeader cli_hdr;

    /* specifies which loggers are done logging */
    uint32_t logged;

    /* bit flags of mpms that have already run */
    uint64_t mpm_ids;

    DetectEngineState *de_state;
} SshState;

void RegisterSSHParsers(void);
void SSHParserRegisterTests(void);

#endif /* __APP_LAYER_SSH_H__ */

