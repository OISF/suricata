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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * App-layer parser for SSH protocol
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"

#include "conf.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-private.h"

#include "util-byte.h"
#include "util-memcmp.h"

#if 0
/**
 * \brief Function to parse the SSH version string of the server
 *
 *  \param  ssh_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSHParseServerVersion(Flow *f, void *ssh_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output) {
    uint8_t *line_ptr = input;
    uint32_t line_len = input_len;
    uint32_t offset = 0;

    SshState *state = (SshState *)ssh_state;

    while (input_len > 0) {
        offset = 0;

        if (pstate->store_len > 0){
            const uint8_t delim[] = { 0x0a, };
            int r = AlpParseFieldByDelimiter(output, pstate,
                            SSH_FIELD_SERVER_VER_STATE_LINE, delim, sizeof(delim),
                            input, input_len, &offset);

            if (r == 0)
                SCReturnInt(0);

            /* process the result elements */
            AppLayerParserResultElmt *e = output->head;
            line_ptr = NULL;
            line_len = 0;
            for (; e != NULL; e = e->next) {
                SCLogDebug("e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len "
                           "%" PRIu32, e, e->name_idx,
                           e->data_ptr, e->data_len);

                /* no parser defined for this field. */
                if (e->name_idx != SSH_FIELD_SERVER_VER_STATE_LINE) {
                    continue;
                }

                line_ptr = e->data_ptr;
                line_len = e->data_len;
            }

            /* Update for the next round */
            input_len -= offset;
            input += offset;

            if (line_ptr == NULL)
                continue;
        } else {
            const uint8_t delim[] = { 0x0a, };
            int r = AlpParseFieldByDelimiter(output, pstate,
                            SSH_FIELD_SERVER_VER_STATE_LINE, delim, sizeof(delim),
                            input, input_len, &offset);

            if (r == 0)
                SCReturnInt(0);

            /* Temporal pointer / len for the current line */
            line_ptr = input;
            line_len = offset;

            /* Update for the next round */
            input_len -= offset;
            input += offset;
        }

        //printf("INPUT: \n");
        //PrintRawDataFp(stdout, line_ptr, line_len);

        if (line_len < 5) {
            SCLogDebug("This is not the version line we are searching for (probably a banner or informational messages)");
            continue;
        }

        /* is it the version line? */
        if (SCMemcmp("SSH-", line_ptr, 4) == 0) {
            if (line_len > 255) {
                SCLogDebug("Invalid version string, it should be less than 255 characters including <CR><NL>");
                SCReturnInt(-1);
            }

            /* ok, we have found the version line/string, skip it and parse proto version */
            line_ptr += 4;
            line_len -= 4;
        } else {
            SCLogDebug("This is not the version line we are searching for (probably a banner or informational messages)");
            continue;
        }

        uint8_t *proto_end = BasicSearch(line_ptr, line_len, (uint8_t*)"-", 1);
        if (proto_end == NULL) {
            /* Strings starting with SSH- are not allowed
             * if they are not the real version string */
            SCLogDebug("Invalid Version String for SSH (invalid usage of SSH- prefix)");
            SCReturnInt(-1);
        }

        uint64_t proto_ver_len = (uint64_t)(proto_end - line_ptr);
        state->server_proto_version = SCMalloc(proto_ver_len + 1);
        if (state->server_proto_version == NULL) {
            SCReturnInt(-1);
        }
        memcpy(state->server_proto_version, line_ptr, proto_ver_len);
        state->server_proto_version[proto_ver_len] = '\0';

        /* Now lets parse the software & version */
        line_ptr += proto_ver_len + 1;
        line_len -= proto_ver_len + 1;
        if (line_len < 1) {
            SCLogDebug("No software version specified (weird)");
            state->flags |= SSH_FLAG_CLIENT_VERSION_PARSED;
            /* Return the remaining length */
            SCReturnInt(input_len);
        }

        uint8_t *sw_end = BasicSearch(line_ptr, line_len, (uint8_t*)" ", 1);
        if (sw_end == NULL) {
            sw_end = BasicSearch(line_ptr, line_len, (uint8_t*)"\r", 1);
            if (sw_end == NULL) {
                sw_end = line_ptr + line_len;
            }
        }

        uint64_t sw_ver_len = (uint64_t)(sw_end - line_ptr);
        state->server_software_version = SCMalloc(sw_ver_len + 1);
        if (state->server_software_version == NULL) {
            SCReturnInt(-1);
        }
        memcpy(state->server_software_version, line_ptr, sw_ver_len);
        state->server_software_version[sw_ver_len] = '\0';
        if (state->server_software_version[sw_ver_len - 1] == 0x0d)
            state->server_software_version[sw_ver_len - 1] = '\0';

        state->flags |= SSH_FLAG_SERVER_VERSION_PARSED;
        /* Return the remaining length */
        SCReturnInt(input_len);
    }

    SCReturnInt(0);
}

/**
 * \brief Function to parse the SSH field in packet received from the server
 *
 *  \param  ssh_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSHParseServerRecord(Flow *f, void *ssh_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                void *local_data, AppLayerParserResult *output)
{
    SshState *state = (SshState *)ssh_state;
    if (state->flags & SSH_FLAG_PARSER_DONE) {
        SCReturnInt(0);
    }

    SCEnter();
    int ret = 0;

    SCLogDebug("ssh_state %p, pstate %p, input %p,input_len %" PRIu32 "",
            ssh_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    if ( !(state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        ret = SSHParseServerVersion(f, ssh_state, pstate, input, input_len, output);
        if (ret < 0) {
            SCLogDebug("Invalid version string");
            SCReturnInt(-1);
        } else if (state->flags & SSH_FLAG_SERVER_VERSION_PARSED) {
            SCLogDebug("Version string parsed");
            input += input_len - ret;
            input_len -= (input_len - ret);
            pstate->parse_field = 1;
            ret = 1;
            if (input_len == 0)
                SCReturnInt(ret);
        } else {
            SCLogDebug("Version string not parsed yet");
            pstate->parse_field = 0;
            SCReturnInt(ret);
        }
    } else {
            SCLogDebug("Version string already parsed");
    }

    uint16_t max_fields = 4;
    int16_t u = 0;
    uint32_t offset = 0;

    //PrintRawDataFp(stdout, input,input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u % 4) {
            case 0:
            {
                continue;
            }
            case 1: /* TLS CONTENT TYPE */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            SSH_FIELD_SERVER_PKT_LENGTH,
                                            /* single byte field */4, data,
                                            data_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 1;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                uint32_t pkt_len = 0;
                int ret = ByteExtractUint32(&pkt_len, BYTE_BIG_ENDIAN,
                        output->tail->data_len, output->tail->data_ptr);
                if (ret != 4) {
                    SCReturnInt(-1);
                }
                state->srv_hdr.pkt_len = pkt_len;
                SCLogDebug("pkt len: %"PRIu32, pkt_len);

                break;
            }
            case 2: /* TLS VERSION */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            SSH_FIELD_SERVER_PADDING_LENGTH,
                                            /* 2 byte field */1, data, data_len,
                                            &offset);
                if (r == 0) {
                    pstate->parse_field = 2;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }
                uint8_t padding_len = 0;
                if (output->tail->data_len == 1) {
                    padding_len = (uint8_t) *output->tail->data_ptr;
                    SCLogDebug("padding len: %"PRIu8, padding_len);
                }
                state->srv_hdr.padding_len = padding_len;

                break;
            }
            case 3: /* SSH_PAYLOAD */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                /* we add a -1 to the pkt len since the padding length is already parsed */
                int r = AlpParseFieldBySize(output, pstate, SSH_FIELD_SERVER_PAYLOAD,
                                            state->srv_hdr.pkt_len - 1, data, data_len,
                                            &offset);
                SCLogDebug("AlpParseFieldBySize returned r %d, offset %"PRIu32,
                           r, offset);
                if (r == 0) {
                    pstate->parse_field = 3;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                uint8_t msg_code = 0;
                if (output->tail->data_len >= 1) {
                    msg_code = (uint8_t) *output->tail->data_ptr;
                    SCLogDebug("msg code: %"PRIu8, msg_code);
                }
                state->srv_hdr.msg_code = msg_code;

                if (state->srv_hdr.msg_code == SSH_MSG_NEWKEYS) {
                    /* We are not going to inspect any packet more
                     * as the data is now encrypted */
                    SCLogDebug("SSH parser done (the rest of the communication is encrypted)");
                    state->flags |= SSH_FLAG_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
                    pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
                    pstate->parse_field = 1;
                    SCReturnInt(1);
                }

                pstate->parse_field = 1;
                ret = 1;

                /* If we have remaining data, continue processing */
                if ((int)input_len - (int)offset > 0) {
                    u = 0;
                }
                break;
            }
        }

    }

    SCReturnInt(ret);
}

/**
 * \brief Function to parse the SSH version string of the client
 *
 *  \param  ssh_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSHParseClientVersion(Flow *f, void *ssh_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output) {
    uint8_t *line_ptr = input;
    uint32_t line_len = input_len;
    uint32_t offset = 0;

    SshState *state = (SshState *)ssh_state;

    while (input_len > 0) {
        offset = 0;


        if (pstate->store_len > 0){
            const uint8_t delim[] = { 0x0a, };
            int r = AlpParseFieldByDelimiter(output, pstate,
                            SSH_FIELD_CLIENT_VER_STATE_LINE, delim, sizeof(delim),
                            input, input_len, &offset);

            if (r == 0)
                SCReturnInt(0);

            /* process the result elements */
            AppLayerParserResultElmt *e = output->head;
            line_ptr = NULL;
            line_len = 0;
            for (; e != NULL; e = e->next) {
                SCLogDebug("e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len "
                           "%" PRIu32, e, e->name_idx,
                           e->data_ptr, e->data_len);

                /* no parser defined for this field. */
                if (e->name_idx != SSH_FIELD_CLIENT_VER_STATE_LINE) {
                    continue;
                }

                line_ptr = e->data_ptr;
                line_len = e->data_len;
            }

            /* Update for the next round */
            input_len -= offset;
            input += offset;

            if (line_ptr == NULL)
                continue;
        } else {
            const uint8_t delim[] = { 0x0a, };
            int r = AlpParseFieldByDelimiter(output, pstate,
                            SSH_FIELD_CLIENT_VER_STATE_LINE, delim, sizeof(delim),
                            input, input_len, &offset);

            if (r == 0)
                SCReturnInt(0);

            /* Temporal pointer / len for the current line */
            line_ptr = input;
            line_len = offset;

            /* Update for the next round */
            input_len -= offset;
            input += offset;
        }

        //PrintRawDataFp(stdout, line_ptr, line_len);

        if (line_len < 5) {
            SCLogDebug("This is not the version line we are searching for (probably a banner or informational messages)");
            continue;
        }

        /* is it the version line? */
        if (SCMemcmp("SSH-", line_ptr, 4) == 0) {
            if (line_len > 255) {
                SCLogDebug("Invalid version string, it should be less than 255 characters including <CR><NL>");
                SCReturnInt(-1);
            }

            /* ok, we have found the version line/string, skip it and parse proto version */
            line_ptr += 4;
            line_len -= 4;
        } else {
            SCLogDebug("This is not the version line we are searching for (probably a banner or informational messages)");
            continue;
        }

        uint8_t *proto_end = BasicSearch(line_ptr, line_len, (uint8_t*)"-", 1);
        if (proto_end == NULL) {
            /* Strings starting with SSH- are not allowed
             * if they are not the real version string */
            SCLogDebug("Invalid Version String for SSH (invalid usage of SSH- prefix)");
            SCReturnInt(-1);
        }

        uint64_t proto_ver_len = (uint64_t)(proto_end - line_ptr);
        state->client_proto_version = SCMalloc(proto_ver_len + 1);
        if (state->client_proto_version == NULL) {
            SCReturnInt(-1);
        }
        memcpy(state->client_proto_version, line_ptr, proto_ver_len);
        state->client_proto_version[proto_ver_len] = '\0';

        /* Now lets parse the software & version */
        line_ptr += proto_ver_len + 1;
        line_len -= proto_ver_len + 1;
        if (line_len < 1) {
            SCLogDebug("No software version specified (weird)");
            state->flags |= SSH_FLAG_CLIENT_VERSION_PARSED;
            /* Return the remaining length */
            SCReturnInt(input_len);
        }

        uint8_t *sw_end = BasicSearch(line_ptr, line_len, (uint8_t*)" ", 1);
        if (sw_end == NULL) {
            sw_end = BasicSearch(line_ptr, line_len, (uint8_t*)"\r", 1);
            if (sw_end == NULL) {
                sw_end = line_ptr + line_len;
            }
        }

        uint64_t sw_ver_len = (uint64_t)(sw_end - line_ptr);
        state->client_software_version = SCMalloc(sw_ver_len + 1);
        if (state->client_software_version == NULL) {
            SCReturnInt(-1);
        }
        memcpy(state->client_software_version, line_ptr, sw_ver_len);
        state->client_software_version[sw_ver_len] = '\0';
        if (state->client_software_version[sw_ver_len - 1] == 0x0d)
            state->client_software_version[sw_ver_len - 1] = '\0';

        state->flags |= SSH_FLAG_CLIENT_VERSION_PARSED;
        /* Return the remaining length */
        SCReturnInt(input_len);
    }

    SCReturnInt(0);
}

/**
 * \brief Function to parse the SSH field in packet received from the client
 *
 *  \param  ssh_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSHParseClientRecord(Flow *f, void *ssh_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                void *local_data, AppLayerParserResult *output)
{
    SshState *state = (SshState *)ssh_state;
    if (state->flags & SSH_FLAG_PARSER_DONE) {
        SCReturnInt(0);
    }

    SCEnter();
    int ret = 0;

    SCLogDebug("ssh_state %p, pstate %p, input %p,input_len %" PRIu32 "",
            ssh_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    if ( !(state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        ret = SSHParseClientVersion(f, ssh_state, pstate, input, input_len, output);
        if (ret < 0) {
            SCLogDebug("Invalid version string");
            SCReturnInt(-1);
        } else if (state->flags & SSH_FLAG_CLIENT_VERSION_PARSED) {
            SCLogDebug("Version string parsed");
            input += input_len - ret;
            input_len -= (input_len - ret);
            pstate->parse_field = 1;
            ret = 1;
        } else {
            SCLogDebug("Version string not parsed yet");
            pstate->parse_field = 0;
            SCReturnInt(0);
        }
    } else {
            SCLogDebug("Version string already parsed");
    }

    uint16_t max_fields = 4;
    int16_t u = 0;
    uint32_t offset = 0;

    //printf("INPUT: \n");
    //PrintRawDataFp(stdout, input,input_len);

    if (pstate == NULL)
        SCReturnInt(-1);

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u % 4) {
            case 0:
            {
                continue;
            }
            case 1: /* TLS CONTENT TYPE */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            SSH_FIELD_CLIENT_PKT_LENGTH,
                                            /* single byte field */4, data,
                                            data_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 1;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                uint32_t pkt_len = 0;
                int ret = ByteExtractUint32(&pkt_len, BYTE_BIG_ENDIAN,
                        output->tail->data_len, output->tail->data_ptr);
                if (ret != 4) {
                    SCReturnInt(-1);
                }
                state->cli_hdr.pkt_len = pkt_len;
                SCLogDebug("pkt len: %"PRIu32"\n", pkt_len);

                break;
            }
            case 2: /* TLS VERSION */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            SSH_FIELD_CLIENT_PADDING_LENGTH,
                                            /* 2 byte field */1, data, data_len,
                                            &offset);
                if (r == 0) {
                    pstate->parse_field = 2;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }
                uint8_t padding_len = 0;
                if (output->tail->data_len == 1) {
                    padding_len = (uint8_t) *output->tail->data_ptr;
                    SCLogDebug("padding len: %"PRIu8, padding_len);
                }
                state->cli_hdr.padding_len = padding_len;

                break;
            }
            case 3: /* SSH_PAYLOAD */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                /* we add a -1 to the pkt len since the padding length is already parsed */
                int r = AlpParseFieldBySize(output, pstate, SSH_FIELD_CLIENT_PAYLOAD,
                                            /* 1 byte field */ state->cli_hdr.pkt_len - 1, data, data_len,
                                            &offset);
                SCLogDebug("AlpParseFieldBySize returned r %d, offset %"PRIu32,
                           r, offset);
                if (r == 0) {
                    pstate->parse_field = 3;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                uint8_t msg_code = 0;
                if (output->tail->data_len >= 1) {
                    msg_code = (uint8_t) *output->tail->data_ptr;
                    SCLogDebug("msg code: %"PRIu8, msg_code);
                }

                state->cli_hdr.msg_code = msg_code;
                if (state->cli_hdr.msg_code == SSH_MSG_NEWKEYS) {
                    /* We are not going to inspect any packet more
                     * as the data is now encrypted */
                    SCLogDebug("SSH parser done (the rest of the communication is encrypted)");
                    state->flags |= SSH_FLAG_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
                    pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
                    pstate->parse_field = 1;
                    SCReturnInt(1);
                }

                pstate->parse_field = 1;
                ret = 1;

                /* If we have remaining data, continue processing */
                if (input_len - offset > 0) {
                    u = 0;
                }

                break;
            }
        }

    }

    SCReturnInt(ret);
}
#endif

static int SSHParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
                           uint8_t *input, uint32_t input_len,
                           void *local_data)
{
    PrintRawDataFp(stdout, input, input_len);
    return 0;
}

static int SSHParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
                            uint8_t *input, uint32_t input_len,
                            void *local_data)
{
    PrintRawDataFp(stdout, input, input_len);
    return 0;
}

/** \brief Function to allocates the SSH state memory
 */
static void *SSHStateAlloc(void)
{
    void *s = SCMalloc(sizeof(SshState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(SshState));
    return s;
}

/** \brief Function to free the SSH state memory
 */
static void SSHStateFree(void *state)
{
    SshState *s = (SshState *)state;
    if (s->client_proto_version != NULL)
        SCFree(s->client_proto_version);
    if (s->client_software_version != NULL)
        SCFree(s->client_software_version);
    if (s->server_proto_version != NULL)
        SCFree(s->server_proto_version);
    if (s->server_software_version != NULL)
        SCFree(s->server_software_version);

    SCFree(s);
}

static int SSHRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SSH,
                                               "SSH-", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SSH,
                                               "SSH-", 4, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    return 0;
}

/** \brief Function to register the SSH protocol parsers and other functions
 */
void RegisterSSHParsers(void)
{
    char *proto_name = "ssh";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_SSH, proto_name);
        if (SSHRegisterPatternsForProtocolDetection() < 0)
            return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SSH, STREAM_TOSERVER,
                                     SSHParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SSH, STREAM_TOCLIENT,
                                     SSHParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SSH, SSHStateAlloc, SSHStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP,
                ALPROTO_SSH, STREAM_TOSERVER|STREAM_TOCLIENT);
    } else {
//        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
//                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SSH, SSHParserRegisterTests);
#endif
}

/* UNITTESTS */
#ifdef UNITTESTS

/** \test Send a version string in one chunk (client version str). */
static int SSHParserTest01(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER|STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a version string in one chunk but multiple lines and comments.
 *        (client version str)
 */
static int SSHParserTest02(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "lalala\n lal al al\nSSH-2.0-MySSHClient-0.5.1 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER|STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a invalid version string in one chunk but multiple lines and comments.
 *        (client version str)
 */
static int SSHParserTest03(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "lalala\n lal al al\nSSH-2.0 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER|STREAM_EOF, sshbuf, sshlen);
    if (r == 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected != 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* Ok, it returned an error. Let's make sure we didn't parse the string at all */

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if (ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED) {
        printf("Client version string parsed? It's not a valid string: ");
        result = 0;
        goto end;
    }

    if (ssh_state->client_proto_version != NULL) {
        result = 0;
        goto end;
    }

    if (ssh_state->client_software_version != NULL) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a version string in one chunk (server version str). */
static int SSHParserTest04(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT|STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a version string in one chunk but multiple lines and comments.
 *        (server version str)
 */
static int SSHParserTest05(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "lalala\n lal al al\nSSH-2.0-MySSHClient-0.5.1 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT|STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a invalid version string in one chunk but multiple lines and comments.
 *        (server version str)
 */
static int SSHParserTest06(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "lalala\n lal al al\nSSH-2.0 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT|STREAM_EOF, sshbuf, sshlen);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected != 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* Ok, it returned an error. Let's make sure we didn't parse the string at all */

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        result = 0;
        goto end;
    }

    if (ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED) {
        printf("Client version string parsed? It's not a valid string: ");
        result = 0;
        goto end;
    }

    if (ssh_state->server_proto_version != NULL) {
        result = 0;
        goto end;
    }

    if (ssh_state->server_software_version != NULL) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

static int SSHParserTest07(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-2.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = { "0-MySSHClient-0.5.1\r\n"};
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a version banner in three chunks. */
static int SSHParserTest08(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { "0-MySSHClient-0.5.1\r\n"};
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

static int SSHParserTest09(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-2.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = { "0-MySSHClient-0.5.1\r\n"};
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a version banner in three chunks. */
static int SSHParserTest10(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { "0-MySSHClient-0.5.1\r\n"};
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a banner and record in three chunks. */
static int SSHParserTest11(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};
    uint32_t sshlen3 = sizeof(sshbuf3);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_PARSER_DONE)) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a banner and 2 records record in four chunks. */
static int SSHParserTest12(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 17, 0x00};
    uint32_t sshlen3 = sizeof(sshbuf3);
    uint8_t sshbuf4[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};
    uint32_t sshlen4 = sizeof(sshbuf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_CLIENT_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->client_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->client_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_PARSER_DONE)) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send toserver a banner and record in three chunks. */
static int SSHParserTest13(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};
    uint32_t sshlen3 = sizeof(sshbuf3);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_PARSER_DONE)) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send toserver a banner and 2 records record in four chunks. */
static int SSHParserTest14(void) {
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "Welcome to this ssh server\nSSH-";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 17, 0x00};
    uint32_t sshlen3 = sizeof(sshbuf3);
    uint8_t sshbuf4[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};
    uint32_t sshlen4 = sizeof(sshbuf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOCLIENT, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_SERVER_VERSION_PARSED)) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_software_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (ssh_state->server_proto_version == NULL) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_software_version, "MySSHClient-0.5.1", strlen("MySSHClient-0.5.1")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if (strncmp((char*)ssh_state->server_proto_version, "2.0", strlen("2.0")) != 0) {
        printf("Client version string not parsed correctly: ");
        goto end;
    }

    if ( !(ssh_state->flags & SSH_FLAG_PARSER_DONE)) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif /* UNITTESTS */

void SSHParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("SSHParserTest01 - ToServer", SSHParserTest01, 1);
    UtRegisterTest("SSHParserTest02 - ToServer", SSHParserTest02, 1);
    UtRegisterTest("SSHParserTest03 - ToServer", SSHParserTest03, 1);
    UtRegisterTest("SSHParserTest04 - ToClient", SSHParserTest04, 1);
    UtRegisterTest("SSHParserTest05 - ToClient", SSHParserTest05, 1);
    UtRegisterTest("SSHParserTest06 - ToClient", SSHParserTest06, 1);
    UtRegisterTest("SSHParserTest07 - ToServer 2 chunks", SSHParserTest07, 1);
    UtRegisterTest("SSHParserTest08 - ToServer 3 chunks", SSHParserTest08, 1);
    UtRegisterTest("SSHParserTest09 - ToClient 2 chunks", SSHParserTest09, 1);
    UtRegisterTest("SSHParserTest10 - ToClient 3 chunks", SSHParserTest10, 1);
    UtRegisterTest("SSHParserTest11 - ToClient 4 chunks", SSHParserTest11, 1);
    UtRegisterTest("SSHParserTest12 - ToClient 4 chunks", SSHParserTest12, 1);
    UtRegisterTest("SSHParserTest13 - ToClient 4 chunks", SSHParserTest13, 1);
    UtRegisterTest("SSHParserTest14 - ToClient 4 chunks", SSHParserTest14, 1);
#endif /* UNITTESTS */
}

