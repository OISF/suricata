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
 *
 * ftpbounce keyword, part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-content.h"
#include "detect-engine-build.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ftp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "threads.h"
#include "detect-ftpbounce.h"
#include "stream-tcp.h"
#include "util-byte.h"

static int DetectFtpbounceALMatch(DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);

static int DetectFtpbounceSetup(DetectEngineCtx *, Signature *, const char *);
static int g_ftp_request_list_id = 0;

/**
 * \brief Registration function for ftpbounce: keyword
 * \todo add support for no_stream and stream_only
 */
void DetectFtpbounceRegister(void)
{
    sigmatch_table[DETECT_FTPBOUNCE].name = "ftpbounce";
    sigmatch_table[DETECT_FTPBOUNCE].desc = "detect FTP bounce attacks";
    sigmatch_table[DETECT_FTPBOUNCE].Setup = DetectFtpbounceSetup;
    sigmatch_table[DETECT_FTPBOUNCE].AppLayerTxMatch = DetectFtpbounceALMatch;
    sigmatch_table[DETECT_FTPBOUNCE].url = "/rules/ftp-keywords.html#ftpbounce";
    sigmatch_table[DETECT_FTPBOUNCE].flags = SIGMATCH_NOOPT;

    g_ftp_request_list_id = DetectBufferTypeRegister("ftp_request");

    DetectAppLayerInspectEngineRegister(
            "ftp_request", ALPROTO_FTP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
}

/**
 * \brief This function is used to match ftpbounce attacks
 *
 * \param payload Payload of the PORT command
 * \param payload_len Length of the payload
 * \param ip_orig IP source to check the ftpbounce condition
 * \param offset offset to the arguments of the PORT command
 *
 * \retval 1 if ftpbounce detected, 0 if not
 */
static int DetectFtpbounceMatchArgs(
        uint8_t *payload, uint32_t payload_len, uint32_t ip_orig, uint32_t offset)
{
    SCEnter();
    SCLogDebug("Checking ftpbounce condition");
    char *c = NULL;
    uint32_t i = 0;
    int octet = 0;
    int octet_ascii_len = 0;
    int noctet = 0;
    uint32_t ip = 0;
    /* PrintRawDataFp(stdout, payload, payload_len); */

    if (payload_len < 7) {
        /* we need at least a different ip address
         * in the format 1,2,3,4,x,y where x,y is the port
         * in two byte representation so let's look at
         * least for the IP octets in comma separated */
        return 0;
    }

    if (offset + 7 >= payload_len)
        return 0;

    c =(char*) payload;
    if (c == NULL) {
        SCLogDebug("No payload to check");
        return 0;
    }

    i = offset;
    /* Search for the first IP octect(Skips "PORT ") */
    while (i < payload_len && !isdigit((unsigned char)c[i])) i++;

    for (;i < payload_len && octet_ascii_len < 4 ;i++) {
        if (isdigit((unsigned char)c[i])) {
            octet =(c[i] - '0') + octet * 10;
            octet_ascii_len++;
        } else {
            if (octet > 256) {
                SCLogDebug("Octet not in ip format");
                return 0;
            }

            if (isspace((unsigned char)c[i]))
                while (i < payload_len && isspace((unsigned char)c[i]) ) i++;

            if (i < payload_len && c[i] == ',') { /* we have an octet */
                noctet++;
                octet_ascii_len = 0;
                ip =(ip << 8) + octet;
                octet = 0;
            } else {
                SCLogDebug("Unrecognized character '%c'", c[i]);
                return 0;
            }
            if (noctet == 4) {
                /* Different IP than src, ftp bounce scan */
                ip = SCNtohl(ip);

                if (ip != ip_orig) {
                    SCLogDebug("Different ip, so Matched ip:%d <-> ip_orig:%d",
                               ip, ip_orig);
                    return 1;
                }
                SCLogDebug("Same ip, so no match here");
                return 0;
            }
        }
    }
    SCLogDebug("No match");
    return 0;
}

/**
 * \brief This function is used to check matches from the FTP App Layer Parser
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch but we don't use it since ftpbounce
 *          has no options
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFtpbounceALMatch(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags,
        void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    FtpState *ftp_state = (FtpState *)state;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    if (ftp_state->command == FTP_COMMAND_PORT) {
        ret = DetectFtpbounceMatchArgs(ftp_state->port_line,
                  ftp_state->port_line_len, f->src.address.address_un_data32[0],
                  ftp_state->arg_offset);
    }

    SCReturnInt(ret);
}

/**
 * \brief this function is used to add the parsed ftpbounce
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param ftpbouncestr pointer to the user provided ftpbounce options
 *                     currently there are no options.
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectFtpbounceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *ftpbouncestr)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_FTP) != 0)
        return -1;

    /* We don't need to allocate any data for ftpbounce here.
     *
     * TODO: As a suggestion, maybe we can add a flag in the flow
     * to set the stream as "bounce detected" for fast Match.
     * When you do a ftp bounce attack you usually use the same
     * communication control stream to "setup" various destinations
     * without breaking the connection, so I guess we can make it a bit faster
     * with a flow flag set lookup in the Match function.
     */

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_FTPBOUNCE, NULL, g_ftp_request_list_id) == NULL) {
        return -1;
    }
    SCReturnInt(0);
}
