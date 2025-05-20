/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Match on FTP reply received.
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "app-layer-ftp.h"

#include "detect-ftp-reply-received.h"

static void DetectFtpReplyReceivedFree(DetectEngineCtx *, void *);
static int g_ftp_reply_received_buffer_id = 0;

static int DetectFtpReplyReceivedMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *m)
{
    FTPTransaction *tx = (FTPTransaction *)txv;
    if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN) {
        return 0;
    }

    const DetectFtpReplyReceivedData *ftprrd = (const DetectFtpReplyReceivedData *)m;
    if (ftprrd->received == tx->done)
        return 1;

    return 0;
}

/**
 * \brief This function is used to parse ftp.reply_received options passed via ftp.reply_received
 * keyword
 *
 * \param str Pointer to the user provided ftp.reply_received options
 *
 * \retval  pointer to DetectFtpReplyReceivedData on success
 * \retval NULL on failure
 */
static DetectFtpReplyReceivedData *DetectFtpdataParse(const char *optstr)
{
    DetectFtpReplyReceivedData *frrd = SCFTPParseReplyReceived(optstr);
    if (unlikely(frrd == NULL)) {
        SCLogError("invalid value; specify yes or no");
        return NULL;
    }

    return frrd;
}

/**
 * \brief parse the options from the 'ftp.reply_received' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided ftp.reply_received options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFtpReplyReceivedSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectFtpReplyReceivedData *frrd = DetectFtpdataParse(str);
    if (frrd == NULL)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) != 0) {
        DetectFtpReplyReceivedFree(de_ctx, frrd);
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FTP_REPLY_RECEIVED, (SigMatchCtx *)frrd,
                g_ftp_reply_received_buffer_id) == NULL) {
        DetectFtpReplyReceivedFree(de_ctx, frrd);
        return -1;
    }
    return 0;
}

/**
 * \brief this function will free memory associated with DetectFtpReplyReceivedData
 *
 * \param ptr pointer to DetectFtpReplyReceivedData
 */
static void DetectFtpReplyReceivedFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr) {
        DetectFtpReplyReceivedData *frrd = (DetectFtpReplyReceivedData *)ptr;
        SCFTPFreeReplyReceivedData(frrd);
    }
}

/**
 * \brief Registration function for ftp.reply_received: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectFtpReplyReceivedRegister(void)
{
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].name = "ftp.reply_received";
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].desc = "match on FTP whether a reply was received";
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].url = "/rules/ftp-keywords.html#ftp.reply_received";
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].AppLayerTxMatch = DetectFtpReplyReceivedMatch;
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].Setup = DetectFtpReplyReceivedSetup;
    sigmatch_table[DETECT_FTP_REPLY_RECEIVED].Free = DetectFtpReplyReceivedFree;

    DetectAppLayerInspectEngineRegister("ftp.reply_received", ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);
    g_ftp_reply_received_buffer_id = DetectBufferTypeGetByName("ftp.reply_received");
}
