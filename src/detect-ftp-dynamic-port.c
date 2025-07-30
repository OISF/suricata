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
 *
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements the ftp.dynamic_port sticky buffer
 *
 */

#include "suricata-common.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-content.h"

#include "flow.h"

#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-ftp.h"

#include "detect-ftp-dynamic-port.h"

#define KEYWORD_NAME "ftp.dynamic_port"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-dynamic_port"
#define BUFFER_NAME  "ftp.dynamic_port"
#define BUFFER_DESC  "ftp dynamic_port"

static int g_ftp_dynport_buffer_id = 0;

static DetectU16Data *DetectFtpDynamicPortParse(const char *rawstr)
{
    return SCDetectU16Parse(rawstr);
}

static void DetectFtpDynamicPortFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU16Free(ptr);
}

static int DetectFtpDynamicPortSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) < 0)
        return -1;

    DetectU16Data *fdp = DetectFtpDynamicPortParse(str);
    if (fdp == NULL) {
        SCLogError("parsing dynamic port from \"%s\" failed", str);
        return -1;
    }

    SCLogDebug("low %u hi %u", fdp->arg1, fdp->arg2);
    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FTP_DYNPORT, (SigMatchCtx *)fdp,
                g_ftp_dynport_buffer_id) == NULL) {
        DetectFtpDynamicPortFree(de_ctx, fdp);
        return -1;
    }
    return 0;
}

static int DetectFtpDynamicPortMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    FTPTransaction *tx = (FTPTransaction *)txv;
    if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN)
        return 0;

    const DetectU16Data *ftpd = (const DetectU16Data *)ctx;

    SCLogDebug("Checking for match between rule value(s) %u, %u with actual value %d", ftpd->arg1,
            ftpd->arg2, tx->dyn_port);
    return DetectU16Match(tx->dyn_port, ftpd);
}

void DetectFtpDynamicPortRegister(void)
{
    /* ftp.dynamic_port sticky buffer */
    sigmatch_table[DETECT_FTP_DYNPORT].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_DYNPORT].desc = "match on the FTP dynamic_port buffer";
    sigmatch_table[DETECT_FTP_DYNPORT].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_DYNPORT].Setup = DetectFtpDynamicPortSetup;
    sigmatch_table[DETECT_FTP_DYNPORT].Free = DetectFtpDynamicPortFree;
    sigmatch_table[DETECT_FTP_DYNPORT].flags = SIGMATCH_INFO_UINT16;
    sigmatch_table[DETECT_FTP_DYNPORT].AppLayerTxMatch = DetectFtpDynamicPortMatch;

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_dynport_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
