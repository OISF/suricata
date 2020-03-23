/* Copyright (C) 2021 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-engine-content-inspection.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-records.h"
#include "app-layer-ssl.h"

#include "detect-tls-record.h"

static int DetectTlsRecordSetup(DetectEngineCtx *, Signature *, const char *);
static int g_tls_record_buffer_id = 0;

/**
 * \brief this function setup the sticky buffer used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsRecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_record_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

/**
 * \brief Registration function for keyword: ja3_hash
 */
void DetectTlsRecordRegister(void)
{
    sigmatch_table[DETECT_TLS_RECORD].name = "tls.record";
    sigmatch_table[DETECT_TLS_RECORD].desc = "sticky buffer for inspecting TLS records";
    sigmatch_table[DETECT_TLS_RECORD].Setup = DetectTlsRecordSetup;
    sigmatch_table[DETECT_TLS_RECORD].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_TLS_RECORD].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    g_tls_record_buffer_id = DetectBufferTypeRegister("tls.record");
    SCLogNotice("g_tls_record_buffer_id %d", g_tls_record_buffer_id);

    DetectPduMpmRegister("tls.record", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmPduRegister,
            ALPROTO_TLS, TLS_RECORD_PDU);
    DetectPduInspectEngineRegister("tls.record", SIG_FLAG_TOSERVER,
            DetectEngineInspectPduBufferGeneric, ALPROTO_TLS, TLS_RECORD_PDU);

    DetectPduMpmRegister("tls.record", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmPduRegister,
            ALPROTO_TLS, TLS_RECORD_PDU);
    DetectPduInspectEngineRegister("tls.record", SIG_FLAG_TOCLIENT,
            DetectEngineInspectPduBufferGeneric, ALPROTO_TLS, TLS_RECORD_PDU);
}
