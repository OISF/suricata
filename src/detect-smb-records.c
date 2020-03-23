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

#include "detect-smb-records.h"
#include "rust.h"

static int DetectNbssRecordSetup(DetectEngineCtx *, Signature *, const char *);
static int g_nbss_record_buffer_id = 0;
static int DetectSmb1RecordSetup(DetectEngineCtx *, Signature *, const char *);
static int g_smb1_record_buffer_id = 0;
static int DetectSmb2RecordSetup(DetectEngineCtx *, Signature *, const char *);
static int g_smb2_record_buffer_id = 0;

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
static int DetectNbssRecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_nbss_record_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}
static int DetectSmb1RecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_smb1_record_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}
static int DetectSmb2RecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_smb2_record_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

void DetectSmbRecordRegister(void)
{
    sigmatch_table[DETECT_SMB1_RECORD].name = "smb1.record";
    sigmatch_table[DETECT_SMB1_RECORD].desc = "sticky buffer for inspecting SMBv1 records";
    sigmatch_table[DETECT_SMB1_RECORD].Setup = DetectSmb1RecordSetup;
    sigmatch_table[DETECT_SMB1_RECORD].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_SMB1_RECORD].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    g_smb1_record_buffer_id = DetectBufferTypeRegister("smb1.record");
    SCLogNotice("g_smb1_record_buffer_id %d", g_smb1_record_buffer_id);

    DetectPduMpmRegister(
            "smb1.record", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, SMB1);
    DetectPduInspectEngineRegister("smb1.record", SIG_FLAG_TOSERVER,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, SMB1);

    DetectPduMpmRegister(
            "smb1.record", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, SMB1);
    DetectPduInspectEngineRegister("smb1.record", SIG_FLAG_TOCLIENT,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, SMB1);

    sigmatch_table[DETECT_SMB2_RECORD].name = "smb2.record";
    sigmatch_table[DETECT_SMB2_RECORD].desc = "sticky buffer for inspecting SMBv2 records";
    sigmatch_table[DETECT_SMB2_RECORD].Setup = DetectSmb2RecordSetup;
    sigmatch_table[DETECT_SMB2_RECORD].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_SMB2_RECORD].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    g_smb2_record_buffer_id = DetectBufferTypeRegister("smb2.record");
    SCLogNotice("g_smb2_record_buffer_id %d", g_smb2_record_buffer_id);

    DetectPduMpmRegister(
            "smb2.record", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, SMB2);
    DetectPduInspectEngineRegister("smb2.record", SIG_FLAG_TOSERVER,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, SMB2);

    DetectPduMpmRegister(
            "smb2.record", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, SMB2);
    DetectPduInspectEngineRegister("smb2.record", SIG_FLAG_TOCLIENT,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, SMB2);

    sigmatch_table[DETECT_NBSS_RECORD].name = "nbss.record";
    sigmatch_table[DETECT_NBSS_RECORD].desc = "sticky buffer for inspecting NBSS records";
    sigmatch_table[DETECT_NBSS_RECORD].Setup = DetectNbssRecordSetup;
    sigmatch_table[DETECT_NBSS_RECORD].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_NBSS_RECORD].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    g_nbss_record_buffer_id = DetectBufferTypeRegister("nbss.record");
    SCLogNotice("g_nbss_record_buffer_id %d", g_nbss_record_buffer_id);

    DetectPduMpmRegister(
            "nbss.record", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, NBSS);
    DetectPduInspectEngineRegister("nbss.record", SIG_FLAG_TOSERVER,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, NBSS);

    DetectPduMpmRegister(
            "nbss.record", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmPduRegister, ALPROTO_SMB, NBSS);
    DetectPduInspectEngineRegister("nbss.record", SIG_FLAG_TOCLIENT,
            DetectEngineInspectPduBufferGeneric, ALPROTO_SMB, NBSS);
}
