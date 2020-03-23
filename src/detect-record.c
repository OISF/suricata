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

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-engine-content-inspection.h"
#include "detect-record.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

static int DetectRecordSetup(DetectEngineCtx *, Signature *, const char *);

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
static int DetectRecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    char value[256] = "";
    strlcpy(value, str, sizeof(value));

    char *dot = strchr(value, '.');
    BUG_ON(!dot);
    *dot++ = '\0';
    const char *val = dot;
    const char *proto = value;

    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_TCP)))
        return -1;

    AppProto alproto = StringToAppProto(proto);
    if (alproto == ALPROTO_UNKNOWN || alproto == ALPROTO_FAILED)
        return -1;

    int raw_rec_type = AppLayerParserGetRecordIdByName(IPPROTO_TCP, alproto, val);
    if (raw_rec_type < 0) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "unknown record '%s' for protocol '%s'", val, proto);
        return -1;
    }
    BUG_ON(raw_rec_type >= UINT8_MAX);

    if (DetectSignatureSetAppProto(s, alproto) < 0)
        return -1;

    uint8_t rec_type = (uint8_t)raw_rec_type;
    /* TODO we can have TS and TC specific recs */
    const int buffer_id = DetectEngineBufferTypeRegisterWithRecordEngines(de_ctx, str, SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT, alproto, rec_type);
    if (buffer_id < 0)
        return -1;
    SCLogNotice("proto %s value %s => buffer_id %d", proto, val, buffer_id);

    if (DetectBufferSetActiveList(s, buffer_id) < 0)
        return -1;

    return 0;
}

/**
 * \brief Registration function for keyword: ja3_hash
 */
void DetectRecordRegister(void)
{
    sigmatch_table[DETECT_RECORD].name = "record";
    sigmatch_table[DETECT_RECORD].desc = "sticky buffer for inspecting app-layer records";
    sigmatch_table[DETECT_RECORD].Setup = DetectRecordSetup;
    sigmatch_table[DETECT_RECORD].flags = SIGMATCH_INFO_STICKY_BUFFER;
}
