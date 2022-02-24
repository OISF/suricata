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
#include "detect-frame.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

static int DetectFrameSetup(DetectEngineCtx *, Signature *, const char *);

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
static int DetectFrameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    char value[256] = "";
    strlcpy(value, str, sizeof(value));

    const bool is_tcp = DetectProtoContainsProto(&s->proto, IPPROTO_TCP);
    const bool is_udp = DetectProtoContainsProto(&s->proto, IPPROTO_UDP);

    if (!(is_tcp || is_udp)) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "'frame' keyword only supported for TCP and UDP");
        return -1;
    }

    int raw_frame_type = -1;
    if (AppProtoIsValid(s->alproto)) {
        if (is_tcp)
            raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_TCP, s->alproto, str);
        if (is_udp && raw_frame_type < 0)
            raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_UDP, s->alproto, str);
        if (raw_frame_type < 0) {
            char *dot = strchr(value, '.');
            if (dot != NULL)
                *dot++ = '\0';
            const char *val = dot ? dot : value;
            const char *proto = dot ? value : NULL;
            if (proto != NULL) {
                const AppProto keyword_alproto = StringToAppProto(proto);
                if (!AppProtoEquals(s->alproto, keyword_alproto)) {
                    SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                            "frame '%s' mismatch with rule protocol '%s'", str,
                            AppProtoToString(s->alproto));
                    return -1;
                }
                if (DetectSignatureSetAppProto(s, keyword_alproto) < 0)
                    return -1;
            }
            if (is_tcp)
                raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_TCP, s->alproto, val);
            if (is_udp && raw_frame_type < 0)
                raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_UDP, s->alproto, val);
            if (raw_frame_type < 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "unknown frame '%s' for protocol '%s'",
                        val, proto);
                return -1;
            }
        }
    } else {
        char *dot = strchr(value, '.');
        if (dot != NULL)
            *dot++ = '\0';
        const char *val = dot ? dot : value;
        const char *proto = dot ? value : NULL;
        if (proto == NULL) {
            return -1;
        }

        AppProto alproto = StringToAppProto(proto);
        if (alproto == ALPROTO_UNKNOWN || alproto == ALPROTO_FAILED) {
            SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "unknown app proto '%s' for 'frame'", proto);
            return -1;
        }

        if (DetectSignatureSetAppProto(s, alproto) < 0)
            return -1;

        if (is_tcp)
            raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_TCP, s->alproto, val);
        if (is_udp && raw_frame_type < 0)
            raw_frame_type = AppLayerParserGetFrameIdByName(IPPROTO_UDP, s->alproto, val);
        if (raw_frame_type < 0) {
            SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "unknown frame '%s' for protocol '%s'", val,
                    proto);
            return -1;
        }
    }
    BUG_ON(raw_frame_type >= UINT8_MAX);

    uint8_t frame_type = (uint8_t)raw_frame_type;
    /* TODO we can have TS and TC specific frames */
    const int buffer_id = DetectEngineBufferTypeRegisterWithFrameEngines(
            de_ctx, str, SIG_FLAG_TOSERVER | SIG_FLAG_TOCLIENT, s->alproto, frame_type);
    if (buffer_id < 0)
        return -1;

    if (DetectBufferSetActiveList(s, buffer_id) < 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS

static int DetectFrameTestBadRules(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    const char *sigs[] = {
        "alert tcp-pkt any any -> any any (frame:tls.pdu; content:\"a\"; sid:1;)",
        "alert udp any any -> any any (frame:tls.pdu; content:\"a\"; sid:2;)",
        "alert smb any any -> any any (frame:tls.pdu; content:\"a\"; sid:3;)",
        "alert tcp any any -> any any (frame:tls; content:\"a\"; sid:4;)",
        "alert tls any any -> any any (content:\"abc\"; frame:tls.pdu; content:\"a\"; sid:5;)",
        "alert tls any any -> any any (tls.version:1.0; frame:tls.pdu; content:\"a\"; sid:6;)",
        "alert tls any any -> any any (frame:smb1.pdu; content:\"a\"; sid:7;)",
        NULL,
    };

    const char **sig = sigs;
    while (*sig) {
        SCLogDebug("sig %s", *sig);
        Signature *s = DetectEngineAppendSig(de_ctx, *sig);
        FAIL_IF_NOT_NULL(s);
        sig++;
    }

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectFrameRegisterTests(void)
{
    UtRegisterTest("DetectFrameTestBadRules", DetectFrameTestBadRules);
}
#endif

/**
 * \brief Registration function for keyword: ja3_hash
 */
void DetectFrameRegister(void)
{
    sigmatch_table[DETECT_FRAME].name = "frame";
    sigmatch_table[DETECT_FRAME].desc = "sticky buffer for inspecting app-layer frames";
    sigmatch_table[DETECT_FRAME].Setup = DetectFrameSetup;
    sigmatch_table[DETECT_FRAME].flags = SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FRAME].RegisterTests = DetectFrameRegisterTests;
#endif
}
