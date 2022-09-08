/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Performs payload matching functions
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-state.h"
#include "detect-engine-payload.h"
#include "detect-engine-build.h"

#include "stream.h"
#include "stream-tcp.h"

#include "util-debug.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"
#include "util-profiling.h"
#include "util-mpm-ac.h"

struct StreamMpmData {
    DetectEngineThreadCtx *det_ctx;
    const MpmCtx *mpm_ctx;
};

static int StreamMpmFunc(
        void *cb_data, const uint8_t *data, const uint32_t data_len, const uint64_t _offset)
{
    struct StreamMpmData *smd = cb_data;
    if (data_len >= smd->mpm_ctx->minlen) {
#ifdef DEBUG
        smd->det_ctx->stream_mpm_cnt++;
        smd->det_ctx->stream_mpm_size += data_len;
#endif
        (void)mpm_table[smd->mpm_ctx->mpm_type].Search(smd->mpm_ctx,
                &smd->det_ctx->mtcs, &smd->det_ctx->pmq,
                data, data_len);
        PREFILTER_PROFILING_ADD_BYTES(smd->det_ctx, data_len);
    }
    return 0;
}

static void PrefilterPktStream(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;

    /* for established packets inspect any stream we may have queued up */
    if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
        SCLogDebug("PRE det_ctx->raw_stream_progress %"PRIu64,
                det_ctx->raw_stream_progress);
        struct StreamMpmData stream_mpm_data = { det_ctx, mpm_ctx };
        StreamReassembleRaw(p->flow->protoctx, p,
                StreamMpmFunc, &stream_mpm_data,
                &det_ctx->raw_stream_progress,
                false /* mpm doesn't use min inspect depth */);
        SCLogDebug("POST det_ctx->raw_stream_progress %"PRIu64,
                det_ctx->raw_stream_progress);

        /* packets that have not been added to the stream will be inspected as if they are stream
         * chunks */
    } else if ((p->flags & (PKT_NOPAYLOAD_INSPECTION | PKT_STREAM_ADD)) == 0) {
        if (p->payload_len >= mpm_ctx->minlen) {
#ifdef DEBUG
            det_ctx->payload_mpm_cnt++;
            det_ctx->payload_mpm_size += p->payload_len;
#endif
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtc, &det_ctx->pmq,
                    p->payload, p->payload_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, p->payload_len);
        }
    }
}

int PrefilterPktStreamRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    return PrefilterAppendPayloadEngine(de_ctx, sgh,
            PrefilterPktStream, mpm_ctx, NULL, "stream");
}

static void PrefilterPktPayload(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    if (p->payload_len < mpm_ctx->minlen)
        SCReturn;

    (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
            &det_ctx->mtc, &det_ctx->pmq,
            p->payload, p->payload_len);

    PREFILTER_PROFILING_ADD_BYTES(det_ctx, p->payload_len);
}

int PrefilterPktPayloadRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    return PrefilterAppendPayloadEngine(de_ctx, sgh,
            PrefilterPktPayload, mpm_ctx, NULL, "payload");
}


/**
 *  \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param f flow (for pcre flowvar storage)
 *  \param p Packet
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
uint8_t DetectEngineInspectPacketPayload(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f, Packet *p)
{
    SCEnter();
    int r = 0;

    if (s->sm_arrays[DETECT_SM_LIST_PMATCH] == NULL) {
        SCReturnInt(0);
    }
#ifdef DEBUG
    det_ctx->payload_persig_cnt++;
    det_ctx->payload_persig_size += p->payload_len;
#endif
    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;

    r = DetectEngineContentInspection(de_ctx, det_ctx,
            s, s->sm_arrays[DETECT_SM_LIST_PMATCH],
            p, f, p->payload, p->payload_len, 0,
            DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD);
    if (r == 1) {
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Do the content inspection & validation for a sigmatch list
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param smd array of matches to eval
 *  \param f flow (for pcre flowvar storage)
 *  \param p Packet
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
static uint8_t DetectEngineInspectStreamUDPPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const Signature *s, const SigMatchData *smd, Flow *f,
        Packet *p)
{
    SCEnter();
    int r = 0;

    if (smd == NULL) {
        SCReturnInt(0);
    }
#ifdef DEBUG
    det_ctx->payload_persig_cnt++;
    det_ctx->payload_persig_size += p->payload_len;
#endif
    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;

    r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            p, f, p->payload, p->payload_len, 0, DETECT_CI_FLAGS_SINGLE,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD);
    if (r == 1) {
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

struct StreamContentInspectData {
    DetectEngineCtx *de_ctx;
    DetectEngineThreadCtx *det_ctx;
    const Signature *s;
    Flow *f;
};

static int StreamContentInspectFunc(
        void *cb_data, const uint8_t *data, const uint32_t data_len, const uint64_t _offset)
{
    SCEnter();
    int r = 0;
    struct StreamContentInspectData *smd = cb_data;
#ifdef DEBUG
    smd->det_ctx->stream_persig_cnt++;
    smd->det_ctx->stream_persig_size += data_len;
#endif
    smd->det_ctx->buffer_offset = 0;
    smd->det_ctx->discontinue_matching = 0;
    smd->det_ctx->inspection_recursion_counter = 0;

    r = DetectEngineContentInspection(smd->de_ctx, smd->det_ctx,
            smd->s, smd->s->sm_arrays[DETECT_SM_LIST_PMATCH],
            NULL, smd->f, (uint8_t *)data, data_len, 0, 0, //TODO
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM);
    if (r == 1) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 *  \brief Do the content inspection & validation for a signature
 *         on the raw stream
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param f flow (for pcre flowvar storage)
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
int DetectEngineInspectStreamPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p)
{
    SCEnter();
    SCLogDebug("FLUSH? %s", (s->flags & SIG_FLAG_FLUSH)?"true":"false");
    uint64_t unused;
    struct StreamContentInspectData inspect_data = { de_ctx, det_ctx, s, f };
    int r = StreamReassembleRaw(f->protoctx, p,
            StreamContentInspectFunc, &inspect_data,
            &unused, ((s->flags & SIG_FLAG_FLUSH) != 0));
    return r;
}

struct StreamContentInspectEngineData {
    DetectEngineCtx *de_ctx;
    DetectEngineThreadCtx *det_ctx;
    const Signature *s;
    const SigMatchData *smd;
    Flow *f;
};

static int StreamContentInspectEngineFunc(
        void *cb_data, const uint8_t *data, const uint32_t data_len, const uint64_t _offset)
{
    SCEnter();
    int r = 0;
    struct StreamContentInspectEngineData *smd = cb_data;
#ifdef DEBUG
    smd->det_ctx->stream_persig_cnt++;
    smd->det_ctx->stream_persig_size += data_len;
#endif
    smd->det_ctx->buffer_offset = 0;
    smd->det_ctx->discontinue_matching = 0;
    smd->det_ctx->inspection_recursion_counter = 0;

    r = DetectEngineContentInspection(smd->de_ctx, smd->det_ctx,
            smd->s, smd->smd,
            NULL, smd->f, (uint8_t *)data, data_len, 0, 0, // TODO
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM);
    if (r == 1) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 *  \brief inspect engine for stateful rules
 *
 *  Caches results as it may be called multiple times if we inspect
 *  multiple transactions in one packet.
 *
 *  Returns "can't match" if depth is reached.
 */
uint8_t DetectEngineInspectStream(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    Packet *p = det_ctx->p; /* TODO: get rid of this HACK */

    /* in certain sigs, e.g. 'alert dns', which apply to both tcp and udp
     * we can get called for UDP. Then we simply inspect the packet payload */
    if (p->proto == IPPROTO_UDP) {
        return DetectEngineInspectStreamUDPPayload(de_ctx, det_ctx, s, engine->smd, f, p);
        /* for other non-TCP protocols we assume match */
    } else if (p->proto != IPPROTO_TCP)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

    TcpSession *ssn = f->protoctx;
    if (ssn == NULL)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;

    SCLogDebug("pre-inspect det_ctx->raw_stream_progress %"PRIu64" FLUSH? %s",
            det_ctx->raw_stream_progress,
            (s->flags & SIG_FLAG_FLUSH)?"true":"false");
    uint64_t unused;
    struct StreamContentInspectEngineData inspect_data = { de_ctx, det_ctx, s, engine->smd, f };
    int match = StreamReassembleRaw(f->protoctx, p,
            StreamContentInspectEngineFunc, &inspect_data,
            &unused, ((s->flags & SIG_FLAG_FLUSH) != 0));

    bool is_last = false;
    if (flags & STREAM_TOSERVER) {
        TcpStream *stream = &ssn->client;
        if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
            is_last = true;
    } else {
        TcpStream *stream = &ssn->server;
        if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
            is_last = true;
    }

    SCLogDebug("%s ran stream for sid %u on packet %"PRIu64" and we %s",
            is_last? "LAST:" : "normal:", s->id, p->pcap_cnt,
            match ? "matched" : "didn't match");

    if (match) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        if (is_last) {
            //SCLogNotice("last, so DETECT_ENGINE_INSPECT_SIG_CANT_MATCH");
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
        }
        /* TODO maybe we can set 'CANT_MATCH' for EOF too? */
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}

#ifdef UNITTESTS

/** \test Not the first but the second occurence of "abc" should be used
  *       for the 2nd match */
static int PayloadTestSig01 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcabcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; content:\"d\"; distance:0; within:1; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/** \test Nocase matching */
static int PayloadTestSig02 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; nocase; content:\"d\"; distance:0; within:1; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/** \test Negative distance matching */
static int PayloadTestSig03 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"aBc\"; nocase; content:\"abca\"; distance:-10; within:4; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig04(void)
{
    uint8_t *buf = (uint8_t *)"now this is is big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:6; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig05(void)
{
    uint8_t *buf = (uint8_t *)"now this is is is big big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:9; content:\"big\"; within:12; "
        "content:\"string\"; within:8; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig06(void)
{
    uint8_t *buf = (uint8_t *)"this this now is is     big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"now\"; content:\"this\"; content:\"is\"; within:12; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig07(void)
{
    uint8_t *buf = (uint8_t *)"         thus thus is a big";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"thus\"; offset:8; content:\"is\"; within:6; content:\"big\"; within:8; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test multiple relative matches with negative matches
 *       and show the need for det_ctx->discontinue_matching.
 */
static int PayloadTestSig08(void)
{
    uint8_t *buf = (uint8_t *)"we need to fix this and yes fix this now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"fix\"; content:\"this\"; within:6; content:!\"and\"; distance:0; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) != 1);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test pcre recursive matching.
 */
static int PayloadTestSig09(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "pcre:/super/; content:\"nova\"; within:7; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig10(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_test:4,>,2,0,relative; sid:11;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 1);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig11(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_jump:1,0,relative; sid:11;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 1);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig12(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "isdataat:10,relative; sid:11;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 1);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Used to check the working of recursion_limit counter.
 */
static int PayloadTestSig13(void)
{
    uint8_t *buf = (uint8_t *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    uint16_t mpm_type = mpm_default_matcher;

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"aa\"; content:\"aa\"; distance:0; content:\"aa\"; distance:0; "
        "byte_test:1,>,200,0,relative; sid:1;)";

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->inspection_recursion_limit = 3000;

    de_ctx->flags |= DE_QUIET;
    de_ctx->mpm_matcher = mpm_type;

    de_ctx->sig_list = SigInit(de_ctx, sig);
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, de_ctx->sig_list->id) != 1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test normal & negated matching, both absolute and relative
 */
static int PayloadTestSig14(void)
{
    uint8_t *buf = (uint8_t *)"User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"User-Agent|3A| Mozilla/5.0 |28|Macintosh|3B| \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 |28|Macintosh|3B| U|3B| Intel Mac OS X 10.5|3B| en-US|3B| rv|3A|1.9.1b4|29| Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    //char sig[] = "alert tcp any any -> any any (content:\"User-Agent: Mozilla/5.0 (Macintosh; \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 1);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig15(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:18,relative; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig16(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:!20,relative; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig17(void)
{
    uint8_t buf[] = { 0xEB, 0x29, 0x25, 0x38, 0x78, 0x25, 0x38, 0x78, 0x25 };
    uint16_t buflen = 9;
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"%\"; depth:4; offset:0; "
        "content:\"%\"; within:2; distance:1; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig18(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig19(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,hex,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig20(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|06 35 07 08|\"; offset:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig21(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|03 04 05 06|\"; depth:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig22(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|09 0A 0B 0C|\"; within:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig23(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x33, 0x0B, 0x0C, 0x0D,
        0x32, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_extract:1,3,two,string,dec,relative; "
        "byte_test:1,=,one,two,string,dec,relative; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig24(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x33, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_jump:1,one,string,dec,relative; "
        "content:\"|0D 0E 0F|\"; distance:0; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/*
 * \test Test negative byte extract.
 */
static int PayloadTestSig25(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|35 07 08 09|\"; "
        "byte_extract:1,-4,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/*
 * \test Test negative byte extract.
 */
static int PayloadTestSig26(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|35 07 08 09|\"; "
        "byte_extract:1,-3000,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) != 0);

    UTHFreePacket(p);

    PASS;
}

/*
 * \test Test packet/stream sigs
 */
static int PayloadTestSig27(void)
{
    uint8_t buf[] = "dummypayload";
    uint16_t buflen = sizeof(buf) - 1;
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"dummy\"; "
        "depth:5; sid:1;)";

    p->flags |= PKT_STREAM_ADD;
    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) != 1);

    UTHFreePacket(p);

    PASS;
}

/*
 * \test Test packet/stream sigs
 */
static int PayloadTestSig28(void)
{
    uint8_t buf[] = "dummypayload";
    uint16_t buflen = sizeof(buf) - 1;
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"payload\"; "
        "offset:4; depth:12; sid:1;)";

    p->flags |= PKT_STREAM_ADD;
    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) != 1);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test pcre recursive matching - bug #529
 */
static int PayloadTestSig29(void)
{
    uint8_t *buf = (uint8_t *)"this is a super dupernova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "pcre:/^.{4}/; content:\"nova\"; within:4; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 1);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig30(void)
{
    uint8_t *buf = (uint8_t *)
                    "xyonexxxxxxtwojunkonetwo";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"one\"; pcre:\"/^two/R\"; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

static int PayloadTestSig31(void)
{
    uint8_t *buf = (uint8_t *)
                    "xyonexxxxxxtwojunkonetwo";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"one\"; pcre:\"/(fiv|^two)/R\"; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test byte_jump.
 */
static int PayloadTestSig32(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_jump:2,-14,string,dec,relative; content:\"card\"; within:4; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test byte_test.
 */
static int PayloadTestSig33(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_test:1,=,2,-14,string,dec,relative; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test byte_extract.
 */
static int PayloadTestSig34(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_extract:1,-14,boom,string,dec,relative; sid:1;)";

    FAIL_IF(UTHPacketMatchSigMpm(p, sig, mpm_default_matcher) == 0);

    UTHFreePacket(p);

    PASS;
}

#endif /* UNITTESTS */

void PayloadRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("PayloadTestSig01", PayloadTestSig01);
    UtRegisterTest("PayloadTestSig02", PayloadTestSig02);
    UtRegisterTest("PayloadTestSig03", PayloadTestSig03);
    UtRegisterTest("PayloadTestSig04", PayloadTestSig04);
    UtRegisterTest("PayloadTestSig05", PayloadTestSig05);
    UtRegisterTest("PayloadTestSig06", PayloadTestSig06);
    UtRegisterTest("PayloadTestSig07", PayloadTestSig07);
    UtRegisterTest("PayloadTestSig08", PayloadTestSig08);
    UtRegisterTest("PayloadTestSig09", PayloadTestSig09);
    UtRegisterTest("PayloadTestSig10", PayloadTestSig10);
    UtRegisterTest("PayloadTestSig11", PayloadTestSig11);
    UtRegisterTest("PayloadTestSig12", PayloadTestSig12);
    UtRegisterTest("PayloadTestSig13", PayloadTestSig13);
    UtRegisterTest("PayloadTestSig14", PayloadTestSig14);
    UtRegisterTest("PayloadTestSig15", PayloadTestSig15);
    UtRegisterTest("PayloadTestSig16", PayloadTestSig16);
    UtRegisterTest("PayloadTestSig17", PayloadTestSig17);

    UtRegisterTest("PayloadTestSig18", PayloadTestSig18);
    UtRegisterTest("PayloadTestSig19", PayloadTestSig19);
    UtRegisterTest("PayloadTestSig20", PayloadTestSig20);
    UtRegisterTest("PayloadTestSig21", PayloadTestSig21);
    UtRegisterTest("PayloadTestSig22", PayloadTestSig22);
    UtRegisterTest("PayloadTestSig23", PayloadTestSig23);
    UtRegisterTest("PayloadTestSig24", PayloadTestSig24);
    UtRegisterTest("PayloadTestSig25", PayloadTestSig25);
    UtRegisterTest("PayloadTestSig26", PayloadTestSig26);
    UtRegisterTest("PayloadTestSig27", PayloadTestSig27);
    UtRegisterTest("PayloadTestSig28", PayloadTestSig28);
    UtRegisterTest("PayloadTestSig29", PayloadTestSig29);

    UtRegisterTest("PayloadTestSig30", PayloadTestSig30);
    UtRegisterTest("PayloadTestSig31", PayloadTestSig31);
    UtRegisterTest("PayloadTestSig32", PayloadTestSig32);
    UtRegisterTest("PayloadTestSig33", PayloadTestSig33);
    UtRegisterTest("PayloadTestSig34", PayloadTestSig34);
#endif /* UNITTESTS */

    return;
}
