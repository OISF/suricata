/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Stream size for the engine.
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow.h"
#include "detect-stream_size.h"
#include "stream-tcp-private.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"
#include "util-debug.h"
#include "util-byte.h"


/*prototypes*/
static int DetectStreamSizeMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectStreamSizeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectStreamSizeFree(DetectEngineCtx *de_ctx, void *);
#ifdef UNITTESTS
static void DetectStreamSizeRegisterTests(void);
#endif
static int PrefilterSetupStreamSize(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterStreamSizeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for stream_size: keyword
 */

void DetectStreamSizeRegister(void)
{
    sigmatch_table[DETECT_STREAM_SIZE].name = "stream_size";
    sigmatch_table[DETECT_STREAM_SIZE].desc = "match on amount of bytes of a stream";
    sigmatch_table[DETECT_STREAM_SIZE].url = "/rules/flow-keywords.html#stream-size";
    sigmatch_table[DETECT_STREAM_SIZE].Match = DetectStreamSizeMatch;
    sigmatch_table[DETECT_STREAM_SIZE].Setup = DetectStreamSizeSetup;
    sigmatch_table[DETECT_STREAM_SIZE].Free = DetectStreamSizeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_STREAM_SIZE].RegisterTests = DetectStreamSizeRegisterTests;
#endif
    sigmatch_table[DETECT_STREAM_SIZE].SupportsPrefilter = PrefilterStreamSizeIsPrefilterable;
    sigmatch_table[DETECT_STREAM_SIZE].SetupPrefilter = PrefilterSetupStreamSize;
}

static int DetectStreamSizeMatchAux(const DetectStreamSizeData *sd, const TcpSession *ssn)
{
    int ret = 0;
    uint32_t csdiff = 0;
    uint32_t ssdiff = 0;

    if (sd->flags == StreamSizeServer) {
        /* get the server stream size */
        ssdiff = ssn->server.next_seq - ssn->server.isn;
        ret = DetectU32Match(ssdiff, &sd->du32);

    } else if (sd->flags == StreamSizeClient) {
        /* get the client stream size */
        csdiff = ssn->client.next_seq - ssn->client.isn;
        ret = DetectU32Match(csdiff, &sd->du32);

    } else if (sd->flags == StreamSizeBoth) {
        ssdiff = ssn->server.next_seq - ssn->server.isn;
        csdiff = ssn->client.next_seq - ssn->client.isn;

        if (DetectU32Match(ssdiff, &sd->du32) && DetectU32Match(csdiff, &sd->du32))
            ret = 1;

    } else if (sd->flags == StreamSizeEither) {
        ssdiff = ssn->server.next_seq - ssn->server.isn;
        csdiff = ssn->client.next_seq - ssn->client.isn;

        if (DetectU32Match(ssdiff, &sd->du32) || DetectU32Match(csdiff, &sd->du32))
            ret = 1;
    }
    return ret;
}

/**
 * \brief This function is used to match Stream size rule option on a packet with those passed via
 * stream_size:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectStreamSizeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectStreamSizeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectStreamSizeData *sd = (const DetectStreamSizeData *)ctx;

    if (!(PacketIsTCP(p)))
        return 0;
    if (p->flow == NULL || p->flow->protoctx == NULL)
        return 0;

    const TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    SCReturnInt(DetectStreamSizeMatchAux(sd, ssn));
}

/**
 * \brief this function is used to add the parsed stream size data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param streamstr pointer to the user provided stream size options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectStreamSizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *streamstr)
{
    DetectStreamSizeData *sd = SCDetectStreamSizeParse(streamstr);
    if (sd == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_STREAM_SIZE, (SigMatchCtx *)sd, DETECT_SM_LIST_MATCH) == NULL) {
        DetectStreamSizeFree(de_ctx, sd);
        return -1;
    }
    return 0;
}

/**
 * \brief this function will free memory associated with DetectStreamSizeData
 *
 * \param ptr pointer to DetectStreamSizeData
 */
void DetectStreamSizeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectStreamSizeFree(ptr);
}

/* prefilter code */

static void PrefilterPacketStreamsizeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (!(PacketIsTCP(p)))
        return;

    if (p->flow == NULL || p->flow->protoctx == NULL)
        return;

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectStreamSizeData dsd;
    dsd.du32.mode = ctx->v1.u8[0];
    dsd.flags = ctx->v1.u8[1];
    dsd.du32.arg1 = ctx->v1.u32[2];
    const TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (DetectStreamSizeMatchAux(&dsd, ssn)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketStreamSizeSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectStreamSizeData *a = smctx;
    v->u8[0] = a->du32.mode;
    v->u8[1] = a->flags;
    v->u32[2] = a->du32.arg1;
}

static bool PrefilterPacketStreamSizeCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectStreamSizeData *a = smctx;
    if (v.u8[0] == a->du32.mode && v.u8[1] == a->flags && v.u32[2] == a->du32.arg1)
        return true;
    return false;
}

static int PrefilterSetupStreamSize(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_STREAM_SIZE, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketStreamSizeSet, PrefilterPacketStreamSizeCompare,
            PrefilterPacketStreamsizeMatch);
}

static bool PrefilterStreamSizeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_STREAM_SIZE:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
/**
 * \test DetectStreamSizeParseTest01 is a test to make sure that we parse the
 *  user options correctly, when given valid stream_size options.
 */

static int DetectStreamSizeParseTest01 (void)
{
    int result = 0;
    DetectStreamSizeData *sd = NULL;
    sd = SCDetectStreamSizeParse("server,<,6");
    if (sd != NULL) {
        if (sd->flags & StreamSizeServer && sd->du32.mode == DETECT_UINT_LT && sd->du32.arg1 == 6)
            result = 1;
        DetectStreamSizeFree(NULL, sd);
    }

    return result;
}

/**
 * \test DetectStreamSizeParseTest02 is a test to make sure that we detect the
 *  invalid stream_size options.
 */

static int DetectStreamSizeParseTest02 (void)
{
    int result = 1;
    DetectStreamSizeData *sd = NULL;
    sd = SCDetectStreamSizeParse("invalidoption,<,6");
    if (sd != NULL) {
        printf("expected: NULL got 0x%02X %" PRIu32 ": ", sd->flags, sd->du32.arg1);
        result = 0;
        DetectStreamSizeFree(NULL, sd);
    }

    return result;
}

/**
 * \test DetectStreamSizeParseTest03 is a test to make sure that we match the
 *  packet correctly provided valid stream size.
 */

static int DetectStreamSizeParseTest03 (void)
{
    TcpSession ssn;
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature s;
    SigMatch sm;
    TcpStream client;
    Flow f;
    TCPHdr tcph;

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtx, 0, sizeof(DetectEngineThreadCtx));
    memset(&s, 0, sizeof(Signature));
    memset(&sm, 0, sizeof(SigMatch));
    memset(&client, 0, sizeof(TcpStream));
    memset(&f, 0, sizeof(Flow));
    memset(&tcph, 0, sizeof(TCPHdr));

    DetectStreamSizeData *sd = SCDetectStreamSizeParse("client,>,8");
    FAIL_IF_NULL(sd);
    FAIL_IF_NOT(sd->flags & StreamSizeClient);
    FAIL_IF_NOT(sd->du32.mode == DETECT_UINT_GT);
    FAIL_IF_NOT(sd->du32.arg1 == 8);

    client.next_seq = 20;
    client.isn = 10;
    ssn.client = client;
    f.protoctx = &ssn;
    p->flow = &f;
    PacketSetTCP(p, (uint8_t *)&tcph);
    sm.ctx = (SigMatchCtx*)sd;

    int result = DetectStreamSizeMatch(&dtx, p, &s, sm.ctx);
    FAIL_IF_NOT(result == 1);
    DetectStreamSizeFree(NULL, sd);
    PacketFree(p);
    PASS;
}

/**
 * \test DetectStreamSizeParseTest04 is a test to make sure that we match the
 *  stream_size against invalid packet parameters.
 */

static int DetectStreamSizeParseTest04 (void)
{
    TcpSession ssn;
    ThreadVars tv;
    DetectEngineThreadCtx dtx;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature s;
    SigMatch sm;
    TcpStream client;
    Flow f;
    IPV4Hdr ip4h;

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtx, 0, sizeof(DetectEngineThreadCtx));
    memset(&s, 0, sizeof(Signature));
    memset(&sm, 0, sizeof(SigMatch));
    memset(&client, 0, sizeof(TcpStream));
    memset(&f, 0, sizeof(Flow));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    DetectStreamSizeData *sd = SCDetectStreamSizeParse(" client , > , 8 ");
    FAIL_IF_NULL(sd);
    FAIL_IF_NOT(sd->flags & StreamSizeClient);
    FAIL_IF_NOT(sd->du32.mode == DETECT_UINT_GT);
    FAIL_IF_NOT(sd->du32.arg1 == 8);

    client.next_seq = 20;
    client.isn = 12;
    ssn.client = client;
    f.protoctx = &ssn;
    p->flow = &f;
    UTHSetIPV4Hdr(p, &ip4h);
    sm.ctx = (SigMatchCtx*)sd;

    FAIL_IF(DetectStreamSizeMatch(&dtx, p, &s, sm.ctx));

    PacketFree(p);
    DetectStreamSizeFree(NULL, sd);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectStreamSize
 */
void DetectStreamSizeRegisterTests(void)
{
    UtRegisterTest("DetectStreamSizeParseTest01", DetectStreamSizeParseTest01);
    UtRegisterTest("DetectStreamSizeParseTest02", DetectStreamSizeParseTest02);
    UtRegisterTest("DetectStreamSizeParseTest03", DetectStreamSizeParseTest03);
    UtRegisterTest("DetectStreamSizeParseTest04", DetectStreamSizeParseTest04);
}
#endif /* UNITTESTS */
