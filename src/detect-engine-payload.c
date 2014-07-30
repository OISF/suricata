/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-content-inspection.h"

#include "util-debug.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

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
int DetectEngineInspectPacketPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, Packet *p)
{
    SCEnter();
    int r = 0;

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCReturnInt(0);
    }

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;
    //det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET;

    r = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH],
                                      f, p->payload, p->payload_len, 0,
                                      DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD, p);
    //r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH], p, f, p->payload, p->payload_len);
    //det_ctx->flags &= ~DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET;
    if (r == 1) {
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Do the content inspection & validation for a signature for a stream chunk
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param f flow (for pcre flowvar storage)
 *  \param payload ptr to the payload to inspect
 *  \param payload_len length of the payload
 *
 *  \retval 0 no match
 *  \retval 1 match
 *
 *  \todo we might also pass the packet to this function for the pktvar
 *        storage. Only, would that be right? We're not inspecting data
 *        from the current packet here.
 */
int DetectEngineInspectStreamPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f,
        uint8_t *payload, uint32_t payload_len)
{
    SCEnter();
    int r = 0;

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCReturnInt(0);
    }

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    //det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM;

    r = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH],
                                      f, payload, payload_len, 0,
                                      DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM, NULL);

    //r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH], NULL, f, payload, payload_len);
    //det_ctx->flags &= ~DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM;
    if (r == 1) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

#ifdef UNITTESTS

/** \test Not the first but the second occurence of "abc" should be used
  *       for the 2nd match */
static int PayloadTestSig01 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcabcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; content:\"d\"; distance:0; within:1; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test Nocase matching */
static int PayloadTestSig02 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; nocase; content:\"d\"; distance:0; within:1; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test Negative distance matching */
static int PayloadTestSig03 (void)
{
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"aBc\"; nocase; content:\"abca\"; distance:-10; within:4; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig04(void)
{
    uint8_t *buf = (uint8_t *)"now this is is big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:6; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig05(void)
{
    uint8_t *buf = (uint8_t *)"now this is is is big big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:9; content:\"big\"; within:12; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig06(void)
{
    uint8_t *buf = (uint8_t *)"this this now is is     big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"now\"; content:\"this\"; content:\"is\"; within:12; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig07(void)
{
    uint8_t *buf = (uint8_t *)"         thus thus is a big";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"thus\"; offset:8; content:\"is\"; within:6; content:\"big\"; within:8; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches with negative matches
 *       and show the need for det_ctx->discontinue_matching.
 */
static int PayloadTestSig08(void)
{
    uint8_t *buf = (uint8_t *)"we need to fix this and yes fix this now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"fix\"; content:\"this\"; within:6; content:!\"and\"; distance:0; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) != 1) {
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test pcre recursive matching.
 */
static int PayloadTestSig09(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "pcre:/super/; content:\"nova\"; within:7; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig10(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_test:4,>,2,0,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig11(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_jump:1,0,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig12(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "isdataat:10,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
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
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;
    uint16_t mpm_type = MPM_B2G;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"aa\"; content:\"aa\"; distance:0; content:\"aa\"; distance:0; "
        "byte_test:1,>,200,0,relative; sid:1;)";

    struct timeval tv_start, tv_end, tv_diff;

    gettimeofday(&tv_start, NULL);

    do {
        DecodeThreadVars dtv;
        ThreadVars th_v;
        DetectEngineThreadCtx *det_ctx = NULL;

        memset(&dtv, 0, sizeof(DecodeThreadVars));
        memset(&th_v, 0, sizeof(th_v));

        DetectEngineCtx *de_ctx = DetectEngineCtxInit();
        if (de_ctx == NULL) {
            printf("de_ctx == NULL: ");
            goto end;
        }
        de_ctx->inspection_recursion_limit = 3000;

        de_ctx->flags |= DE_QUIET;
        de_ctx->mpm_matcher = mpm_type;

        de_ctx->sig_list = SigInit(de_ctx, sig);
        if (de_ctx->sig_list == NULL) {
            printf("signature == NULL: ");
            goto end;
        }

        SigGroupBuild(de_ctx);
        DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

        SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
        if (PacketAlertCheck(p, de_ctx->sig_list->id) != 1) {
            goto end;
        }

        result = 1;
    end:
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

        if (de_ctx != NULL)
            DetectEngineCtxFree(de_ctx);
    } while (0);

    gettimeofday(&tv_end, NULL);

    tv_diff.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
    tv_diff.tv_usec = tv_end.tv_usec - tv_start.tv_usec;

    printf("%ld.%06ld\n", (long int)tv_diff.tv_sec, (long int)tv_diff.tv_usec);

    result = 1;

    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test normal & negated matching, both absolute and relative
 */
static int PayloadTestSig14(void)
{
    uint8_t *buf = (uint8_t *)"User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"User-Agent|3A| Mozilla/5.0 |28|Macintosh|3B| \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 |28|Macintosh|3B| U|3B| Intel Mac OS X 10.5|3B| en-US|3B| rv|3A|1.9.1b4|29| Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    //char sig[] = "alert tcp any any -> any any (content:\"User-Agent: Mozilla/5.0 (Macintosh; \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig15(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:18,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig16(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:!20,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig17(void)
{
    uint8_t buf[] = { 0xEB, 0x29, 0x25, 0x38, 0x78, 0x25, 0x38, 0x78, 0x25 };
    uint16_t buflen = 9;
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"%\"; depth:4; offset:0; "
        "content:\"%\"; within:2; distance:1; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig18(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig19(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,hex,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig20(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|06 35 07 08|\"; offset:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig21(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|03 04 05 06|\"; depth:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig22(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|09 0A 0B 0C|\"; within:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig23(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x33, 0x0B, 0x0C, 0x0D,
        0x32, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_extract:1,3,two,string,dec,relative; "
        "byte_test:1,=,one,two,string,dec,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig24(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x33, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_jump:1,one,string,dec,relative; "
        "content:\"|0D 0E 0F|\"; distance:0; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
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
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|35 07 08 09|\"; "
        "byte_extract:1,-4,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
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
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|35 07 08 09|\"; "
        "byte_extract:1,-3000,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) != 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/*
 * \test Test packet/stream sigs
 */
static int PayloadTestSig27(void)
{
    uint8_t buf[] = "dummypayload";
    uint16_t buflen = sizeof(buf) - 1;
    int result = 0;

    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    char sig[] = "alert tcp any any -> any any (content:\"dummy\"; "
        "depth:5; sid:1;)";

    p->flags |= PKT_STREAM_ADD;
    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) != 1)
        goto end;

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/*
 * \test Test packet/stream sigs
 */
static int PayloadTestSig28(void)
{
    uint8_t buf[] = "dummypayload";
    uint16_t buflen = sizeof(buf) - 1;
    int result = 0;

    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    char sig[] = "alert tcp any any -> any any (content:\"payload\"; "
        "offset:4; depth:12; sid:1;)";

    p->flags |= PKT_STREAM_ADD;
    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) != 1)
        goto end;

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test pcre recursive matching - bug #529
 */
static int PayloadTestSig29(void)
{
    uint8_t *buf = (uint8_t *)"this is a super dupernova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "pcre:/^.{4}/; content:\"nova\"; within:4; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, DEFAULT_MPM) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig30(void)
{
    uint8_t *buf = (uint8_t *)
                    "xyonexxxxxxtwojunkonetwo";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"one\"; pcre:\"/^two/R\"; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig31(void)
{
    uint8_t *buf = (uint8_t *)
                    "xyonexxxxxxtwojunkonetwo";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"one\"; pcre:\"/(fiv|^two)/R\"; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test byte_jump.
 */
static int PayloadTestSig32(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_jump:2,-14,string,dec,relative; content:\"card\"; within:4; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0)
        goto end;

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test byte_test.
 */
static int PayloadTestSig33(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_test:1,=,2,-14,string,dec,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0)
        goto end;

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test byte_extract.
 */
static int PayloadTestSig34(void)
{
    uint8_t *buf = (uint8_t *)"dummy2xxcardmessage";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"crash\"; "
        "content:\"message\"; byte_extract:1,-14,boom,string,dec,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0)
        goto end;

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

#endif /* UNITTESTS */

void PayloadRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("PayloadTestSig01", PayloadTestSig01, 1);
    UtRegisterTest("PayloadTestSig02", PayloadTestSig02, 1);
    UtRegisterTest("PayloadTestSig03", PayloadTestSig03, 1);
    UtRegisterTest("PayloadTestSig04", PayloadTestSig04, 1);
    UtRegisterTest("PayloadTestSig05", PayloadTestSig05, 1);
    UtRegisterTest("PayloadTestSig06", PayloadTestSig06, 1);
    UtRegisterTest("PayloadTestSig07", PayloadTestSig07, 1);
    UtRegisterTest("PayloadTestSig08", PayloadTestSig08, 1);
    UtRegisterTest("PayloadTestSig09", PayloadTestSig09, 1);
    UtRegisterTest("PayloadTestSig10", PayloadTestSig10, 1);
    UtRegisterTest("PayloadTestSig11", PayloadTestSig11, 1);
    UtRegisterTest("PayloadTestSig12", PayloadTestSig12, 1);
    UtRegisterTest("PayloadTestSig13", PayloadTestSig13, 1);
    UtRegisterTest("PayloadTestSig14", PayloadTestSig14, 1);
    UtRegisterTest("PayloadTestSig15", PayloadTestSig15, 1);
    UtRegisterTest("PayloadTestSig16", PayloadTestSig16, 1);
    UtRegisterTest("PayloadTestSig17", PayloadTestSig17, 1);

    UtRegisterTest("PayloadTestSig18", PayloadTestSig18, 1);
    UtRegisterTest("PayloadTestSig19", PayloadTestSig19, 1);
    UtRegisterTest("PayloadTestSig20", PayloadTestSig20, 1);
    UtRegisterTest("PayloadTestSig21", PayloadTestSig21, 1);
    UtRegisterTest("PayloadTestSig22", PayloadTestSig22, 1);
    UtRegisterTest("PayloadTestSig23", PayloadTestSig23, 1);
    UtRegisterTest("PayloadTestSig24", PayloadTestSig24, 1);
    UtRegisterTest("PayloadTestSig25", PayloadTestSig25, 1);
    UtRegisterTest("PayloadTestSig26", PayloadTestSig26, 1);
    UtRegisterTest("PayloadTestSig27", PayloadTestSig27, 1);
    UtRegisterTest("PayloadTestSig28", PayloadTestSig28, 1);
    UtRegisterTest("PayloadTestSig29", PayloadTestSig29, 1);

    UtRegisterTest("PayloadTestSig30", PayloadTestSig30, 1);
    UtRegisterTest("PayloadTestSig31", PayloadTestSig31, 1);
    UtRegisterTest("PayloadTestSig32", PayloadTestSig32, 1);
    UtRegisterTest("PayloadTestSig33", PayloadTestSig33, 1);
    UtRegisterTest("PayloadTestSig34", PayloadTestSig34, 1);
#endif /* UNITTESTS */

    return;
}
