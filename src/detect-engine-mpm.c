/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Multi pattern matcher
 */

#include "suricata.h"
#include "suricata-common.h"

#include "app-layer-protos.h"

#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-parse.h"
#include "util-mpm.h"
#include "util-memcmp.h"
#include "util-memcpy.h"
#include "conf.h"
#include "detect-fast-pattern.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#include "stream.h"

#include "util-enum.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-memcmp.h"
#ifdef __SC_CUDA_SUPPORT__
#include "util-mpm-ac.h"
#endif
#include "util-validate.h"

/** \todo make it possible to use multiple pattern matcher algorithms next to
          each other. */

#define POPULATE_MPM_AVOID_PACKET_MPM_PATTERNS 0x01
#define POPULATE_MPM_AVOID_STREAM_MPM_PATTERNS 0x02
#define POPULATE_MPM_AVOID_URI_MPM_PATTERNS 0x04

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against a packets payload (as opposed to the stream payload)
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasPacketContent(Signature *s)
{
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->proto.proto[IPPROTO_TCP / 8] & 1 << (IPPROTO_TCP % 8))) {
        SCReturnInt(1);
    }

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against the stream payload (as opposed to the individual packets
 *         payload(s))
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasStreamContent(Signature *s)
{
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->proto.proto[IPPROTO_TCP / 8] & 1 << (IPPROTO_TCP % 8))) {
        SCReturnInt(0);
    }

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}


/**
 *  \brief  Function to return the multi pattern matcher algorithm to be
 *          used by the engine, based on the mpm-algo setting in yaml
 *          Use the default mpm if none is specified in the yaml file.
 *
 *  \retval mpm algo value
 */
uint16_t PatternMatchDefaultMatcher(void)
{
    char *mpm_algo;
    uint16_t mpm_algo_val = DEFAULT_MPM;

    /* Get the mpm algo defined in config file by the user */
    if ((ConfGet("mpm-algo", &mpm_algo)) == 1) {
        uint16_t u;

        if (mpm_algo != NULL) {
            for (u = 0; u < MPM_TABLE_SIZE; u++) {
                if (mpm_table[u].name == NULL)
                    continue;

                if (strcmp(mpm_table[u].name, mpm_algo) == 0) {
                    mpm_algo_val = u;
                    goto done;
                }
            }
        }

        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid mpm algo supplied "
                "in the yaml conf file: \"%s\"", mpm_algo);
        exit(EXIT_FAILURE);
    }

 done:
#ifdef __tile__
    if (mpm_algo_val == MPM_AC)
        mpm_algo_val = MPM_AC_TILE;
#endif

    return mpm_algo_val;
}

uint32_t PacketPatternSearchWithStreamCtx(DetectEngineThreadCtx *det_ctx,
                                         Packet *p)
{
    SCEnter();

    uint32_t ret = 0;

    if (p->flowflags & FLOW_PKT_TOSERVER) {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_stream_ctx_ts == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_stream_ctx_ts->mpm_type].
            Search(det_ctx->sgh->mpm_stream_ctx_ts, &det_ctx->mtc, &det_ctx->pmq,
                   p->payload, p->payload_len);
    } else {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_stream_ctx_tc == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_stream_ctx_tc->mpm_type].
            Search(det_ctx->sgh->mpm_stream_ctx_tc, &det_ctx->mtc, &det_ctx->pmq,
                   p->payload, p->payload_len);
    }

    SCReturnInt(ret);
}

/** \brief Pattern match -- searches for only one pattern per signature.
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *
 *  \retval ret number of matches
 */
uint32_t PacketPatternSearch(DetectEngineThreadCtx *det_ctx, Packet *p)
{
    SCEnter();

    uint32_t ret;
    MpmCtx *mpm_ctx = NULL;

    if (p->proto == IPPROTO_TCP) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            mpm_ctx = det_ctx->sgh->mpm_proto_tcp_ctx_ts;
        } else {
            mpm_ctx = det_ctx->sgh->mpm_proto_tcp_ctx_tc;
        }
    } else if (p->proto == IPPROTO_UDP) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            mpm_ctx = det_ctx->sgh->mpm_proto_udp_ctx_ts;
        } else {
            mpm_ctx = det_ctx->sgh->mpm_proto_udp_ctx_tc;
        }
    } else {
        mpm_ctx = det_ctx->sgh->mpm_proto_other_ctx;
    }
    if (unlikely(mpm_ctx == NULL))
        SCReturnInt(0);

#ifdef __SC_CUDA_SUPPORT__
    if (p->cuda_pkt_vars.cuda_mpm_enabled && p->pkt_src == PKT_SRC_WIRE) {
        ret = SCACCudaPacketResultsProcessing(p, mpm_ctx, &det_ctx->pmq);
    } else {
        ret = mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                                                  &det_ctx->mtc,
                                                  &det_ctx->pmq,
                                                  p->payload,
                                                  p->payload_len);
    }
#else
    ret = mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                                              &det_ctx->mtc,
                                              &det_ctx->pmq,
                                              p->payload,
                                              p->payload_len);
#endif

    SCReturnInt(ret);
}

/** \brief Uri Pattern match -- searches for one pattern per signature.
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *
 *  \retval ret number of matches
 */
uint32_t UriPatternSearch(DetectEngineThreadCtx *det_ctx,
                          uint8_t *uri, uint16_t uri_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_uri_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_uri_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_uri_ctx_ts,
                &det_ctx->mtcu, &det_ctx->pmq, uri, uri_len);

    //PrintRawDataFp(stdout, uri, uri_len);

    SCReturnUInt(ret);
}

/** \brief Http client body pattern match -- searches for one pattern per
 *         signature.
 *
 *  \param det_ctx  Detection engine thread ctx.
 *  \param body     The request body to inspect.
 *  \param body_len Body length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpClientBodyPatternSearch(DetectEngineThreadCtx *det_ctx,
                                     uint8_t *body, uint32_t body_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hcbd_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hcbd_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_hcbd_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, body, body_len);

    SCReturnUInt(ret);
}

/** \brief Http server body pattern match -- searches for one pattern per
 *         signature.
 *
 *  \param det_ctx  Detection engine thread ctx.
 *  \param body     The request body to inspect.
 *  \param body_len Body length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpServerBodyPatternSearch(DetectEngineThreadCtx *det_ctx,
                                     uint8_t *body, uint32_t body_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(!(flags & STREAM_TOCLIENT));
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hsbd_ctx_tc == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hsbd_ctx_tc->mpm_type].
        Search(det_ctx->sgh->mpm_hsbd_ctx_tc, &det_ctx->mtcu,
                &det_ctx->pmq, body, body_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http header match -- searches for one pattern per signature.
 *
 * \param det_ctx     Detection engine thread ctx.
 * \param headers     Headers to inspect.
 * \param headers_len Headers length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpHeaderPatternSearch(DetectEngineThreadCtx *det_ctx,
                                 uint8_t *headers, uint32_t headers_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;
    if (flags & STREAM_TOSERVER) {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hhd_ctx_ts == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hhd_ctx_ts->mpm_type].
            Search(det_ctx->sgh->mpm_hhd_ctx_ts, &det_ctx->mtcu,
                   &det_ctx->pmq, headers, headers_len);
    } else {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hhd_ctx_tc == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hhd_ctx_tc->mpm_type].
            Search(det_ctx->sgh->mpm_hhd_ctx_tc, &det_ctx->mtcu,
                   &det_ctx->pmq, headers, headers_len);
    }

    SCReturnUInt(ret);
}

/**
 * \brief Http raw header match -- searches for one pattern per signature.
 *
 * \param det_ctx     Detection engine thread ctx.
 * \param headers     Raw headers to inspect.
 * \param headers_len Raw headers length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpRawHeaderPatternSearch(DetectEngineThreadCtx *det_ctx,
                                    uint8_t *raw_headers, uint32_t raw_headers_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;
    if (flags & STREAM_TOSERVER) {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hrhd_ctx_ts == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hrhd_ctx_ts->mpm_type].
            Search(det_ctx->sgh->mpm_hrhd_ctx_ts, &det_ctx->mtcu,
                   &det_ctx->pmq, raw_headers, raw_headers_len);
    } else {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hrhd_ctx_tc == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hrhd_ctx_tc->mpm_type].
            Search(det_ctx->sgh->mpm_hrhd_ctx_tc, &det_ctx->mtcu,
                   &det_ctx->pmq, raw_headers, raw_headers_len);
    }

    SCReturnUInt(ret);
}

/**
 * \brief Http method match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param method     Method to inspect.
 * \param method_len Method length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpMethodPatternSearch(DetectEngineThreadCtx *det_ctx,
                                 uint8_t *raw_method, uint32_t raw_method_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hmd_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hmd_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_hmd_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, raw_method, raw_method_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http cookie match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param cookie     Cookie to inspect.
 * \param cookie_len Cookie length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpCookiePatternSearch(DetectEngineThreadCtx *det_ctx,
                                 uint8_t *cookie, uint32_t cookie_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;
    if (flags & STREAM_TOSERVER) {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hcd_ctx_ts == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hcd_ctx_ts->mpm_type].
            Search(det_ctx->sgh->mpm_hcd_ctx_ts, &det_ctx->mtcu,
                   &det_ctx->pmq, cookie, cookie_len);
    } else {
        DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hcd_ctx_tc == NULL);

        ret = mpm_table[det_ctx->sgh->mpm_hcd_ctx_tc->mpm_type].
            Search(det_ctx->sgh->mpm_hcd_ctx_tc, &det_ctx->mtcu,
                   &det_ctx->pmq, cookie, cookie_len);
    }

    SCReturnUInt(ret);
}

/**
 * \brief Http raw uri match -- searches for one pattern per signature.
 *
 * \param det_ctx Detection engine thread ctx.
 * \param uri     Raw uri to inspect.
 * \param uri_len Raw uri length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpRawUriPatternSearch(DetectEngineThreadCtx *det_ctx,
                                 uint8_t *uri, uint32_t uri_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hrud_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hrud_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_hrud_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, uri, uri_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http stat msg match -- searches for one pattern per signature.
 *
 * \param det_ctx      Detection engine thread ctx.
 * \param stat_msg     Stat msg to inspect.
 * \param stat_msg_len Stat msg length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpStatMsgPatternSearch(DetectEngineThreadCtx *det_ctx,
                                  uint8_t *stat_msg, uint32_t stat_msg_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(!(flags & STREAM_TOCLIENT));
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hsmd_ctx_tc == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hsmd_ctx_tc->mpm_type].
        Search(det_ctx->sgh->mpm_hsmd_ctx_tc, &det_ctx->mtcu,
                &det_ctx->pmq, stat_msg, stat_msg_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http stat code match -- searches for one pattern per signature.
 *
 * \param det_ctx       Detection engine thread ctx.
 * \param stat_code     Stat code to inspect.
 * \param stat_code_len Stat code length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpStatCodePatternSearch(DetectEngineThreadCtx *det_ctx,
                                   uint8_t *stat_code, uint32_t stat_code_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(!(flags & STREAM_TOCLIENT));
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hscd_ctx_tc == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hscd_ctx_tc->mpm_type].
        Search(det_ctx->sgh->mpm_hscd_ctx_tc, &det_ctx->mtcu,
                &det_ctx->pmq, stat_code, stat_code_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http user agent match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param cookie     User-Agent to inspect.
 * \param cookie_len User-Agent buffer length.
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpUAPatternSearch(DetectEngineThreadCtx *det_ctx,
                             uint8_t *ua, uint32_t ua_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_huad_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_huad_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_huad_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, ua, ua_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http host header match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param hh     Host header to inspect.
 * \param hh_len Host header buffer length.
 * \param flags  Flags
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpHHPatternSearch(DetectEngineThreadCtx *det_ctx,
                             uint8_t *hh, uint32_t hh_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hhhd_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hhhd_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_hhhd_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, hh, hh_len);

    SCReturnUInt(ret);
}

/**
 * \brief Http raw host header match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param hrh        Raw hostname to inspect.
 * \param hrh_len    Raw hostname buffer length.
 * \param flags  Flags
 *
 *  \retval ret Number of matches.
 */
uint32_t HttpHRHPatternSearch(DetectEngineThreadCtx *det_ctx,
                              uint8_t *hrh, uint32_t hrh_len, uint8_t flags)
{
    SCEnter();

    uint32_t ret;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_hrhhd_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_hrhhd_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_hrhhd_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, hrh, hrh_len);

    SCReturnUInt(ret);
}

/**
 * \brief DNS query match -- searches for one pattern per signature.
 *
 * \param det_ctx   Detection engine thread ctx.
 * \param hrh       Buffer to inspect.
 * \param hrh_len   buffer length.
 * \param flags     Flags
 *
 *  \retval ret Number of matches.
 */
uint32_t DnsQueryPatternSearch(DetectEngineThreadCtx *det_ctx,
                              uint8_t *buffer, uint32_t buffer_len,
                              uint8_t flags)
{
    SCEnter();

    uint32_t ret = 0;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_dnsquery_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_dnsquery_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_dnsquery_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, buffer, buffer_len);

    SCReturnUInt(ret);
}

/** \brief Pattern match -- searches for only one pattern per signature.
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet
 *  \param smsg stream msg (reassembled stream data)
 *  \param flags stream flags
 *
 *  \retval ret number of matches
 */
uint32_t StreamPatternSearch(DetectEngineThreadCtx *det_ctx, Packet *p,
                             StreamMsg *smsg, uint8_t flags)
{
    SCEnter();

    uint32_t ret = 0;
    uint8_t cnt = 0;

    //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);

    uint32_t r;
    if (flags & STREAM_TOSERVER) {
        for ( ; smsg != NULL; smsg = smsg->next) {
            r = mpm_table[det_ctx->sgh->mpm_stream_ctx_ts->mpm_type].
                Search(det_ctx->sgh->mpm_stream_ctx_ts, &det_ctx->mtcs,
                       &det_ctx->smsg_pmq[cnt], smsg->data, smsg->data_len);
            if (r > 0) {
                ret += r;

                SCLogDebug("smsg match stored in det_ctx->smsg_pmq[%u]", cnt);

                /* merge results with overall pmq */
                PmqMerge(&det_ctx->smsg_pmq[cnt], &det_ctx->pmq);
            }

            cnt++;
        }
    } else {
        for ( ; smsg != NULL; smsg = smsg->next) {
            r = mpm_table[det_ctx->sgh->mpm_stream_ctx_tc->mpm_type].
                Search(det_ctx->sgh->mpm_stream_ctx_tc, &det_ctx->mtcs,
                       &det_ctx->smsg_pmq[cnt], smsg->data, smsg->data_len);
            if (r > 0) {
                ret += r;

                SCLogDebug("smsg match stored in det_ctx->smsg_pmq[%u]", cnt);

                /* merge results with overall pmq */
                PmqMerge(&det_ctx->smsg_pmq[cnt], &det_ctx->pmq);
            }

            cnt++;
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief SMTP Filedata match -- searches for one pattern per signature.
 *
 * \param det_ctx    Detection engine thread ctx.
 * \param buffer     Buffer to inspect.
 * \param buffer_len buffer length.
 * \param flags      Flags
 *
 *  \retval ret Number of matches.
 */
uint32_t SMTPFiledataPatternSearch(DetectEngineThreadCtx *det_ctx,
                              uint8_t *buffer, uint32_t buffer_len,
                              uint8_t flags)
{
    SCEnter();

    uint32_t ret = 0;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_smtp_filedata_ctx_ts == NULL);

    ret = mpm_table[det_ctx->sgh->mpm_smtp_filedata_ctx_ts->mpm_type].
        Search(det_ctx->sgh->mpm_smtp_filedata_ctx_ts, &det_ctx->mtcu,
                &det_ctx->pmq, buffer, buffer_len);

    SCReturnUInt(ret);
}

/** \brief cleans up the mpm instance after a match */
void PacketPatternCleanup(ThreadVars *t, DetectEngineThreadCtx *det_ctx)
{
    PmqReset(&det_ctx->pmq);

    if (det_ctx->sgh == NULL)
        return;

    /* content */
    if (det_ctx->sgh->mpm_proto_tcp_ctx_ts != NULL &&
        mpm_table[det_ctx->sgh->mpm_proto_tcp_ctx_ts->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_proto_tcp_ctx_ts->mpm_type].Cleanup(&det_ctx->mtc);
    }
    if (det_ctx->sgh->mpm_proto_tcp_ctx_tc != NULL &&
        mpm_table[det_ctx->sgh->mpm_proto_tcp_ctx_tc->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_proto_tcp_ctx_tc->mpm_type].Cleanup(&det_ctx->mtc);
    }

    if (det_ctx->sgh->mpm_proto_udp_ctx_ts != NULL &&
        mpm_table[det_ctx->sgh->mpm_proto_udp_ctx_ts->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_proto_udp_ctx_ts->mpm_type].Cleanup(&det_ctx->mtc);
    }
    if (det_ctx->sgh->mpm_proto_udp_ctx_tc != NULL &&
        mpm_table[det_ctx->sgh->mpm_proto_udp_ctx_tc->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_proto_udp_ctx_tc->mpm_type].Cleanup(&det_ctx->mtc);
    }

    if (det_ctx->sgh->mpm_proto_other_ctx != NULL &&
        mpm_table[det_ctx->sgh->mpm_proto_other_ctx->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_proto_other_ctx->mpm_type].Cleanup(&det_ctx->mtc);
    }

    /* uricontent */
    if (det_ctx->sgh->mpm_uri_ctx_ts != NULL && mpm_table[det_ctx->sgh->mpm_uri_ctx_ts->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_uri_ctx_ts->mpm_type].Cleanup(&det_ctx->mtcu);
    }

    /* stream content */
    if (det_ctx->sgh->mpm_stream_ctx_ts != NULL && mpm_table[det_ctx->sgh->mpm_stream_ctx_ts->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_stream_ctx_ts->mpm_type].Cleanup(&det_ctx->mtcs);
    }
    if (det_ctx->sgh->mpm_stream_ctx_tc != NULL && mpm_table[det_ctx->sgh->mpm_stream_ctx_tc->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_stream_ctx_tc->mpm_type].Cleanup(&det_ctx->mtcs);
    }

    return;
}

void StreamPatternCleanup(ThreadVars *t, DetectEngineThreadCtx *det_ctx, StreamMsg *smsg)
{
    uint8_t cnt = 0;

    while (smsg != NULL) {
        PmqReset(&det_ctx->smsg_pmq[cnt]);

        smsg = smsg->next;
        cnt++;
    }
}

void PatternMatchDestroy(MpmCtx *mpm_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_ctx %p, mpm_matcher %"PRIu16"", mpm_ctx, mpm_matcher);
    mpm_table[mpm_matcher].DestroyCtx(mpm_ctx);
}

void PatternMatchPrepare(MpmCtx *mpm_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_ctx %p, mpm_matcher %"PRIu16"", mpm_ctx, mpm_matcher);
    MpmInitCtx(mpm_ctx, mpm_matcher);
}

void PatternMatchThreadPrint(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16" defunct", mpm_thread_ctx, mpm_matcher);
    //mpm_table[mpm_matcher].PrintThreadCtx(mpm_thread_ctx);
}
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16"", mpm_thread_ctx, mpm_matcher);
    if (mpm_table[mpm_matcher].DestroyThreadCtx != NULL)
        mpm_table[mpm_matcher].DestroyThreadCtx(NULL, mpm_thread_ctx);
}
void PatternMatchThreadPrepare(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher, uint32_t max_id)
{
    SCLogDebug("mpm_thread_ctx %p, type %"PRIu16", max_id %"PRIu32"", mpm_thread_ctx, mpm_matcher, max_id);
    MpmInitThreadCtx(mpm_thread_ctx, mpm_matcher, max_id);
}


/* free the pattern matcher part of a SigGroupHead */
void PatternMatchDestroyGroup(SigGroupHead *sh)
{
    /* content */
    if (!(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        if (sh->mpm_proto_tcp_ctx_ts != NULL &&
            !sh->mpm_proto_tcp_ctx_ts->global)
        {
            SCLogDebug("destroying mpm_ctx %p (sh %p)",
                    sh->mpm_proto_tcp_ctx_ts, sh);
            mpm_table[sh->mpm_proto_tcp_ctx_ts->mpm_type].
                DestroyCtx(sh->mpm_proto_tcp_ctx_ts);
            SCFree(sh->mpm_proto_tcp_ctx_ts);
        }
        /* ready for reuse */
        sh->mpm_proto_tcp_ctx_ts = NULL;

        if (sh->mpm_proto_tcp_ctx_tc != NULL &&
            !sh->mpm_proto_tcp_ctx_tc->global)
        {
            SCLogDebug("destroying mpm_ctx %p (sh %p)",
                    sh->mpm_proto_tcp_ctx_tc, sh);
            mpm_table[sh->mpm_proto_tcp_ctx_tc->mpm_type].
                DestroyCtx(sh->mpm_proto_tcp_ctx_tc);
            SCFree(sh->mpm_proto_tcp_ctx_tc);
        }
        /* ready for reuse */
        sh->mpm_proto_tcp_ctx_tc = NULL;

        if (sh->mpm_proto_udp_ctx_ts != NULL &&
            !sh->mpm_proto_udp_ctx_ts->global)
        {
            SCLogDebug("destroying mpm_ctx %p (sh %p)",
                    sh->mpm_proto_udp_ctx_ts, sh);
            mpm_table[sh->mpm_proto_udp_ctx_ts->mpm_type].
                DestroyCtx(sh->mpm_proto_udp_ctx_ts);
            SCFree(sh->mpm_proto_udp_ctx_ts);
        }
        /* ready for reuse */
        sh->mpm_proto_udp_ctx_ts = NULL;

        if (sh->mpm_proto_udp_ctx_tc != NULL &&
                !sh->mpm_proto_udp_ctx_tc->global)
        {
            SCLogDebug("destroying mpm_ctx %p (sh %p)",
                    sh->mpm_proto_udp_ctx_tc, sh);
            mpm_table[sh->mpm_proto_udp_ctx_tc->mpm_type].
                DestroyCtx(sh->mpm_proto_udp_ctx_tc);
            SCFree(sh->mpm_proto_udp_ctx_tc);
        }
        /* ready for reuse */
        sh->mpm_proto_udp_ctx_tc = NULL;

        if (sh->mpm_proto_other_ctx != NULL &&
                !sh->mpm_proto_other_ctx->global)
        {
            SCLogDebug("destroying mpm_ctx %p (sh %p)",
                    sh->mpm_proto_other_ctx, sh);
            mpm_table[sh->mpm_proto_other_ctx->mpm_type].
                DestroyCtx(sh->mpm_proto_other_ctx);
            SCFree(sh->mpm_proto_other_ctx);
        }
        /* ready for reuse */
        sh->mpm_proto_other_ctx = NULL;
    }

    /* uricontent */
    if ((sh->mpm_uri_ctx_ts != NULL) && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        if (sh->mpm_uri_ctx_ts != NULL) {
            if (!sh->mpm_uri_ctx_ts->global) {
                SCLogDebug("destroying mpm_uri_ctx %p (sh %p)", sh->mpm_uri_ctx_ts, sh);
                mpm_table[sh->mpm_uri_ctx_ts->mpm_type].DestroyCtx(sh->mpm_uri_ctx_ts);
                SCFree(sh->mpm_uri_ctx_ts);
            }
            /* ready for reuse */
            sh->mpm_uri_ctx_ts = NULL;
        }
    }

    /* stream content */
    if ((sh->mpm_stream_ctx_ts != NULL || sh->mpm_stream_ctx_tc != NULL) &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
        if (sh->mpm_stream_ctx_ts != NULL) {
            if (!sh->mpm_stream_ctx_ts->global) {
                SCLogDebug("destroying mpm_stream_ctx %p (sh %p)", sh->mpm_stream_ctx_ts, sh);
                mpm_table[sh->mpm_stream_ctx_ts->mpm_type].DestroyCtx(sh->mpm_stream_ctx_ts);
                SCFree(sh->mpm_stream_ctx_ts);
            }
            /* ready for reuse */
            sh->mpm_stream_ctx_ts = NULL;
        }
        if (sh->mpm_stream_ctx_tc != NULL) {
            if (!sh->mpm_stream_ctx_tc->global) {
                SCLogDebug("destroying mpm_stream_ctx %p (sh %p)", sh->mpm_stream_ctx_tc, sh);
                mpm_table[sh->mpm_stream_ctx_tc->mpm_type].DestroyCtx(sh->mpm_stream_ctx_tc);
                SCFree(sh->mpm_stream_ctx_tc);
            }
            /* ready for reuse */
            sh->mpm_stream_ctx_tc = NULL;
        }
    }

    if (sh->mpm_hcbd_ctx_ts != NULL) {
        if (sh->mpm_hcbd_ctx_ts != NULL) {
            if (!sh->mpm_hcbd_ctx_ts->global) {
                mpm_table[sh->mpm_hcbd_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hcbd_ctx_ts);
                SCFree(sh->mpm_hcbd_ctx_ts);
            }
            sh->mpm_hcbd_ctx_ts = NULL;
        }
    }

    if (sh->mpm_hsbd_ctx_tc != NULL) {
        if (sh->mpm_hsbd_ctx_tc != NULL) {
            if (!sh->mpm_hsbd_ctx_tc->global) {
                mpm_table[sh->mpm_hsbd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hsbd_ctx_tc);
                SCFree(sh->mpm_hsbd_ctx_tc);
            }
            sh->mpm_hsbd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_smtp_filedata_ctx_ts != NULL) {
        if (sh->mpm_smtp_filedata_ctx_ts != NULL) {
            if (!sh->mpm_smtp_filedata_ctx_ts->global) {
                mpm_table[sh->mpm_smtp_filedata_ctx_ts->mpm_type].DestroyCtx(sh->mpm_smtp_filedata_ctx_ts);
                SCFree(sh->mpm_smtp_filedata_ctx_ts);
            }
            sh->mpm_smtp_filedata_ctx_ts = NULL;
        }
    }

    if (sh->mpm_hhd_ctx_ts != NULL || sh->mpm_hhd_ctx_tc != NULL) {
        if (sh->mpm_hhd_ctx_ts != NULL) {
            if (!sh->mpm_hhd_ctx_ts->global) {
                mpm_table[sh->mpm_hhd_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hhd_ctx_ts);
                SCFree(sh->mpm_hhd_ctx_ts);
            }
            sh->mpm_hhd_ctx_ts = NULL;
        }
        if (sh->mpm_hhd_ctx_tc != NULL) {
            if (!sh->mpm_hhd_ctx_tc->global) {
                mpm_table[sh->mpm_hhd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hhd_ctx_tc);
                SCFree(sh->mpm_hhd_ctx_tc);
            }
            sh->mpm_hhd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_hrhd_ctx_ts != NULL || sh->mpm_hrhd_ctx_tc != NULL) {
        if (sh->mpm_hrhd_ctx_ts != NULL) {
            if (!sh->mpm_hrhd_ctx_ts->global) {
                mpm_table[sh->mpm_hrhd_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hrhd_ctx_ts);
                SCFree(sh->mpm_hrhd_ctx_ts);
            }
            sh->mpm_hrhd_ctx_ts = NULL;
        }
        if (sh->mpm_hrhd_ctx_tc != NULL) {
            if (!sh->mpm_hrhd_ctx_tc->global) {
                mpm_table[sh->mpm_hrhd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hrhd_ctx_tc);
                SCFree(sh->mpm_hrhd_ctx_tc);
            }
            sh->mpm_hrhd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_hmd_ctx_ts != NULL) {
        if (sh->mpm_hmd_ctx_ts != NULL) {
            if (!sh->mpm_hmd_ctx_ts->global) {
                mpm_table[sh->mpm_hmd_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hmd_ctx_ts);
                SCFree(sh->mpm_hmd_ctx_ts);
            }
            sh->mpm_hmd_ctx_ts = NULL;
        }
    }

    if (sh->mpm_hcd_ctx_ts != NULL || sh->mpm_hcd_ctx_tc != NULL) {
        if (sh->mpm_hcd_ctx_ts != NULL) {
            if (!sh->mpm_hcd_ctx_ts->global) {
                mpm_table[sh->mpm_hcd_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hcd_ctx_ts);
                SCFree(sh->mpm_hcd_ctx_ts);
            }
            sh->mpm_hcd_ctx_ts = NULL;
        }
        if (sh->mpm_hcd_ctx_tc != NULL) {
            if (!sh->mpm_hcd_ctx_tc->global) {
                mpm_table[sh->mpm_hcd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hcd_ctx_tc);
                SCFree(sh->mpm_hcd_ctx_tc);
            }
            sh->mpm_hcd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_hrud_ctx_ts != NULL) {
        if (sh->mpm_hrud_ctx_ts != NULL) {
            if (!sh->mpm_hrud_ctx_ts->global) {
                mpm_table[sh->mpm_hrud_ctx_ts->mpm_type].DestroyCtx(sh->mpm_hrud_ctx_ts);
                SCFree(sh->mpm_hrud_ctx_ts);
            }
            sh->mpm_hrud_ctx_ts = NULL;
        }
    }

    if (sh->mpm_hsmd_ctx_tc != NULL) {
        if (sh->mpm_hsmd_ctx_tc != NULL) {
            if (!sh->mpm_hsmd_ctx_tc->global) {
                mpm_table[sh->mpm_hsmd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hsmd_ctx_tc);
                SCFree(sh->mpm_hsmd_ctx_tc);
            }
            sh->mpm_hsmd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_hscd_ctx_tc != NULL) {
        if (sh->mpm_hscd_ctx_tc != NULL) {
            if (!sh->mpm_hscd_ctx_tc->global) {
                mpm_table[sh->mpm_hscd_ctx_tc->mpm_type].DestroyCtx(sh->mpm_hscd_ctx_tc);
                SCFree(sh->mpm_hscd_ctx_tc);
            }
            sh->mpm_hscd_ctx_tc = NULL;
        }
    }

    if (sh->mpm_huad_ctx_ts != NULL) {
        if (sh->mpm_huad_ctx_ts != NULL) {
            if (!sh->mpm_huad_ctx_ts->global) {
                mpm_table[sh->mpm_huad_ctx_ts->mpm_type].DestroyCtx(sh->mpm_huad_ctx_ts);
                SCFree(sh->mpm_huad_ctx_ts);
            }
            sh->mpm_huad_ctx_ts = NULL;
        }
    }

    /* dns query */
    if (sh->mpm_dnsquery_ctx_ts != NULL) {
        if (!sh->mpm_dnsquery_ctx_ts->global) {
            mpm_table[sh->mpm_dnsquery_ctx_ts->mpm_type].DestroyCtx(sh->mpm_dnsquery_ctx_ts);
            SCFree(sh->mpm_dnsquery_ctx_ts);
        }
        sh->mpm_dnsquery_ctx_ts = NULL;
    }

    return;
}

/** \brief Hash for looking up contents that are most used,
 *         always used, etc. */
typedef struct ContentHash_ {
    DetectContentData *ptr;
    uint16_t cnt;
    uint8_t use; /* use no matter what */
} ContentHash;

typedef struct UricontentHash_ {
    DetectContentData *ptr;
    uint16_t cnt;
    uint8_t use; /* use no matter what */
} UricontentHash;

uint32_t ContentHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
     ContentHash *ch = (ContentHash *)data;
     DetectContentData *co = ch->ptr;
     uint32_t hash = 0;
     int i;
     for (i = 0; i < co->content_len; i++) {
         hash += co->content[i];
     }
     hash = hash % ht->array_size;
     SCLogDebug("hash %" PRIu32 "", hash);
     return hash;
}

uint32_t UricontentHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
     UricontentHash *ch = (UricontentHash *)data;
     DetectContentData *ud = ch->ptr;
     uint32_t hash = 0;
     int i;
     for (i = 0; i < ud->content_len; i++) {
         hash += ud->content[i];
     }
     hash = hash % ht->array_size;
     SCLogDebug("hash %" PRIu32 "", hash);
     return hash;
}

char ContentHashCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    ContentHash *ch1 = (ContentHash *)data1;
    ContentHash *ch2 = (ContentHash *)data2;
    DetectContentData *co1 = ch1->ptr;
    DetectContentData *co2 = ch2->ptr;

    if (co1->content_len == co2->content_len &&
        ((co1->flags & DETECT_CONTENT_NOCASE) == (co2->flags & DETECT_CONTENT_NOCASE)) &&
        SCMemcmp(co1->content, co2->content, co1->content_len) == 0)
        return 1;

    return 0;
}

char UricontentHashCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    UricontentHash *ch1 = (UricontentHash *)data1;
    UricontentHash *ch2 = (UricontentHash *)data2;
    DetectContentData *ud1 = ch1->ptr;
    DetectContentData *ud2 = ch2->ptr;

    if (ud1->content_len == ud2->content_len &&
        ((ud1->flags & DETECT_CONTENT_NOCASE) == (ud2->flags & DETECT_CONTENT_NOCASE)) &&
        SCMemcmp(ud1->content, ud2->content, ud1->content_len) == 0)
        return 1;

    return 0;
}

ContentHash *ContentHashAlloc(DetectContentData *ptr)
{
    ContentHash *ch = SCMalloc(sizeof(ContentHash));
    if (unlikely(ch == NULL))
        return NULL;

    ch->ptr = ptr;
    ch->cnt = 1;
    ch->use = 0;

    return ch;
}

UricontentHash *UricontentHashAlloc(DetectContentData *ptr)
{
    UricontentHash *ch = SCMalloc(sizeof(UricontentHash));
    if (unlikely(ch == NULL))
        return NULL;

    ch->ptr = ptr;
    ch->cnt = 1;
    ch->use = 0;

    return ch;
}

void ContentHashFree(void *ch)
{
    SCFree(ch);
}

void UricontentHashFree(void *ch)
{
    SCFree(ch);
}

/** \brief Predict a strength value for patterns
 *
 *  Patterns with high character diversity score higher.
 *  Alpha chars score not so high
 *  Other printable + a few common codes a little higher
 *  Everything else highest.
 *  Longer patterns score better than short patters.
 *
 *  \param pat pattern
 *  \param patlen length of the patternn
 *
 *  \retval s pattern score
 */
uint32_t PatternStrength(uint8_t *pat, uint16_t patlen)
{
    uint8_t a[256];
    memset(&a, 0 ,sizeof(a));

    uint32_t s = 0;
    uint16_t u = 0;
    for (u = 0; u < patlen; u++) {
        if (a[pat[u]] == 0) {
            if (isalpha(pat[u]))
                s += 3;
            else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
                s += 4;
            else
                s += 6;

            a[pat[u]] = 1;
        } else {
            s++;
        }
    }

    return s;
}

static void PopulateMpmHelperAddPatternToPktCtx(MpmCtx *mpm_ctx,
                                                DetectContentData *cd,
                                                Signature *s, uint8_t flags,
                                                int chop)
{
    if (cd->flags & DETECT_CONTENT_NOCASE) {
        if (chop) {
            MpmAddPatternCI(mpm_ctx,
                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                            0, 0,
                            cd->id, s->num, flags);
        } else {
            MpmAddPatternCI(mpm_ctx,
                            cd->content, cd->content_len,
                            0, 0,
                            cd->id, s->num, flags);
        }
    } else {
        if (chop) {
            MpmAddPatternCS(mpm_ctx,
                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                            0, 0,
                            cd->id, s->num, flags);
        } else {
            MpmAddPatternCS(mpm_ctx,
                            cd->content, cd->content_len,
                            0, 0,
                            cd->id, s->num, flags);
        }
    }

    return;
}

static void PopulateMpmAddPatternToMpm(DetectEngineCtx *de_ctx,
                                       SigGroupHead *sgh, Signature *s,
                                       SigMatch *mpm_sm)
{
    s->mpm_sm = mpm_sm;

    if (mpm_sm == NULL) {
        SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
        return;
    }

    int sm_list = SigMatchListSMBelongsTo(s, mpm_sm);
    if (sm_list == -1)
        BUG_ON(SigMatchListSMBelongsTo(s, mpm_sm) == -1);

    uint8_t flags = 0;

    DetectContentData *cd = NULL;

    switch (sm_list) {
        case DETECT_SM_LIST_PMATCH:
        {
            cd = (DetectContentData *)mpm_sm->ctx;
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                if (DETECT_CONTENT_IS_SINGLE(cd) &&
                    !(cd->flags & DETECT_CONTENT_NEGATED) &&
                    !(cd->flags & DETECT_CONTENT_REPLACE) &&
                    cd->content_len == cd->fp_chop_len) {
                    cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
                }

                /* add the content to the "packet" mpm */
                if (SignatureHasPacketContent(s)) {
                    if (s->proto.proto[6 / 8] & 1 << (6 % 8)) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_tcp_ctx_ts,
                                                                cd, s, flags, 1);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_tcp_ctx_tc,
                                                                cd, s, flags, 1);
                        }
                    }
                    if (s->proto.proto[17 / 8] & 1 << (17 % 8)) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_udp_ctx_ts,
                                                                cd, s, flags, 1);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_udp_ctx_tc,
                                                                cd, s, flags, 1);
                        }
                    }
                    int i;
                    for (i = 0; i < 256; i++) {
                        if (i == 6 || i == 17)
                            continue;
                        if (s->proto.proto[i / 8] & (1 << (i % 8))) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_other_ctx,
                                                                cd, s, flags, 1);
                            break;
                        }
                    }
                    /* tell matcher we are inspecting packet */
                    s->flags |= SIG_FLAG_MPM_PACKET;
                    s->mpm_pattern_id_div_8 = cd->id / 8;
                    s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                        s->flags |= SIG_FLAG_MPM_PACKET_NEG;
                    }
                }
                if (SignatureHasStreamContent(s)) {
                    if (cd->flags & DETECT_CONTENT_NOCASE) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            MpmAddPatternCI(sgh->mpm_stream_ctx_ts,
                                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            MpmAddPatternCI(sgh->mpm_stream_ctx_tc,
                                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                    } else {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            MpmAddPatternCS(sgh->mpm_stream_ctx_ts,
                                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            MpmAddPatternCS(sgh->mpm_stream_ctx_tc,
                                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                    }
                    /* tell matcher we are inspecting stream */
                    s->flags |= SIG_FLAG_MPM_STREAM;
                    s->mpm_pattern_id_div_8 = cd->id / 8;
                    s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                        s->flags |= SIG_FLAG_MPM_STREAM_NEG;
                    }
                }
            } else {
                if (DETECT_CONTENT_IS_SINGLE(cd) &&
                    !(cd->flags & DETECT_CONTENT_NEGATED) &&
                    !(cd->flags & DETECT_CONTENT_REPLACE)) {
                    cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
                }

                if (SignatureHasPacketContent(s)) {
                    /* add the content to the "packet" mpm */
                    if (s->proto.proto[6 / 8] & 1 << (6 % 8)) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_tcp_ctx_ts,
                                                                cd, s, flags, 0);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_tcp_ctx_tc,
                                                                cd, s, flags, 0);
                        }
                    }
                    if (s->proto.proto[17 / 8] & 1 << (17 % 8)) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_udp_ctx_ts,
                                                                cd, s, flags, 0);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_udp_ctx_tc,
                                                                cd, s, flags, 0);
                        }
                    }
                    int i;
                    for (i = 0; i < 256; i++) {
                        if (i == 6 || i == 17)
                            continue;
                        if (s->proto.proto[i / 8] & (1 << (i % 8))) {
                            PopulateMpmHelperAddPatternToPktCtx(sgh->mpm_proto_other_ctx,
                                                                cd, s, flags, 0);
                            break;
                        }
                    }
                    /* tell matcher we are inspecting packet */
                    s->flags |= SIG_FLAG_MPM_PACKET;
                    s->mpm_pattern_id_div_8 = cd->id / 8;
                    s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                        s->flags |= SIG_FLAG_MPM_PACKET_NEG;
                    }
                }
                if (SignatureHasStreamContent(s)) {
                    /* add the content to the "packet" mpm */
                    if (cd->flags & DETECT_CONTENT_NOCASE) {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            MpmAddPatternCI(sgh->mpm_stream_ctx_ts,
                                            cd->content, cd->content_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            MpmAddPatternCI(sgh->mpm_stream_ctx_tc,
                                            cd->content, cd->content_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                    } else {
                        if (s->flags & SIG_FLAG_TOSERVER) {
                            MpmAddPatternCS(sgh->mpm_stream_ctx_ts,
                                            cd->content, cd->content_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                        if (s->flags & SIG_FLAG_TOCLIENT) {
                            MpmAddPatternCS(sgh->mpm_stream_ctx_tc,
                                            cd->content, cd->content_len,
                                            0, 0,
                                            cd->id, s->num, flags);
                        }
                    }
                    /* tell matcher we are inspecting stream */
                    s->flags |= SIG_FLAG_MPM_STREAM;
                    s->mpm_pattern_id_div_8 = cd->id / 8;
                    s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                        s->flags |= SIG_FLAG_MPM_STREAM_NEG;
                    }
                }
            }
            if (SignatureHasPacketContent(s)) {
                sgh->flags |= SIG_GROUP_HEAD_MPM_PACKET;
            }
            if (SignatureHasStreamContent(s)) {
                sgh->flags |= SIG_GROUP_HEAD_MPM_STREAM;
            }

            break;
        } /* case DETECT_CONTENT */

        case DETECT_SM_LIST_UMATCH:
        case DETECT_SM_LIST_HRUDMATCH:
        case DETECT_SM_LIST_HCBDMATCH:
        case DETECT_SM_LIST_FILEDATA:
        case DETECT_SM_LIST_HHDMATCH:
        case DETECT_SM_LIST_HRHDMATCH:
        case DETECT_SM_LIST_HMDMATCH:
        case DETECT_SM_LIST_HCDMATCH:
        case DETECT_SM_LIST_HSMDMATCH:
        case DETECT_SM_LIST_HSCDMATCH:
        case DETECT_SM_LIST_HUADMATCH:
        case DETECT_SM_LIST_HHHDMATCH:
        case DETECT_SM_LIST_HRHHDMATCH:
        case DETECT_SM_LIST_DNSQUERYNAME_MATCH:
        {
            MpmCtx *mpm_ctx_ts = NULL;
            MpmCtx *mpm_ctx_tc = NULL;

            cd = (DetectContentData *)mpm_sm->ctx;

            if (sm_list == DETECT_SM_LIST_UMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_uri_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_URI;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HCBDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hcbd_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HCBD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_FILEDATA) {
                if (s->flags & SIG_FLAG_TOCLIENT) {
                    mpm_ctx_tc = sgh->mpm_hsbd_ctx_tc;
                    sgh->flags |= SIG_GROUP_HEAD_MPM_HSBD;
                }
                if (s->flags & SIG_FLAG_TOSERVER) {
                    mpm_ctx_ts = sgh->mpm_smtp_filedata_ctx_ts;
                    sgh->flags |= SIG_GROUP_HEAD_MPM_FD_SMTP;
                }
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HHDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hhd_ctx_ts;
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = sgh->mpm_hhd_ctx_tc;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HHD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HRHDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hrhd_ctx_ts;
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = sgh->mpm_hrhd_ctx_tc;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HRHD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HMDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hmd_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HMD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HCDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hcd_ctx_ts;
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = sgh->mpm_hcd_ctx_tc;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HCD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HRUDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hrud_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HRUD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HSMDMATCH) {
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = sgh->mpm_hsmd_ctx_tc;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HSMD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HSCDMATCH) {
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = sgh->mpm_hscd_ctx_tc;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HSCD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HUADMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_huad_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HUAD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HHHDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hhhd_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HHHD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_HRHHDMATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_hrhhd_ctx_ts;
                sgh->flags |= SIG_GROUP_HEAD_MPM_HRHHD;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            } else if (sm_list == DETECT_SM_LIST_DNSQUERYNAME_MATCH) {
                if (s->flags & SIG_FLAG_TOSERVER)
                    mpm_ctx_ts = sgh->mpm_dnsquery_ctx_ts;
                if (s->flags & SIG_FLAG_TOCLIENT)
                    mpm_ctx_tc = NULL;
                sgh->flags |= SIG_GROUP_HEAD_MPM_DNSQUERY;
                s->flags |= SIG_FLAG_MPM_APPLAYER;
                if (cd->flags & DETECT_CONTENT_NEGATED)
                    s->flags |= SIG_FLAG_MPM_APPLAYER_NEG;
            }

            if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                if (DETECT_CONTENT_IS_SINGLE(cd) &&
                    !(cd->flags & DETECT_CONTENT_NEGATED) &&
                    !(cd->flags & DETECT_CONTENT_REPLACE) &&
                    cd->content_len == cd->fp_chop_len) {
                    cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
                }

                /* add the content to the mpm */
                if (cd->flags & DETECT_CONTENT_NOCASE) {
                    if (mpm_ctx_ts != NULL) {
                        MpmAddPatternCI(mpm_ctx_ts,
                                        cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                    if (mpm_ctx_tc != NULL) {
                        MpmAddPatternCI(mpm_ctx_tc,
                                        cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                } else {
                    if (mpm_ctx_ts != NULL) {
                        MpmAddPatternCS(mpm_ctx_ts,
                                        cd->content + cd->fp_chop_offset,
                                        cd->fp_chop_len,
                                        0, 0, cd->id, s->num, flags);
                    }
                    if (mpm_ctx_tc != NULL) {
                        MpmAddPatternCS(mpm_ctx_tc,
                                        cd->content + cd->fp_chop_offset,
                                        cd->fp_chop_len,
                                        0, 0, cd->id, s->num, flags);
                    }
                }
            } else {
                if (DETECT_CONTENT_IS_SINGLE(cd) &&
                    !(cd->flags & DETECT_CONTENT_NEGATED) &&
                    !(cd->flags & DETECT_CONTENT_REPLACE)) {
                    cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
                }

                /* add the content to the "uri" mpm */
                if (cd->flags & DETECT_CONTENT_NOCASE) {
                    if (mpm_ctx_ts != NULL) {
                        MpmAddPatternCI(mpm_ctx_ts,
                                        cd->content, cd->content_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                    if (mpm_ctx_tc != NULL) {
                        MpmAddPatternCI(mpm_ctx_tc,
                                        cd->content, cd->content_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                } else {
                    if (mpm_ctx_ts != NULL) {
                        MpmAddPatternCS(mpm_ctx_ts,
                                        cd->content, cd->content_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                    if (mpm_ctx_tc != NULL) {
                        MpmAddPatternCS(mpm_ctx_tc,
                                        cd->content, cd->content_len,
                                        0, 0,
                                        cd->id, s->num, flags);
                    }
                }
            }
            /* tell matcher we are inspecting uri */
            s->mpm_pattern_id_div_8 = cd->id / 8;
            s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);

            break;
        }
    } /* switch (mpm_sm->type) */

    SCLogDebug("%"PRIu32" adding cd->id %"PRIu32" to the mpm phase "
               "(s->num %"PRIu32")", s->id,
               ((DetectContentData *)mpm_sm->ctx)->id, s->num);

    return;
}

SigMatch *RetrieveFPForSig(Signature *s)
{
    SigMatch *mpm_sm = NULL, *sm = NULL;
    uint8_t has_non_negated_non_stream_pattern = 0;

    if (s->mpm_sm != NULL)
        return s->mpm_sm;

    int list_id;
    for (list_id = 0 ; list_id < DETECT_SM_LIST_MAX; list_id++) {
        /* we have no keywords that support fp in this Signature sm list */
        if (!FastPatternSupportEnabledForSigMatchList(list_id))
            continue;

        for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
            /* this keyword isn't registered for fp support */
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN)
                return sm;
            if (!(cd->flags & DETECT_CONTENT_NEGATED) &&
                (list_id != DETECT_SM_LIST_PMATCH) &&
                (list_id != DETECT_SM_LIST_HMDMATCH) &&
                (list_id != DETECT_SM_LIST_HSMDMATCH) &&
                (list_id != DETECT_SM_LIST_HSCDMATCH)) {
                has_non_negated_non_stream_pattern = 1;
            }
        }
    }

    int max_len = 0;
    int max_len_negated = 0;
    int max_len_non_negated = 0;
    for (list_id = 0; list_id < DETECT_SM_LIST_MAX; list_id++) {
        if (!FastPatternSupportEnabledForSigMatchList(list_id))
            continue;

        if (has_non_negated_non_stream_pattern &&
            ((list_id == DETECT_SM_LIST_PMATCH) ||
             (list_id == DETECT_SM_LIST_HMDMATCH) ||
             (list_id == DETECT_SM_LIST_HSMDMATCH) ||
             (list_id == DETECT_SM_LIST_HSCDMATCH))) {
            continue;
        }

        for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd->flags & DETECT_CONTENT_NEGATED) {
                if (max_len_negated < cd->content_len)
                    max_len_negated = cd->content_len;
            } else {
                if (max_len_non_negated < cd->content_len)
                    max_len_non_negated = cd->content_len;
            }
        }
    }

    int skip_negated_content = 0;
    if (max_len_non_negated == 0) {
        max_len = max_len_negated;
        skip_negated_content = 0;
    } else {
        max_len = max_len_non_negated;
        skip_negated_content = 1;
    }

    for (list_id = 0; list_id < DETECT_SM_LIST_MAX; list_id++) {
        if (!FastPatternSupportEnabledForSigMatchList(list_id))
            continue;

        if (has_non_negated_non_stream_pattern &&
            ((list_id == DETECT_SM_LIST_PMATCH) ||
             (list_id == DETECT_SM_LIST_HMDMATCH) ||
             (list_id == DETECT_SM_LIST_HSMDMATCH) ||
             (list_id == DETECT_SM_LIST_HSCDMATCH))) {
            continue;
        }

        for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if ((cd->flags & DETECT_CONTENT_NEGATED) && skip_negated_content)
                continue;
            if (cd->content_len < max_len)
                continue;

            if (mpm_sm == NULL) {
                mpm_sm = sm;
            } else {
                DetectContentData *data1 = (DetectContentData *)sm->ctx;
                DetectContentData *data2 = (DetectContentData *)mpm_sm->ctx;
                uint32_t ls = PatternStrength(data1->content, data1->content_len);
                uint32_t ss = PatternStrength(data2->content, data2->content_len);
                if (ls > ss) {
                    mpm_sm = sm;
                } else if (ls == ss) {
                    /* if 2 patterns are of equal strength, we pick the longest */
                    if (data1->content_len > data2->content_len)
                        mpm_sm = sm;
                } else {
                    SCLogDebug("sticking with mpm_sm");
                }
            } /* else - if (mpm == NULL) */
        } /* for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) */
    } /* for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) */

    return mpm_sm;
}

SigMatch *RetrieveFPForSigV2(Signature *s)
{
    if (s->mpm_sm != NULL)
        return s->mpm_sm;


    SigMatch *mpm_sm = NULL, *sm = NULL;
    int nn_sm_list[DETECT_SM_LIST_MAX];
    int n_sm_list[DETECT_SM_LIST_MAX];
    memset(nn_sm_list, 0, sizeof(nn_sm_list));
    memset(n_sm_list, 0, sizeof(n_sm_list));
    int count_nn_sm_list = 0;
    int count_n_sm_list = 0;
    int list_id;

    for (list_id = 0; list_id < DETECT_SM_LIST_MAX; list_id++) {
        if (!FastPatternSupportEnabledForSigMatchList(list_id))
            continue;

        for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if ((cd->flags & DETECT_CONTENT_FAST_PATTERN))
                return sm;
            if (cd->flags & DETECT_CONTENT_NEGATED) {
                n_sm_list[list_id] = 1;
                count_n_sm_list++;
            } else {
                nn_sm_list[list_id] = 1;
                count_nn_sm_list++;
            }
        } /* for */
    } /* for */

    int *curr_sm_list = NULL;
    int skip_negated_content = 1;
    if (count_nn_sm_list > 0) {
        curr_sm_list = nn_sm_list;
    } else if (count_n_sm_list > 0) {
        curr_sm_list = n_sm_list;
        skip_negated_content = 0;
    } else {
        return NULL;
    }

    int final_sm_list[DETECT_SM_LIST_MAX];
    int count_final_sm_list = 0;
    int priority;

    SCFPSupportSMList *tmp = sm_fp_support_smlist_list;
    while (tmp != NULL) {
        for (priority = tmp->priority;
             tmp != NULL && priority == tmp->priority;
             tmp = tmp->next) {

            if (curr_sm_list[tmp->list_id] == 0)
                continue;
            final_sm_list[count_final_sm_list++] = tmp->list_id;
        }
        if (count_final_sm_list != 0)
            break;
    }

    BUG_ON(count_final_sm_list == 0);

    int max_len = 0;
    int i;
    for (i = 0; i < count_final_sm_list; i++) {
        for (sm = s->sm_lists[final_sm_list[i]]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            /* skip_negated_content is only set if there's absolutely no
             * non-negated content present in the sig */
            if ((cd->flags & DETECT_CONTENT_NEGATED) && skip_negated_content)
                continue;
            if (max_len < cd->content_len)
                max_len = cd->content_len;
        }
    }

    for (i = 0; i < count_final_sm_list; i++) {
        for (sm = s->sm_lists[final_sm_list[i]]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            /* skip_negated_content is only set if there's absolutely no
             * non-negated content present in the sig */
            if ((cd->flags & DETECT_CONTENT_NEGATED) && skip_negated_content)
                continue;
            if (cd->content_len != max_len)
                continue;

            if (mpm_sm == NULL) {
                mpm_sm = sm;
            } else {
                DetectContentData *data1 = (DetectContentData *)sm->ctx;
                DetectContentData *data2 = (DetectContentData *)mpm_sm->ctx;
                uint32_t ls = PatternStrength(data1->content, data1->content_len);
                uint32_t ss = PatternStrength(data2->content, data2->content_len);
                if (ls > ss) {
                    mpm_sm = sm;
                } else if (ls == ss) {
                    /* if 2 patterns are of equal strength, we pick the longest */
                    if (data1->content_len > data2->content_len)
                        mpm_sm = sm;
                } else {
                    SCLogDebug("sticking with mpm_sm");
                }
            } /* else - if */
        } /* for */
    } /* for */

    return mpm_sm;
}

/**
 * \internal
 * \brief Setup the mpm content.
 *
 * \param de_ctx Pointer to the detect engine context.
 * \param sgh    Pointer to the signature group head against which we are
 *               adding patterns to the mpm ctx.
 *
 * \retval  0 Always.
 */
static int PatternMatchPreparePopulateMpm(DetectEngineCtx *de_ctx,
                                          SigGroupHead *sgh)
{
    uint32_t sig = 0;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;
        PopulateMpmAddPatternToMpm(de_ctx, sgh, s, s->mpm_sm);
    } /* for (sig = 0; sig < sgh->sig_cnt; sig++) */

    return 0;
}

/** \brief Prepare the pattern matcher ctx in a sig group head.
 *
 *  \todo determine if a content match can set the 'single' flag
 *  \todo do error checking
 *  \todo rewrite the COPY stuff
 */
int PatternMatchPrepareGroup(DetectEngineCtx *de_ctx, SigGroupHead *sh)
{
    Signature *s = NULL;
    uint32_t has_co_packet = 0; /**< our sgh has packet payload inspecting content */
    uint32_t has_co_stream = 0; /**< our sgh has stream inspecting content */
    uint32_t has_co_uri = 0;    /**< our sgh has uri inspecting content */
    /* used to indicate if sgh has atleast one sig with http_client_body */
    uint32_t has_co_hcbd = 0;
    /* used to indicate if sgh has atleast one sig with http_server_body */
    uint32_t has_co_hsbd = 0;
    /* used to indicate if sgh has smtp file_data inspecting content */
    uint32_t has_co_smtp = 0;
    /* used to indicate if sgh has atleast one sig with http_header */
    uint32_t has_co_hhd = 0;
    /* used to indicate if sgh has atleast one sig with http_raw_header */
    uint32_t has_co_hrhd = 0;
    /* used to indicate if sgh has atleast one sig with http_method */
    uint32_t has_co_hmd = 0;
    /* used to indicate if sgh has atleast one sig with http_cookie */
    uint32_t has_co_hcd = 0;
    /* used to indicate if sgh has atleast one sig with http_raw_uri */
    uint32_t has_co_hrud = 0;
    /* used to indicate if sgh has atleast one sig with http_stat_msg */
    uint32_t has_co_hsmd = 0;
    /* used to indicate if sgh has atleast one sig with http_stat_code */
    uint32_t has_co_hscd = 0;
    /* used to indicate if sgh has atleast one sig with http_user_agent */
    uint32_t has_co_huad = 0;
    /* used to indicate if sgh has atleast one sig with http_host */
    uint32_t has_co_hhhd = 0;
    /* used to indicate if sgh has atleast one sig with http_raw_host */
    uint32_t has_co_hrhhd = 0;
    //uint32_t cnt = 0;
    uint32_t sig = 0;
    /* sgh has at least one sig with dns_query */
    int has_co_dnsquery = 0;

    /* see if this head has content and/or uricontent */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        s = sh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureHasPacketContent(s) == 1) {
            has_co_packet = 1;
        }
        if (SignatureHasStreamContent(s) == 1) {
            has_co_stream = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL) {
            has_co_uri = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL) {
            has_co_hcbd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_FILEDATA] != NULL) {
            if (s->alproto == ALPROTO_SMTP)
                has_co_smtp = 1;
            else if (s->alproto == ALPROTO_HTTP)
                has_co_hsbd = 1;
            else if (s->alproto == ALPROTO_UNKNOWN) {
                has_co_smtp = 1;
                has_co_hsbd = 1;
            }
        }

        if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL) {
            has_co_hhd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL) {
            has_co_hrhd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL) {
            has_co_hmd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL) {
            has_co_hcd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL) {
            has_co_hrud = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HSMDMATCH] != NULL) {
            has_co_hsmd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HSCDMATCH] != NULL) {
            has_co_hscd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HUADMATCH] != NULL) {
            has_co_huad = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HHHDMATCH] != NULL) {
            has_co_hhhd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_HRHHDMATCH] != NULL) {
            has_co_hrhhd = 1;
        }

        if (s->sm_lists[DETECT_SM_LIST_DNSQUERYNAME_MATCH] != NULL) {
            has_co_dnsquery = 1;
        }
    }

    /* intialize contexes */
    if (has_co_packet) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_proto_tcp_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 0);
            sh->mpm_proto_tcp_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 1);
        } else {
            sh->mpm_proto_tcp_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_proto_tcp_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_proto_tcp_ctx_ts == NULL || sh->mpm_proto_tcp_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_proto_tcp_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }
        MpmInitCtx(sh->mpm_proto_tcp_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_proto_tcp_ctx_tc, de_ctx->mpm_matcher);

        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_proto_udp_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 0);
            sh->mpm_proto_udp_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 1);
        } else {
            sh->mpm_proto_udp_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_proto_udp_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_proto_udp_ctx_ts == NULL || sh->mpm_proto_udp_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_proto_udp_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }
        MpmInitCtx(sh->mpm_proto_udp_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_proto_udp_ctx_tc, de_ctx->mpm_matcher);

        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_proto_other_ctx =
                MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_other_packet, 0);
        } else {
            sh->mpm_proto_other_ctx =
                MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_proto_other_ctx == NULL) {
            SCLogDebug("sh->mpm_proto_other_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }
        MpmInitCtx(sh->mpm_proto_other_ctx, de_ctx->mpm_matcher);
    } /* if (has_co_packet) */

    if (has_co_stream) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_stream_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 0);
            sh->mpm_stream_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 1);
        } else {
            sh->mpm_stream_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_stream_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_stream_ctx_tc == NULL || sh->mpm_stream_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_stream_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }
        MpmInitCtx(sh->mpm_stream_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_stream_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_uri) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_uri_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_uri, 0);
        } else {
            sh->mpm_uri_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_uri_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_uri_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_uri_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hcbd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hcbd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcbd, 0);
        } else {
            sh->mpm_hcbd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_hcbd_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hcbd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hcbd_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hsbd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hsbd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsbd, 1);
        } else {
            sh->mpm_hsbd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hsbd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hsbd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hsbd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_smtp) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_smtp_filedata_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_smtp, 0);
        } else {
            sh->mpm_smtp_filedata_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_smtp_filedata_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_smtp_filedata_ctx_ts == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_smtp_filedata_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hhd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhd, 0);
            sh->mpm_hhd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhd, 1);
        } else {
            sh->mpm_hhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_hhd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hhd_ctx_ts == NULL || sh->mpm_hhd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hhd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hhd_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_hhd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_hrhd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hrhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhd, 0);
            sh->mpm_hrhd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhd, 1);
        } else {
            sh->mpm_hrhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_hrhd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hrhd_ctx_ts == NULL || sh->mpm_hrhd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hrhd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hrhd_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_hrhd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_hmd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hmd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hmd, 0);
        } else {
            sh->mpm_hmd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_hmd_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hmd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hmd_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hcd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hcd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcd, 0);
            sh->mpm_hcd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcd, 1);
        } else {
            sh->mpm_hcd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
            sh->mpm_hcd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hcd_ctx_ts == NULL || sh->mpm_hcd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hcd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hcd_ctx_ts, de_ctx->mpm_matcher);
        MpmInitCtx(sh->mpm_hcd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_hrud) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hrud_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrud, 0);
        } else {
            sh->mpm_hrud_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_hrud_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hrud_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hrud_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hsmd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hsmd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsmd, 1);
        } else {
            sh->mpm_hsmd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hsmd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hsmd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hsmd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_hscd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hscd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hscd, 1);
        } else {
            sh->mpm_hscd_ctx_tc = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 1);
        }
        if (sh->mpm_hscd_ctx_tc == NULL) {
            SCLogDebug("sh->mpm_hscd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hscd_ctx_tc, de_ctx->mpm_matcher);
    }

    if (has_co_huad) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_huad_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_huad, 0);
        } else {
            sh->mpm_huad_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_huad_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_huad_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_huad_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hhhd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hhhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhhd, 0);
        } else {
            sh->mpm_hhhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_hhhd_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hhhd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hhhd_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_hrhhd) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_hrhhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhhd, 0);
        } else {
            sh->mpm_hrhhd_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_hrhhd_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hrhhd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_hrhhd_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_dnsquery) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_dnsquery_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_dnsquery, 0);
        } else {
            sh->mpm_dnsquery_ctx_ts = MpmFactoryGetMpmCtxForProfile(de_ctx, MPM_CTX_FACTORY_UNIQUE_CONTEXT, 0);
        }
        if (sh->mpm_dnsquery_ctx_ts == NULL) {
            SCLogDebug("sh->mpm_hrhhd_ctx == NULL. This should never happen");
            exit(EXIT_FAILURE);
        }

        MpmInitCtx(sh->mpm_dnsquery_ctx_ts, de_ctx->mpm_matcher);
    }

    if (has_co_packet ||
        has_co_stream ||
        has_co_uri ||
        has_co_hcbd ||
        has_co_hsbd ||
        has_co_smtp ||
        has_co_hhd ||
        has_co_hrhd ||
        has_co_hmd ||
        has_co_hcd ||
        has_co_hsmd ||
        has_co_hscd ||
        has_co_hrud ||
        has_co_huad ||
        has_co_hhhd ||
        has_co_hrhhd ||
        has_co_dnsquery)
    {
        PatternMatchPreparePopulateMpm(de_ctx, sh);

        if (sh->mpm_proto_tcp_ctx_ts != NULL) {
            if (sh->mpm_proto_tcp_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_tcp_ctx_ts);
                sh->mpm_proto_tcp_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_proto_tcp_ctx_ts->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_proto_tcp_ctx_ts->mpm_type].
                            Prepare(sh->mpm_proto_tcp_ctx_ts);
                    }
                }
            }
        }
        if (sh->mpm_proto_tcp_ctx_tc != NULL) {
            if (sh->mpm_proto_tcp_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_tcp_ctx_tc);
                sh->mpm_proto_tcp_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_proto_tcp_ctx_tc->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_proto_tcp_ctx_tc->mpm_type].
                            Prepare(sh->mpm_proto_tcp_ctx_tc);
                    }
                }
            }
        }

        if (sh->mpm_proto_udp_ctx_ts != NULL) {
            if (sh->mpm_proto_udp_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_udp_ctx_ts);
                sh->mpm_proto_udp_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_proto_udp_ctx_ts->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_proto_udp_ctx_ts->mpm_type].
                            Prepare(sh->mpm_proto_udp_ctx_ts);
                    }
                }
            }
        }
        if (sh->mpm_proto_udp_ctx_tc != NULL) {
            if (sh->mpm_proto_udp_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_udp_ctx_tc);
                sh->mpm_proto_udp_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_proto_udp_ctx_tc->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_proto_udp_ctx_tc->mpm_type].
                            Prepare(sh->mpm_proto_udp_ctx_tc);
                    }
                }
            }
        }

        if (sh->mpm_proto_other_ctx != NULL) {
            if (sh->mpm_proto_other_ctx->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_other_ctx);
                sh->mpm_proto_other_ctx = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_proto_other_ctx->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_proto_other_ctx->mpm_type].
                            Prepare(sh->mpm_proto_other_ctx);
                    }
                }
            }
        }

        if (sh->mpm_stream_ctx_ts != NULL) {
            if (sh->mpm_stream_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_stream_ctx_ts);
                sh->mpm_stream_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_stream_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_stream_ctx_ts->mpm_type].Prepare(sh->mpm_stream_ctx_ts);
                }
            }
        }
        if (sh->mpm_stream_ctx_tc != NULL) {
            if (sh->mpm_stream_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_stream_ctx_tc);
                sh->mpm_stream_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_stream_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_stream_ctx_tc->mpm_type].Prepare(sh->mpm_stream_ctx_tc);
                }
            }
        }

        if (sh->mpm_uri_ctx_ts != NULL) {
            if (sh->mpm_uri_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_uri_ctx_ts);
                sh->mpm_uri_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_uri_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_uri_ctx_ts->mpm_type].Prepare(sh->mpm_uri_ctx_ts);
                }
            }
        }

        if (sh->mpm_hcbd_ctx_ts != NULL) {
            if (sh->mpm_hcbd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcbd_ctx_ts);
                sh->mpm_hcbd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hcbd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hcbd_ctx_ts->mpm_type].Prepare(sh->mpm_hcbd_ctx_ts);
                }
            }
        }

        if (sh->mpm_hsbd_ctx_tc != NULL) {
            if (sh->mpm_hsbd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hsbd_ctx_tc);
                sh->mpm_hsbd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hsbd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hsbd_ctx_tc->mpm_type].Prepare(sh->mpm_hsbd_ctx_tc);
                }
            }
        }

        if (sh->mpm_smtp_filedata_ctx_ts != NULL) {
            if (sh->mpm_smtp_filedata_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_smtp_filedata_ctx_ts);
                sh->mpm_smtp_filedata_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_smtp_filedata_ctx_ts->mpm_type].Prepare != NULL) {
                        mpm_table[sh->mpm_smtp_filedata_ctx_ts->mpm_type].Prepare(sh->mpm_smtp_filedata_ctx_ts);
                    }
                }
            }
        }

        if (sh->mpm_hhd_ctx_ts != NULL) {
            if (sh->mpm_hhd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhd_ctx_ts);
                sh->mpm_hhd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hhd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hhd_ctx_ts->mpm_type].Prepare(sh->mpm_hhd_ctx_ts);
                }
            }
        }
        if (sh->mpm_hhd_ctx_tc != NULL) {
            if (sh->mpm_hhd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhd_ctx_tc);
                sh->mpm_hhd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hhd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hhd_ctx_tc->mpm_type].Prepare(sh->mpm_hhd_ctx_tc);
                }
            }
        }

        if (sh->mpm_hrhd_ctx_ts != NULL) {
            if (sh->mpm_hrhd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhd_ctx_ts);
                sh->mpm_hrhd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hrhd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hrhd_ctx_ts->mpm_type].Prepare(sh->mpm_hrhd_ctx_ts);
                }
            }
        }
        if (sh->mpm_hrhd_ctx_tc != NULL) {
            if (sh->mpm_hrhd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhd_ctx_tc);
                sh->mpm_hrhd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hrhd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hrhd_ctx_tc->mpm_type].Prepare(sh->mpm_hrhd_ctx_tc);
                }
            }
        }

        if (sh->mpm_hmd_ctx_ts != NULL) {
            if (sh->mpm_hmd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hmd_ctx_ts);
                sh->mpm_hmd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hmd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hmd_ctx_ts->mpm_type].Prepare(sh->mpm_hmd_ctx_ts);
                }
            }
        }

        if (sh->mpm_hcd_ctx_ts != NULL) {
            if (sh->mpm_hcd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcd_ctx_ts);
                sh->mpm_hcd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hcd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hcd_ctx_ts->mpm_type].Prepare(sh->mpm_hcd_ctx_ts);
                }
            }
        }
        if (sh->mpm_hcd_ctx_tc != NULL) {
            if (sh->mpm_hcd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcd_ctx_tc);
                sh->mpm_hcd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hcd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hcd_ctx_tc->mpm_type].Prepare(sh->mpm_hcd_ctx_tc);
                }
            }
        }

        if (sh->mpm_hrud_ctx_ts != NULL) {
            if (sh->mpm_hrud_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrud_ctx_ts);
                sh->mpm_hrud_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hrud_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hrud_ctx_ts->mpm_type].Prepare(sh->mpm_hrud_ctx_ts);
                }
            }
        }

        if (sh->mpm_hsmd_ctx_tc != NULL) {
            if (sh->mpm_hsmd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hsmd_ctx_tc);
                sh->mpm_hsmd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hsmd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hsmd_ctx_tc->mpm_type].Prepare(sh->mpm_hsmd_ctx_tc);
                }
            }
        }

        if (sh->mpm_hscd_ctx_tc != NULL) {
            if (sh->mpm_hscd_ctx_tc->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hscd_ctx_tc);
                sh->mpm_hscd_ctx_tc = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hscd_ctx_tc->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hscd_ctx_tc->mpm_type].Prepare(sh->mpm_hscd_ctx_tc);
                }
            }
        }

        if (sh->mpm_huad_ctx_ts != NULL) {
            if (sh->mpm_huad_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_huad_ctx_ts);
                sh->mpm_huad_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_huad_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_huad_ctx_ts->mpm_type].Prepare(sh->mpm_huad_ctx_ts);
                }
            }
        }

        if (sh->mpm_hhhd_ctx_ts != NULL) {
            if (sh->mpm_hhhd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhhd_ctx_ts);
                sh->mpm_hhhd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hhhd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hhhd_ctx_ts->mpm_type].Prepare(sh->mpm_hhhd_ctx_ts);
                }
            }
        }

        if (sh->mpm_hrhhd_ctx_ts != NULL) {
            if (sh->mpm_hrhhd_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhhd_ctx_ts);
                sh->mpm_hrhhd_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_hrhhd_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_hrhhd_ctx_ts->mpm_type].Prepare(sh->mpm_hrhhd_ctx_ts);
                }
            }
        }

        if (sh->mpm_dnsquery_ctx_ts != NULL) {
            if (sh->mpm_dnsquery_ctx_ts->pattern_cnt == 0) {
                MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_dnsquery_ctx_ts);
                sh->mpm_dnsquery_ctx_ts = NULL;
            } else {
                if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
                    if (mpm_table[sh->mpm_dnsquery_ctx_ts->mpm_type].Prepare != NULL)
                        mpm_table[sh->mpm_dnsquery_ctx_ts->mpm_type].Prepare(sh->mpm_dnsquery_ctx_ts);
                }
            }
        }
    } else {
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_other_ctx);
        sh->mpm_proto_other_ctx = NULL;

        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_tcp_ctx_ts);
        sh->mpm_proto_tcp_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_udp_ctx_ts);
        sh->mpm_proto_udp_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_stream_ctx_ts);
        sh->mpm_stream_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_uri_ctx_ts);
        sh->mpm_uri_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcbd_ctx_ts);
        sh->mpm_hcbd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhd_ctx_ts);
        sh->mpm_hhd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhd_ctx_ts);
        sh->mpm_hrhd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hmd_ctx_ts);
        sh->mpm_hmd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcd_ctx_ts);
        sh->mpm_hcd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrud_ctx_ts);
        sh->mpm_hrud_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_huad_ctx_ts);
        sh->mpm_huad_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhhd_ctx_ts);
        sh->mpm_hhhd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhhd_ctx_ts);
        sh->mpm_hrhhd_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_dnsquery_ctx_ts);
        sh->mpm_dnsquery_ctx_ts = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_smtp_filedata_ctx_ts);
        sh->mpm_smtp_filedata_ctx_ts = NULL;

        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_tcp_ctx_tc);
        sh->mpm_proto_tcp_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_proto_udp_ctx_tc);
        sh->mpm_proto_udp_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_stream_ctx_tc);
        sh->mpm_stream_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hhd_ctx_tc);
        sh->mpm_hhd_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hrhd_ctx_tc);
        sh->mpm_hrhd_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hcd_ctx_tc);
        sh->mpm_hcd_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hsmd_ctx_tc);
        sh->mpm_hsmd_ctx_tc = NULL;
        MpmFactoryReClaimMpmCtx(de_ctx, sh->mpm_hscd_ctx_tc);
        sh->mpm_hscd_ctx_tc = NULL;
    }

    return 0;
}

/** \brief Pattern ID Hash for sharing pattern id's
 *
 *  A per detection engine hash to make sure each pattern has a unique
 *  global id but patterns that are the same share id's.
 */
typedef struct MpmPatternIdTableElmt_ {
    uint8_t *pattern;       /**< ptr to the pattern */
    uint16_t pattern_len;   /**< pattern len */
    PatIntId id;            /**< pattern id */
    uint16_t dup_count;     /**< duplicate count */
    uint8_t sm_list;        /**< SigMatch list */
} MpmPatternIdTableElmt;

/** \brief Hash compare func for MpmPatternId api
 *  \retval 1 patterns are the same
 *  \retval 0 patterns are not the same
 **/
static char MpmPatternIdCompare(void *p1, uint16_t len1, void *p2, uint16_t len2)
{
    SCEnter();
    BUG_ON(len1 < sizeof(MpmPatternIdTableElmt));
    BUG_ON(len2 < sizeof(MpmPatternIdTableElmt));

    MpmPatternIdTableElmt *e1 = (MpmPatternIdTableElmt *)p1;
    MpmPatternIdTableElmt *e2 = (MpmPatternIdTableElmt *)p2;

    if (e1->pattern_len != e2->pattern_len ||
        e1->sm_list != e2->sm_list) {
        SCReturnInt(0);
    }

    if (SCMemcmp(e1->pattern, e2->pattern, e1->pattern_len) != 0) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

/** \brief Hash func for MpmPatternId api
 *  \retval hash hash value
 */
static uint32_t MpmPatternIdHashFunc(HashTable *ht, void *p, uint16_t len)
{
    SCEnter();
    BUG_ON(len < sizeof(MpmPatternIdTableElmt));

    MpmPatternIdTableElmt *e = (MpmPatternIdTableElmt *)p;
    uint32_t hash = e->pattern_len;
    uint16_t u = 0;

    for (u = 0; u < e->pattern_len; u++) {
        hash += e->pattern[u];
    }

    SCReturnUInt(hash % ht->array_size);
}

/** \brief free a MpmPatternIdTableElmt */
static void MpmPatternIdTableElmtFree(void *e)
{
    SCEnter();
    MpmPatternIdTableElmt *c = (MpmPatternIdTableElmt *)e;
    SCFree(c->pattern);
    SCFree(c);
    SCReturn;
}

/** \brief alloc initialize the MpmPatternIdHash */
MpmPatternIdStore *MpmPatternIdTableInitHash(void)
{
    SCEnter();

    MpmPatternIdStore *ht = SCMalloc(sizeof(MpmPatternIdStore));
    BUG_ON(ht == NULL);
    memset(ht, 0x00, sizeof(MpmPatternIdStore));

    ht->hash = HashTableInit(65536, MpmPatternIdHashFunc, MpmPatternIdCompare, MpmPatternIdTableElmtFree);
    BUG_ON(ht->hash == NULL);

    SCReturnPtr(ht, "MpmPatternIdStore");
}

void MpmPatternIdTableFreeHash(MpmPatternIdStore *ht)
{
   SCEnter();

    if (ht == NULL) {
        SCReturn;
    }

    if (ht->hash != NULL) {
        HashTableFree(ht->hash);
    }

    SCFree(ht);
    SCReturn;
}

uint32_t MpmPatternIdStoreGetMaxId(MpmPatternIdStore *ht)
{
    if (ht == NULL) {
        return 0;
    }

    return ht->max_id;
}

/**
 *  \brief Get the pattern id for a content pattern
 *
 *  \param ht mpm pattern id hash table store
 *  \param co content pattern data
 *
 *  \retval id pattern id
 *  \initonly
 */
uint32_t DetectContentGetId(MpmPatternIdStore *ht, DetectContentData *co)
{
    SCEnter();

    BUG_ON(ht == NULL || ht->hash == NULL);

    MpmPatternIdTableElmt *e = NULL;
    MpmPatternIdTableElmt *r = NULL;
    uint32_t id = 0;

    e = SCMalloc(sizeof(MpmPatternIdTableElmt));
    BUG_ON(e == NULL);
    memset(e, 0, sizeof(MpmPatternIdTableElmt));
    e->pattern = SCMalloc(co->content_len);
    BUG_ON(e->pattern == NULL);
    memcpy(e->pattern, co->content, co->content_len);
    e->pattern_len = co->content_len;
    e->id = 0;

    r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
    if (r == NULL) {
        e->id = ht->max_id;
        ht->max_id++;
        id = e->id;

        int ret = HashTableAdd(ht->hash, e, sizeof(MpmPatternIdTableElmt));
        BUG_ON(ret != 0);

        e = NULL;

        ht->unique_patterns++;
    } else {
        id = r->id;

        ht->shared_patterns++;
    }

    if (e != NULL)
        MpmPatternIdTableElmtFree(e);

    SCReturnUInt(id);
}

typedef struct DetectFPAndItsId_ {
    PatIntId id;
    uint16_t content_len;
    uint32_t flags;
    int sm_list;

    uint8_t *content;
} DetectFPAndItsId;

/**
 * \brief Figured out the FP and their respective content ids for all the
 *        sigs in the engine.
 *
 * \param de_ctx Detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectSetFastPatternAndItsId(DetectEngineCtx *de_ctx)
{
    uint32_t struct_total_size = 0;
    uint32_t content_total_size = 0;
    Signature *s = NULL;

    /* Count the amount of memory needed to store all the structures
     * and the content of those structures. This will over estimate the
     * true size, since duplicates are removed below, but counted here.
     */
    for (s = de_ctx->sig_list; s != NULL; s = s->next) {
        s->mpm_sm = RetrieveFPForSigV2(s);
        if (s->mpm_sm != NULL) {
            DetectContentData *cd = (DetectContentData *)s->mpm_sm->ctx;
            struct_total_size += sizeof(DetectFPAndItsId);
            content_total_size += cd->content_len;
        }
    }

    /* array hash buffer - i've run out of ideas to name it */
    uint8_t *ahb = SCMalloc(sizeof(uint8_t) * (struct_total_size + content_total_size));
    if (unlikely(ahb == NULL))
        return -1;

    uint8_t *content = NULL;
    uint8_t content_len = 0;
    PatIntId max_id = 0;
    DetectFPAndItsId *struct_offset = (DetectFPAndItsId *)ahb;
    uint8_t *content_offset = ahb + struct_total_size;
    for (s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->mpm_sm != NULL) {
            int sm_list = SigMatchListSMBelongsTo(s, s->mpm_sm);
            BUG_ON(sm_list == -1);

            DetectContentData *cd = (DetectContentData *)s->mpm_sm->ctx;
            DetectFPAndItsId *dup = (DetectFPAndItsId *)ahb;
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                content = cd->content + cd->fp_chop_offset;
                content_len = cd->fp_chop_len;
            } else {
                content = cd->content;
                content_len = cd->content_len;
            }
            uint32_t flags = cd->flags & DETECT_CONTENT_NOCASE;
            /* Check for content already found on the same list */
            for (; dup != struct_offset; dup++) {
                if (dup->content_len != content_len)
                    continue;
                if (dup->sm_list != sm_list)
                    continue;
                if (dup->flags != flags)
                    continue;
                /* Check for pattern matching a duplicate. Use case insensitive matching
                 * for case insensitive patterns. */
                if (flags & DETECT_CONTENT_NOCASE) {
                    if (SCMemcmpLowercase(dup->content, content, content_len) != 0)
                        continue;
                } else {
                    /* Case sensitive matching */
                    if (SCMemcmp(dup->content, content, content_len) != 0)
                        continue;
                }
                /* Found a match with a previous pattern. */
                break;
            }
            if (dup != struct_offset) {
              /* Exited for-loop before the end, so found an existing match.
               * Use its ID. */
                cd->id = dup->id;
                continue;
            }

            /* Not found, so new content. Give it a new ID and add it
             * to the array.  Copy the content at the end of the
             * content array.
             */
            struct_offset->id = max_id++;
            cd->id = struct_offset->id;
            struct_offset->content_len = content_len;
            struct_offset->sm_list = sm_list;
            struct_offset->content = content_offset;
            struct_offset->flags = flags;

            content_offset += content_len;

            if (flags & DETECT_CONTENT_NOCASE) {
              /* Need to store case-insensitive patterns as lower case
               * because SCMemcmpLowercase() above assumes that all
               * patterns are stored lower case so that it doesn't
               * need to relower its first argument.
               */
              memcpy_tolower(struct_offset->content, content, content_len);
            } else {
              memcpy(struct_offset->content, content, content_len);
            }

            struct_offset++;
        } /* if (s->mpm_sm != NULL) */
    } /* for */

    de_ctx->max_fp_id = max_id;

    SCFree(ahb);

    return 0;
}
