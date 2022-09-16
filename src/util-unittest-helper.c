/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * This file provide a set of helper functions for reducing the complexity
 * when constructing unittests
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-spm-bs.h"
#include "util-unittest.h"
#include "util-error.h"
#include "util-time.h"
#include "util-debug.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "detect-engine-build.h"
#include "detect-engine-sigorder.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect.h"
#include "flow-spare-pool.h"
#include "flow-util.h"
#include "flow-private.h"
#include "decode.h"
#endif

#include "util-unittest-helper.h"

#if defined(UNITTESTS) || defined(FUZZ)
Flow *TestHelperBuildFlow(int family, const char *src, const char *dst, Port sp, Port dp)
{
    struct in_addr in;

    Flow *f = SCMalloc(sizeof(Flow));
    if (unlikely(f == NULL)) {
        printf("FlowAlloc failed\n");
        ;
        return NULL;
    }
    memset(f, 0x00, sizeof(Flow));

    FLOW_INITIALIZE(f);

    if (family == AF_INET) {
        f->flags |= FLOW_IPV4;
    } else if (family == AF_INET6) {
        f->flags |= FLOW_IPV6;
    }

    if (src != NULL) {
        if (family == AF_INET) {
            if (inet_pton(AF_INET, src, &in) != 1) {
                printf("invalid address %s\n", src);
                SCFree(f);
                return NULL;
            }
            f->src.addr_data32[0] = in.s_addr;
        } else {
            BUG_ON(1);
        }
    }
    if (dst != NULL) {
        if (family == AF_INET) {
            if (inet_pton(AF_INET, dst, &in) != 1) {
                printf("invalid address %s\n", dst);
                SCFree(f);
                return NULL;
            }
            f->dst.addr_data32[0] = in.s_addr;
        } else {
            BUG_ON(1);
        }
    }

    f->sp = sp;
    f->dp = dp;

    return f;
}
/** \brief writes the contents of a buffer into a file */
int TestHelperBufferToFile(const char *name, const uint8_t *data, size_t size)
{
    if (remove(name) != 0) {
        if (errno != ENOENT) {
            printf("failed remove, errno=%d\n", errno);
            return -1;
        }
    }
    FILE *fd = fopen(name, "wb");
    if (fd == NULL) {
        printf("failed open, errno=%d\n", errno);
        return -2;
    }
    if (fwrite (data, 1, size, fd) != size) {
        fclose(fd);
        return -3;
    }
    fclose(fd);
    return 0;
}

#endif
#ifdef UNITTESTS

/**
 *  \brief return the uint32_t for a ipv4 address string
 *
 *  \param str Valid ipaddress in string form (e.g. 1.2.3.4)
 *
 *  \retval uint the uin32_t representation
 */
uint32_t UTHSetIPv4Address(const char *str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, str, &in) != 1) {
        printf("invalid IPv6 address %s\n", str);
        exit(EXIT_FAILURE);
    }
    return (uint32_t)in.s_addr;
}

/**
 * \brief UTHBuildPacketReal is a function that create tcp/udp packets for unittests
 * specifying ip and port sources and destinations (IPV6)
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 * \param src pointer to a string containing the ip source
 * \param dst pointer to a string containing the ip destination
 * \param sport pointer to a string containing the port source
 * \param dport pointer to a string containing the port destination
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketIPV6Real(uint8_t *payload, uint16_t payload_len,
                           uint8_t ipproto, const char *src, const char *dst,
                           uint16_t sport, uint16_t dport)
{
    uint32_t in[4];

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return NULL;

    TimeGet(&p->ts);

    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->payload = payload;
    p->payload_len = payload_len;
    p->proto = ipproto;

    p->ip6h = SCMalloc(sizeof(IPV6Hdr));
    if (p->ip6h == NULL)
        goto error;
    memset(p->ip6h, 0, sizeof(IPV6Hdr));
    p->ip6h->s_ip6_nxt = ipproto;
    p->ip6h->s_ip6_plen = htons(payload_len + sizeof(TCPHdr));

    if (inet_pton(AF_INET6, src, &in) != 1)
        goto error;
    p->src.addr_data32[0] = in[0];
    p->src.addr_data32[1] = in[1];
    p->src.addr_data32[2] = in[2];
    p->src.addr_data32[3] = in[3];
    p->sp = sport;
    p->ip6h->s_ip6_src[0] = in[0];
    p->ip6h->s_ip6_src[1] = in[1];
    p->ip6h->s_ip6_src[2] = in[2];
    p->ip6h->s_ip6_src[3] = in[3];

    if (inet_pton(AF_INET6, dst, &in) != 1)
        goto error;
    p->dst.addr_data32[0] = in[0];
    p->dst.addr_data32[1] = in[1];
    p->dst.addr_data32[2] = in[2];
    p->dst.addr_data32[3] = in[3];
    p->dp = dport;
    p->ip6h->s_ip6_dst[0] = in[0];
    p->ip6h->s_ip6_dst[1] = in[1];
    p->ip6h->s_ip6_dst[2] = in[2];
    p->ip6h->s_ip6_dst[3] = in[3];

    p->tcph = SCMalloc(sizeof(TCPHdr));
    if (p->tcph == NULL)
        goto error;
    memset(p->tcph, 0, sizeof(TCPHdr));
    p->tcph->th_sport = htons(sport);
    p->tcph->th_dport = htons(dport);

    SET_PKT_LEN(p, sizeof(IPV6Hdr) + sizeof(TCPHdr) + payload_len);
    return p;

error:
    if (p != NULL) {
        if (p->ip6h != NULL) {
            SCFree(p->ip6h);
        }
        if (p->tcph != NULL) {
            SCFree(p->tcph);
        }
        SCFree(p);
    }
    return NULL;
}

/**
 * \brief UTHBuildPacketReal is a function that create tcp/udp packets for unittests
 * specifying ip and port sources and destinations
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 * \param src pointer to a string containing the ip source
 * \param dst pointer to a string containing the ip destination
 * \param sport pointer to a string containing the port source
 * \param dport pointer to a string containing the port destination
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketReal(uint8_t *payload, uint16_t payload_len,
                           uint8_t ipproto, const char *src, const char *dst,
                           uint16_t sport, uint16_t dport)
{
    struct in_addr in;

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return NULL;

    struct timeval tv;
    TimeGet(&tv);
    COPY_TIMESTAMP(&tv, &p->ts);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = payload;
    p->payload_len = payload_len;
    p->proto = ipproto;

    if (inet_pton(AF_INET, src, &in) != 1)
        goto error;
    p->src.addr_data32[0] = in.s_addr;
    p->sp = sport;

    if (inet_pton(AF_INET, dst, &in) != 1)
        goto error;
    p->dst.addr_data32[0] = in.s_addr;
    p->dp = dport;

    p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    if (p->ip4h == NULL)
        goto error;

    p->ip4h->s_ip_src.s_addr = p->src.addr_data32[0];
    p->ip4h->s_ip_dst.s_addr = p->dst.addr_data32[0];
    p->ip4h->ip_proto = ipproto;
    p->ip4h->ip_verhl = sizeof(IPV4Hdr);
    p->proto = ipproto;

    int hdr_offset = sizeof(IPV4Hdr);
    switch (ipproto) {
        case IPPROTO_UDP:
            p->udph = (UDPHdr *)(GET_PKT_DATA(p) + sizeof(IPV4Hdr));
            if (p->udph == NULL)
                goto error;

            p->udph->uh_sport = sport;
            p->udph->uh_dport = dport;
            hdr_offset += sizeof(UDPHdr);
            break;
        case IPPROTO_TCP:
            p->tcph = (TCPHdr *)(GET_PKT_DATA(p) + sizeof(IPV4Hdr));
            if (p->tcph == NULL)
                goto error;

            p->tcph->th_sport = htons(sport);
            p->tcph->th_dport = htons(dport);
            hdr_offset += sizeof(TCPHdr);
            break;
        case IPPROTO_ICMP:
            p->icmpv4h = (ICMPV4Hdr *)(GET_PKT_DATA(p) + sizeof(IPV4Hdr));
            if (p->icmpv4h == NULL)
                goto error;

            hdr_offset += sizeof(ICMPV4Hdr);
            break;
        default:
            break;
        /* TODO: Add more protocols */
    }

    if (payload && payload_len) {
        PacketCopyDataOffset(p, hdr_offset, payload, payload_len);
    }
    SET_PKT_LEN(p, hdr_offset + payload_len);
    p->payload = GET_PKT_DATA(p)+hdr_offset;

    return p;

error:
    SCFree(p);
    return NULL;
}

/**
 * \brief UTHBuildPacket is a wrapper that build packets with default ip
 * and port fields
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacket(uint8_t *payload, uint16_t payload_len,
                           uint8_t ipproto)
{
    return UTHBuildPacketReal(payload, payload_len, ipproto,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
}

/**
 * \brief UTHBuildPacketArrayFromEth is a wrapper that build a packets from an array of
 *        packets in ethernet rawbytes. Hint: It also share the flows.
 *
 * \param raw_eth pointer to the array of ethernet packets in rawbytes
 * \param pktsize pointer to the array of sizes corresponding to each buffer pointed
 *                from pktsize.
 * \param numpkts number of packets in the array
 *
 * \retval Packet pointer to the array of built in packets; NULL if something fail
 */
Packet **UTHBuildPacketArrayFromEth(uint8_t *raw_eth[], int *pktsize, int numpkts)
{
    DecodeThreadVars dtv;
    ThreadVars th_v;
    if (raw_eth == NULL || pktsize == NULL || numpkts <= 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "The arrays cant be null, and the number"
                                        " of packets should be grater thatn zero");
        return NULL;
    }
    Packet **p = NULL;
    p = SCMalloc(sizeof(Packet *) * numpkts);
    if (unlikely(p == NULL))
        return NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    int i = 0;
    for (; i < numpkts; i++) {
        p[i] = PacketGetFromAlloc();
        if (p[i] == NULL) {
            SCFree(p);
            return NULL;
        }
        DecodeEthernet(&th_v, &dtv, p[i], raw_eth[i], pktsize[i]);
    }
    return p;
}

/**
 * \brief UTHBuildPacketFromEth is a wrapper that build a packet for the rawbytes
 *
 * \param raw_eth pointer to the rawbytes containing an ethernet packet
 *                    (and any other headers inside)
 * \param pktsize pointer to the length of the payload
 *
 * \retval Packet pointer to the built in packet; NULL if something fail
 */
Packet *UTHBuildPacketFromEth(uint8_t *raw_eth, uint16_t pktsize)
{
    DecodeThreadVars dtv;
    ThreadVars th_v;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DecodeEthernet(&th_v, &dtv, p, raw_eth, pktsize);
    return p;
}

/**
 * \brief UTHBuildPacketSrcDst is a wrapper that build packets specifying IPs
 * and defaulting ports
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketSrcDst(uint8_t *payload, uint16_t payload_len,
                             uint8_t ipproto, const char *src, const char *dst)
{
    return UTHBuildPacketReal(payload, payload_len, ipproto,
                              src, dst,
                              41424, 80);
}

/**
 * \brief UTHBuildPacketSrcDst is a wrapper that build packets specifying IPs
 * and defaulting ports (IPV6)
 *
 * \param payload pointer to the payload buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketIPV6SrcDst(uint8_t *payload, uint16_t payload_len,
                           uint8_t ipproto, const char *src, const char *dst)
{
    return UTHBuildPacketIPV6Real(payload, payload_len, ipproto,
                              src, dst,
                              41424, 80);
}

/**
 * \brief UTHBuildPacketSrcDstPorts is a wrapper that build packets specifying
 * src and dst ports and defaulting IPs
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketSrcDstPorts(uint8_t *payload, uint16_t payload_len,
                           uint8_t ipproto, uint16_t sport, uint16_t dport)
{
    return UTHBuildPacketReal(payload, payload_len, ipproto,
                              "192.168.1.5", "192.168.1.1",
                              sport, dport);
}

/**
 * \brief UTHFreePackets: function to release the allocated data
 * from UTHBuildPacket and the packet itself
 *
 * \param p pointer to the Packet
 */
void UTHFreePackets(Packet **p, int numpkts)
{
    if (p == NULL)
        return;

    int i = 0;
    for (; i < numpkts; i++) {
        UTHFreePacket(p[i]);
    }
}

/**
 * \brief UTHFreePacket: function to release the allocated data
 * from UTHBuildPacket and the packet itself
 *
 * \param p pointer to the Packet
 */
void UTHFreePacket(Packet *p)
{
    if (p == NULL)
        return;
#if 0 // VJ we now use one buffer
    switch (p->proto) {
        case IPPROTO_UDP:
            if (p->udph != NULL)
                SCFree(p->udph);
            if (p->ip4h != NULL)
                SCFree(p->ip4h);
        break;
        case IPPROTO_TCP:
            if (p->tcph != NULL)
                SCFree(p->tcph);
            if (p->ip4h != NULL)
                SCFree(p->ip4h);
        break;
        case IPPROTO_ICMP:
            if (p->ip4h != NULL)
                SCFree(p->ip4h);
        break;
        /* TODO: Add more protocols */
    }
#endif
    SCFree(p);
}

void UTHAssignFlow(Packet *p, Flow *f)
{
    if (p && f) {
        p->flow = f;
        p->flags |= PKT_HAS_FLOW;
    }
}

Flow *UTHBuildFlow(int family, const char *src, const char *dst, Port sp, Port dp)
{
    return TestHelperBuildFlow(family, src, dst, sp, dp);
}

void UTHFreeFlow(Flow *flow)
{
    if (flow != NULL) {
        SCFree(flow);//FlowFree(flow);
    }
}

int UTHAddStreamToFlow(Flow *f, int direction,
    uint8_t *data, uint32_t data_len)
{
    FAIL_IF_NULL(f);
    FAIL_IF_NOT(f->proto == IPPROTO_TCP);
    FAIL_IF_NULL(f->protoctx);
    TcpSession *ssn = f->protoctx;

    StreamingBufferSegment seg;
    TcpStream *stream = direction == 0 ? &ssn->client : &ssn->server;
    int r = StreamingBufferAppend(&stream->sb, &seg, data, data_len);
    FAIL_IF_NOT(r == 0);
    stream->last_ack += data_len;
    return 1;
}

int UTHAddSessionToFlow(Flow *f,
    uint32_t ts_isn,
    uint32_t tc_isn)
{
    FAIL_IF_NULL(f);

    TcpSession *ssn = SCCalloc(1, sizeof(*ssn));
    FAIL_IF_NULL(ssn);

    StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    ssn->client.sb = x;
    ssn->server.sb = x;

    ssn->client.isn = ts_isn;
    ssn->server.isn = tc_isn;

    f->protoctx = ssn;
    return 1;
}

int UTHRemoveSessionFromFlow(Flow *f)
{
    FAIL_IF_NULL(f);
    FAIL_IF_NOT(f->proto == IPPROTO_TCP);
    TcpSession *ssn = f->protoctx;
    FAIL_IF_NULL(ssn);
    StreamTcpSessionCleanup(ssn);
    SCFree(ssn);
    f->protoctx = NULL;
    return 1;
}

/**
 * \brief UTHGenericTest: function that perfom a generic check taking care of
 *                      as maximum common unittest elements as possible.
 *                      It will create a detection engine, append an array
 *                      of signatures an check the spected results for each
 *                      of them, it check matches for an array of packets
 *
 * \param pkt pointer to the array of packets
 * \param numpkts number of packets to match
 * \param sigs array of char* pointing to signatures to load
 * \param numsigs number of signatures to load and check
 * \param results pointer to arrays of numbers, each of them foreach packet
 *                to check if sids matches that packet as expected with
 *                that number of times or not. The size of results should be
 *                numpkts * numsigs * sizeof(uint16_t *)
 *
 *                Example:
 *                result[1][3] would mean the number of times the pkt[1]
 *                match the sid[3]
 *
 * \retval int 1 if the match of all the sids is the specified has the
 *             specified results; 0 if not
 */
int UTHGenericTest(Packet **pkt, int numpkts, const char *sigs[], uint32_t sids[], uint32_t *results, int numsigs)
{

    int result = 0;
    if (pkt == NULL || sigs == NULL || numpkts == 0
        || sids == NULL || results == NULL || numsigs == 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Arguments invalid, that the pointer/arrays are not NULL, and the number of signatures and packets is > 0");
        goto end;
    }
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, numsigs) == 0)
        goto cleanup;

    result = UTHMatchPacketsWithResults(de_ctx, pkt, numpkts, sids, results, numsigs);

cleanup:
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \brief UTHCheckPacketMatches: function to check if a packet match some sids
 *
 *
 * \param p pointer to the Packet
 * \param sigs array of char* pointing to signatures to load
 * \param numsigs number of signatures to load from the array
 * \param results pointer to an array of numbers to check if sids matches
 *                that number of times or not.
 *
 * \retval int 1 if the match of all the sids is the specified has the
 *             specified results; 0 if not
 */
int UTHCheckPacketMatchResults(Packet *p, uint32_t sids[],
        uint32_t results[], int numsids)
{
    if (p == NULL || sids == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Arguments invalid, check if the "
                "packet is NULL, and if the array contain sids is set");
        return 0;
    }

    int i = 0;
    int res = 1;
    for (; i < numsids; i++) {
        uint32_t r = PacketAlertCheck(p, sids[i]);
        if (r != results[i]) {
            SCLogInfo("Sid %" PRIu32 " matched %" PRIu32 " times, and not %" PRIu32 " as expected",
                    sids[i], r, results[i]);
            res = 0;
        } else {
            SCLogInfo("Sid %" PRIu32 " matched %" PRIu32 " times, as expected", sids[i], r);
        }
    }
    return res;
}

/**
 * \brief UTHAppendSigs: Add sigs to the detection_engine checking for errors
 *
 * \param de_ctx pointer to the DetectEngineCtx used
 * \param sigs array of char* pointing to signatures to load
 * \param numsigs number of signatures to load from the array
 *                (size of the array)
 *
 * \retval int 0 if we have errors; 1 if all the signatures loaded succesfuly
 */
int UTHAppendSigs(DetectEngineCtx *de_ctx, const char *sigs[], int numsigs)
{
    BUG_ON(de_ctx == NULL);
    BUG_ON(numsigs <= 0);
    BUG_ON(sigs == NULL);

    for (int i = 0; i < numsigs; i++) {
        if (sigs[i] == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Check the signature"
                       " at position %d", i);
            return 0;
        }
        Signature *s = DetectEngineAppendSig(de_ctx, sigs[i]);
        if (s == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Check the signature at"
                       " position %d (%s)", i, sigs[i]);
            return 0;
        }
    }
    return 1;
}

/**
 * \test UTHMatchPacketsWithResults Match a packet or a array of packets against sigs
 * of a de_ctx, checking that each signature match match X times for certain packets
 *
 * \param de_ctx pointer with the signatures loaded
 * \param p pointer to the array of packets
 * \param num_packets number of packets in the array
 *
 * \retval return 1 if all goes well
 * \retval return 0 if something fail
 */
int UTHMatchPacketsWithResults(DetectEngineCtx *de_ctx, Packet **p, int num_packets, uint32_t sids[], uint32_t *results, int numsigs)
{
    BUG_ON(de_ctx == NULL);
    BUG_ON(p == NULL);

    int result = 0;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    for (int i = 0; i < num_packets; i++) {
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);
        if (UTHCheckPacketMatchResults(p[i], sids, &results[(i * numsigs)], numsigs) == 0)
            goto cleanup;
    }

    result = 1;
cleanup:
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    return result;
}

/**
 * \test UTHMatchPackets Match a packet or a array of packets against sigs
 * of a de_ctx, but note that the return value doesn't mean that we have a
 * match, we have to check it later with PacketAlertCheck()
 *
 * \param de_ctx pointer with the signatures loaded
 * \param p pointer to the array of packets
 * \param num_packets number of packets in the array
 *
 * \retval return 1 if all goes well
 * \retval return 0 if something fail
 */
int UTHMatchPackets(DetectEngineCtx *de_ctx, Packet **p, int num_packets)
{
    BUG_ON(de_ctx == NULL);
    BUG_ON(p == NULL);
    int result = 1;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));
    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    for (int i = 0; i < num_packets; i++)
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

    /* Here we don't check if the packet matched or not, because
     * the de_ctx can have multiple signatures, and some of them may match
     * and others may not. That check will be outside
     */
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    return result;
}

/**
 * \test Test if a packet match a signature given as string and a mpm_type
 * Hint: Useful for unittests with only one packet and one signature
 *
 * \param sig pointer to the string signature to test
 * \param sid sid number of the signature
 *
 * \retval return 1 if match
 * \retval return 0 if not
 */
int UTHPacketMatchSigMpm(Packet *p, char *sig, uint16_t mpm_type)
{
    SCEnter();

    int result = 0;

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
        printf("signature didn't alert: ");
        goto end;
    }

    result = 1;
end:
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCReturnInt(result);
}

/**
 * \test Test if a packet match a signature given as string
 * Hint: Useful for unittests with only one packet and one signature
 *
 * \param sig pointer to the string signature to test
 * \param sid sid number of the signature
 *
 * \retval return 1 if match
 * \retval return 0 if not
 */
int UTHPacketMatchSig(Packet *p, const char *sig)
{
    int result = 1;

    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result=0;
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig);
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, de_ctx->sig_list->id) != 1) {
        result = 0;
        goto end;
    }

end:
    if (de_ctx) {
	SigGroupCleanup(de_ctx);
	SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    return result;
}

uint32_t UTHBuildPacketOfFlows(uint32_t start, uint32_t end, uint8_t dir)
{
    FlowLookupStruct fls;
    memset(&fls, 0, sizeof(fls));

    uint32_t i = start;
    uint8_t payload[] = "Payload";
    for (; i < end; i++) {
        Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);
        if (dir == 0) {
            p->src.addr_data32[0] = i;
            p->dst.addr_data32[0] = i + 1;
        } else {
            p->src.addr_data32[0] = i + 1;
            p->dst.addr_data32[0] = i;
        }
        FlowHandlePacket(NULL, &fls, p);
        if (p->flow != NULL) {
            p->flow->use_cnt = 0;
            FLOWLOCK_UNLOCK(p->flow);
        }

        /* Now the queues shoul be updated */
        UTHFreePacket(p);
    }

    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(&fls.spare_queue))) {
        FlowFree(f);
    }
    while ((f = FlowQueuePrivateGetFromTop(&fls.work_queue))) {
        FlowFree(f);
    }

    return i;
}

/** \brief parser a sig and see if the expected result is correct */
int UTHParseSignature(const char *str, bool expect)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, str);
    if (expect)
        FAIL_IF_NULL(s);
    else
        FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/*
 * unittests for the unittest helpers
 */

/**
 * \brief CheckUTHTestPacket wrapper to check packets for unittests
 */
static int CheckUTHTestPacket(Packet *p, uint8_t ipproto)
{
    uint16_t sport = 41424;
    uint16_t dport = 80;
    uint8_t payload[] = "Payload";

    uint8_t len = sizeof(payload);

    if (p == NULL)
        return 0;

    if (p->payload_len != len)
        return 0;

    if (strncmp((char *)payload, (char *)p->payload, len) != 0)
        return 0;

    if (p->src.family != AF_INET)
        return 0;
    if (p->dst.family != AF_INET)
        return 0;
    if (p->proto != ipproto)
        return 0;

    switch(ipproto) {
        case IPPROTO_UDP:
            if (p->udph == NULL)
                return 0;
            if (p->udph->uh_sport != sport)
                return 0;
            if (p->udph->uh_dport != dport)
                return 0;
        break;
        case IPPROTO_TCP:
            if (p->tcph == NULL)
                return 0;
            if (SCNtohs(p->tcph->th_sport) != sport)
                return 0;
            if (SCNtohs(p->tcph->th_dport) != dport)
                return 0;
        break;
    }
    return 1;
}

#ifdef HAVE_MEMMEM
#include <string.h>
void * UTHmemsearch(const void *big, size_t big_len, const void *little, size_t little_len) {
    return memmem(big, big_len, little, little_len);
}
#else
void * UTHmemsearch(const void *big, size_t big_len, const void *little, size_t little_len) {
    return BasicSearch(big, big_len, little, little_len);
}
#endif //HAVE_MEMMEM

/**
 * \brief UTHBuildPacketRealTest01 wrapper to check packets for unittests
 */
static int UTHBuildPacketRealTest01(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketReal(payload, sizeof(payload), IPPROTO_TCP,
                                   "192.168.1.5", "192.168.1.1", 41424, 80);

    int ret = CheckUTHTestPacket(p, IPPROTO_TCP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketRealTest02 wrapper to check packets for unittests
 */
static int UTHBuildPacketRealTest02(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketReal(payload, sizeof(payload), IPPROTO_UDP,
                                   "192.168.1.5", "192.168.1.1", 41424, 80);

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);
    return ret;
}

/**
 * \brief UTHBuildPacketTest01 wrapper to check packets for unittests
 */
static int UTHBuildPacketTest01(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

    int ret = CheckUTHTestPacket(p, IPPROTO_TCP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketTest02 wrapper to check packets for unittests
 */
static int UTHBuildPacketTest02(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_UDP);

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketOfFlowsTest01 wrapper to check packets for unittests
 */
static int UTHBuildPacketOfFlowsTest01(void)
{
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    uint32_t flow_spare_q_len = FlowSpareGetPoolSize();

    UTHBuildPacketOfFlows(0, 100, 0);

    if (FlowSpareGetPoolSize() != flow_spare_q_len - 100)
        result = 0;
    else
        result = 1;
    FlowShutdown();

    return result;
}


/**
 * \brief UTHBuildPacketSrcDstTest01 wrapper to check packets for unittests
 */
static int UTHBuildPacketSrcDstTest01(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketSrcDst(payload, sizeof(payload), IPPROTO_TCP,
                                     "192.168.1.5", "192.168.1.1");

    int ret = CheckUTHTestPacket(p, IPPROTO_TCP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketSrcDstTest02 wrapper to check packets for unittests
 */
static int UTHBuildPacketSrcDstTest02(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketSrcDst(payload, sizeof(payload), IPPROTO_UDP,
                                     "192.168.1.5", "192.168.1.1");

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketSrcDstPortsTest01 wrapper to check packets for unittests
 */
static int UTHBuildPacketSrcDstPortsTest01(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketSrcDstPorts(payload, sizeof(payload), IPPROTO_TCP,
                                          41424, 80);

    int ret = CheckUTHTestPacket(p, IPPROTO_TCP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketSrcDstPortsTest02 wrapper to check packets for unittests
 */
static int UTHBuildPacketSrcDstPortsTest02(void)
{
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketSrcDstPorts(payload, sizeof(payload), IPPROTO_UDP,
                                          41424, 80);

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);

    return ret;
}

#endif /* UNITTESTS */

void UTHRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("UTHBuildPacketRealTest01", UTHBuildPacketRealTest01);
    UtRegisterTest("UTHBuildPacketRealTest02", UTHBuildPacketRealTest02);
    UtRegisterTest("UTHBuildPacketTest01", UTHBuildPacketTest01);
    UtRegisterTest("UTHBuildPacketTest02", UTHBuildPacketTest02);
    UtRegisterTest("UTHBuildPacketSrcDstTest01", UTHBuildPacketSrcDstTest01);
    UtRegisterTest("UTHBuildPacketSrcDstTest02", UTHBuildPacketSrcDstTest02);
    UtRegisterTest("UTHBuildPacketSrcDstPortsTest01",
                   UTHBuildPacketSrcDstPortsTest01);
    UtRegisterTest("UTHBuildPacketSrcDstPortsTest02",
                   UTHBuildPacketSrcDstPortsTest02);
    UtRegisterTest("UTHBuildPacketOfFlowsTest01", UTHBuildPacketOfFlowsTest01);

#endif /* UNITTESTS */
}

