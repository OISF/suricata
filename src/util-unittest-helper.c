/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * This file provide a set of helper functions for reducing the complexity
 * when constructing unittests
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include <stdarg.h>
#include "detect-engine.h"

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
                           uint16_t ipproto, char *src, char *dst,
                           uint16_t sport, uint16_t dport) {
    uint32_t in[4];

    Packet *p = SCMalloc(sizeof(Packet));
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet");
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(Packet));

    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->payload = payload;
    p->payload_len = payload_len;
    p->proto = ipproto;

    inet_pton(AF_INET6, src, &in);
    p->src.addr_data32[0] = in[0];
    p->src.addr_data32[1] = in[1];
    p->src.addr_data32[2] = in[2];
    p->src.addr_data32[3] = in[3];
    p->sp = sport;

    inet_pton(AF_INET6, dst, &in);
    p->dst.addr_data32[0] = in[0];
    p->dst.addr_data32[1] = in[1];
    p->dst.addr_data32[2] = in[2];
    p->dst.addr_data32[3] = in[3];
    p->dp = dport;

    p->ip6h = SCMalloc(sizeof(IPV6Hdr));
    if (p->ip6h == NULL) {
       SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet ip6h");
        exit(EXIT_FAILURE);
    }
    p->tcph = SCMalloc(sizeof(TCPHdr));
    if (p->tcph == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet tcph");
        exit(EXIT_FAILURE);
    }
    p->tcph->th_sport = sport;
    p->tcph->th_dport = dport;
    return p;
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
                           uint16_t ipproto, char *src, char *dst,
                           uint16_t sport, uint16_t dport) {
    struct in_addr in;

    Packet *p = SCMalloc(sizeof(Packet));
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet");
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(Packet));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = payload;
    p->payload_len = payload_len;
    p->proto = ipproto;

    inet_pton(AF_INET, src, &in);
    p->src.addr_data32[0] = in.s_addr;
    p->sp = sport;

    inet_pton(AF_INET, dst, &in);
    p->dst.addr_data32[0] = in.s_addr;
    p->dp = dport;

    switch (ipproto) {
        case IPPROTO_UDP:
            p->ip4h = SCMalloc(sizeof(IPV4Hdr));
            if (p->ip4h == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet ip4h");
                exit(EXIT_FAILURE);
            }
            p->udph = SCMalloc(sizeof(UDPHdr));
            if (p->udph == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet udph");
                exit(EXIT_FAILURE);
            }
            p->udph->uh_sport = sport;
            p->udph->uh_dport = dport;
        break;
        case IPPROTO_TCP:
            p->ip4h = SCMalloc(sizeof(IPV4Hdr));
            if (p->ip4h == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet ip4h");
                exit(EXIT_FAILURE);
            }
            p->tcph = SCMalloc(sizeof(TCPHdr));
            if (p->tcph == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet tcph");
                exit(EXIT_FAILURE);
            }
            p->tcph->th_sport = sport;
            p->tcph->th_dport = dport;
        break;
        case IPPROTO_ICMP:
            p->ip4h = SCMalloc(sizeof(IPV4Hdr));
            if (p->ip4h == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating packet ip4h");
                exit(EXIT_FAILURE);
            }
        break;
        /* TODO: Add more protocols */
    }
    return p;
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
                           uint16_t ipproto) {
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
Packet **UTHBuildPacketArrayFromEth(uint8_t *raw_eth[], int *pktsize, int numpkts) {
    DecodeThreadVars dtv;
    ThreadVars th_v;
    if (raw_eth == NULL || pktsize == NULL || numpkts <= 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "The arrays cant be null, and the number"
                                        " of packets should be grater thatn zero");
        return NULL;
    }
    Packet **p = NULL;
    p = SCMalloc(sizeof(Packet *) * numpkts);
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for the packet array");
        return NULL;
    }

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    int i = 0;
    for (; i < numpkts; i++) {
        p[i] = SCMalloc(sizeof(Packet));
        if (p[i] == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for a packet of the array");
            SCFree(p);
            return NULL;
        }
        memset(p[i], 0, sizeof(Packet));
        DecodeEthernet(&th_v, &dtv, p[i], raw_eth[i], pktsize[i], NULL);
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
Packet *UTHBuildPacketFromEth(uint8_t *raw_eth, uint16_t pktsize) {
    DecodeThreadVars dtv;
    ThreadVars th_v;
    Packet *p = SCMalloc(sizeof(Packet));
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for the packet");
        return NULL;
    }
    memset(p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DecodeEthernet(&th_v, &dtv, p, raw_eth, pktsize, NULL);
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
                           uint16_t ipproto, char *src, char *dst) {
    return UTHBuildPacketReal(payload, payload_len, ipproto,
                              src, dst,
                              41424, 80);
}

/**
 * \brief UTHBuildPacketSrcDst is a wrapper that build packets specifying IPs
 * and defaulting ports (IPV6)
 *
 * \param payload pointer to the payloadd buffer
 * \param payload_len pointer to the length of the payload
 * \param ipproto Protocols allowed atm are IPPROTO_TCP and IPPROTO_UDP
 *
 * \retval Packet pointer to the built in packet
 */
Packet *UTHBuildPacketIPV6SrcDst(uint8_t *payload, uint16_t payload_len,
                           uint16_t ipproto, char *src, char *dst) {
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
                           uint16_t ipproto, uint16_t sport, uint16_t dport) {
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
void UTHFreePackets(Packet **p, int numpkts) {
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
void UTHFreePacket(Packet *p) {
    if (p == NULL)
        return;

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
    SCFree(p);
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
int UTHGenericTest(Packet **pkt, int numpkts, char *sigs[], uint32_t sids[], uint32_t *results, int numsigs) {

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
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
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
int UTHCheckPacketMatchResults(Packet *p, uint32_t sids[], uint32_t results[], int numsids) {
    if (p == NULL || sids == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Arguments invalid, check if the packet is NULL, and if the array contain sids is set");
        return 0;
    }
    int i = 0;
    int res = 1;
    for (; i < numsids; i++) {
        uint16_t r = PacketAlertCheck(p, sids[i]);
        if (r != results[i]) {
            SCLogInfo("Sid %"PRIu32" matched %"PRIu16" times, and not %"PRIu16" as expected", sids[i], r, results[i]);
            res = 0;
        } else {
            SCLogInfo("Sid %"PRIu32" matched %"PRIu16" times, as expected", sids[i], r);
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
int UTHAppendSigs(DetectEngineCtx *de_ctx, char *sigs[], int numsigs) {
    if (de_ctx == NULL || numsigs <= 0 || sigs == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Arguments invalid, check if sigs or de_ctx are NULL, and if the array contain sigs");
        return 0;
    }
    //SCLogDebug("Adding %d signatures for the current unittest", numsigs);

    Signature *s;
    int i = 0;

    for ( ; i < numsigs; i++) {
        if (sigs[i] == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Check the signature"
                       " at position %d", i);
            return 0;
        }
        s = DetectEngineAppendSig(de_ctx, sigs[i]);
        if (s == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Check the signature at"
                       " position %d (%s)", i, sigs[i]);
            return 0;
        }
    }
    //SCLogDebug("Added %d signatures to the de_ctx of the unittest", i);
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
int UTHMatchPacketsWithResults(DetectEngineCtx *de_ctx, Packet **p, int num_packets, uint32_t sids[], uint32_t *results, int numsigs) {
    int result = 0;

    if (de_ctx == NULL || p == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "packet or de_ctx was null");
        result = 0;
        goto end;
    }

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    //de_ctx->flags |= DE_QUIET;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);
        if (UTHCheckPacketMatchResults(p[i], sids, &results[(i * numsigs)], numsigs) == 0)
            goto cleanup;
    }

    /* so far, so good ;) */
    result = 1;

cleanup:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
end:
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
int UTHMatchPackets(DetectEngineCtx *de_ctx, Packet **p, int num_packets) {
    int result = 1;

    if (de_ctx == NULL || p == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "packet or de_ctx was null");
        result = 0;
        goto end;
    }

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    //de_ctx->flags |= DE_QUIET;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++)
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

    /* Here we don't check if the packet matched or not, because
     * the de_ctx can have multiple signatures, and some of them may match
     * and others may not. That check will be outside
     */
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
end:
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
int UTHPacketMatchSigMpm(Packet *p, char *sig, uint16_t mpm_type) {
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
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL)
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
int UTHPacketMatchSig(Packet *p, char *sig) {
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


#ifdef UNITTESTS
/**
 * \brief CheckUTHTestPacket wrapper to check packets for unittests
 */
int CheckUTHTestPacket(Packet *p, uint16_t ipproto) {
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
            if (p->tcph->th_sport != sport)
                return 0;
            if (p->tcph->th_dport != dport)
                return 0;
        break;
    }
    return 1;
}

/**
 * \brief UTHBuildPacketRealTest01 wrapper to check packets for unittests
 */
int UTHBuildPacketRealTest01(void) {
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
int UTHBuildPacketRealTest02(void) {
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
int UTHBuildPacketTest01(void) {
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

    int ret = CheckUTHTestPacket(p, IPPROTO_TCP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketTest02 wrapper to check packets for unittests
 */
int UTHBuildPacketTest02(void) {
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_UDP);

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);

    return ret;
}

/**
 * \brief UTHBuildPacketSrcDstTest01 wrapper to check packets for unittests
 */
int UTHBuildPacketSrcDstTest01(void) {
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
int UTHBuildPacketSrcDstTest02(void) {
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
int UTHBuildPacketSrcDstPortsTest01(void) {
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
int UTHBuildPacketSrcDstPortsTest02(void) {
    uint8_t payload[] = "Payload";

    Packet *p = UTHBuildPacketSrcDstPorts(payload, sizeof(payload), IPPROTO_UDP,
                                          41424, 80);

    int ret = CheckUTHTestPacket(p, IPPROTO_UDP);
    UTHFreePacket(p);

    return ret;
}

#endif /* UNITTESTS */

void UTHRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("UTHBuildPacketRealTest01", UTHBuildPacketRealTest01, 1);
    UtRegisterTest("UTHBuildPacketRealTest02", UTHBuildPacketRealTest02, 1);
    UtRegisterTest("UTHBuildPacketTest01", UTHBuildPacketTest01, 1);
    UtRegisterTest("UTHBuildPacketTest02", UTHBuildPacketTest02, 1);
    UtRegisterTest("UTHBuildPacketSrcDstTest01", UTHBuildPacketSrcDstTest01, 1);
    UtRegisterTest("UTHBuildPacketSrcDstTest02", UTHBuildPacketSrcDstTest02, 1);
    UtRegisterTest("UTHBuildPacketSrcDstPortsTest01", UTHBuildPacketSrcDstPortsTest01, 1);
    UtRegisterTest("UTHBuildPacketSrcDstPortsTest02", UTHBuildPacketSrcDstPortsTest02, 1);

#endif /* UNITTESTS */
}

