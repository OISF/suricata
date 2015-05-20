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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode IPv6
 */

#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-ipv6.h"
#include "decode-icmpv6.h"
#include "decode-events.h"
#include "defrag.h"
#include "pkt-var.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-unittest.h"
#include "util-profiling.h"
#include "host.h"

#define IPV6_EXTHDRS     ip6eh.ip6_exthdrs
#define IPV6_EH_CNT      ip6eh.ip6_exthdrs_cnt

/**
 * \brief Function to decode IPv4 in IPv6 packets
 *
 */
static void DecodeIPv4inIPv6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t plen, PacketQueue *pq)
{

    if (unlikely(plen < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_IN_IPV6_PKT_TOO_SMALL);
        return;
    }
    if (IP_GET_RAW_VER(pkt) == 4) {
        if (pq != NULL) {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt, plen, DECODE_TUNNEL_IPV4, pq);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_IPV6);
                /* add the tp to the packet queue. */
                PacketEnqueue(pq,tp);
                StatsIncr(tv, dtv->counter_ipv4inipv6);
                return;
            }
        }
    } else {
        ENGINE_SET_EVENT(p, IPV4_IN_IPV6_WRONG_IP_VER);
    }
    return;
}

/**
 * \brief Function to decode IPv6 in IPv6 packets
 *
 */
static int DecodeIP6inIP6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t plen, PacketQueue *pq)
{

    if (unlikely(plen < IPV6_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV6_IN_IPV6_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (IP_GET_RAW_VER(pkt) == 6) {
        if (unlikely(pq != NULL)) {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt, plen, DECODE_TUNNEL_IPV6, pq);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_IPV6);
                PacketEnqueue(pq,tp);
                StatsIncr(tv, dtv->counter_ipv6inipv6);
            }
        }
    } else {
        ENGINE_SET_EVENT(p, IPV6_IN_IPV6_WRONG_IP_VER);
    }
    return TM_ECODE_OK;
}

static void
DecodeIPV6ExtHdrs(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCEnter();

    uint8_t *orig_pkt = pkt;
    uint8_t nh = 0; /* careful, 0 is actually a real type */
    uint16_t hdrextlen;
    uint16_t plen;
    char dstopts = 0;
    char exthdr_fh_done = 0;

    nh = IPV6_GET_NH(p);
    plen = len;

    while(1)
    {
        /* No upper layer, but we do have data. Suspicious. */
        if (nh == IPPROTO_NONE && plen > 0) {
            ENGINE_SET_EVENT(p, IPV6_DATA_AFTER_NONE_HEADER);
            SCReturn;
        }

        if (plen < 2) { /* minimal needed in a hdr */
            SCReturn;
        }

        switch(nh)
        {
            case IPPROTO_TCP:
                IPV6_SET_L4PROTO(p,nh);
                DecodeTCP(tv, dtv, p, pkt, plen, pq);
                SCReturn;

            case IPPROTO_UDP:
                IPV6_SET_L4PROTO(p,nh);
                DecodeUDP(tv, dtv, p, pkt, plen, pq);
                SCReturn;

            case IPPROTO_ICMPV6:
                IPV6_SET_L4PROTO(p,nh);
                DecodeICMPV6(tv, dtv, p, pkt, plen, pq);
                SCReturn;

            case IPPROTO_SCTP:
                IPV6_SET_L4PROTO(p,nh);
                DecodeSCTP(tv, dtv, p, pkt, plen, pq);
                SCReturn;

            case IPPROTO_ROUTING:
                IPV6_SET_L4PROTO(p,nh);
                hdrextlen = 8 + (*(pkt+1) * 8);  /* 8 bytes + length in 8 octet units */

                SCLogDebug("hdrextlen %"PRIu8, hdrextlen);

                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }

                if (p->IPV6_EH_CNT < IPV6_MAX_OPT)
                {
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].type = nh;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].next = *pkt;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].len = hdrextlen;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].data = pkt+2;
                    p->IPV6_EH_CNT++;
                }

                if (IPV6_EXTHDR_ISSET_RH(p)) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_RH);
                    /* skip past this extension so we can continue parsing the rest
                     * of the packet */
                    nh = *pkt;
                    pkt += hdrextlen;
                    plen -= hdrextlen;
                    break;
                }

                IPV6_EXTHDR_SET_RH(p, pkt);

                /** \todo move into own function and load on demand */
                if (IPV6_EXTHDR_RH(p)->ip6rh_type == 0) {
#if 0 // XXX usused and broken, original packet is modified in the memcpy
                    uint8_t i;

                    uint8_t n = hdrextlen / 2;
                    /* because we devide the header len by 2 (as rfc 2460 tells us to)
                     * we devide the result by 8 and not 16 as the header fields are
                     * sized */
                    for (i = 0; i < (n/8) && i < sizeof(IPV6_EXTHDR_RH(p)->ip6rh0_addr)/sizeof(struct in6_addr); ++i) {
                        /* the address header fields are 16 bytes in size */
                        /** \todo do this without memcpy since it's expensive */
                        memcpy(&IPV6_EXTHDR_RH(p)->ip6rh0_addr[i], pkt+(i*16)+8, sizeof(IPV6_EXTHDR_RH(p)->ip6rh0_addr[i]));
                    }
                    IPV6_EXTHDR_RH(p)->ip6rh0_num_addrs = i;
#endif
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_RH_TYPE_0);
                }

                nh = *pkt;
                pkt += hdrextlen;
                plen -= hdrextlen;
                break;

            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            {
                IPV6OptHAO *hao = NULL;
                IPV6OptRA *ra = NULL;
                IPV6OptJumbo *jumbo = NULL;
                uint16_t optslen = 0;

                IPV6_SET_L4PROTO(p,nh);
                hdrextlen =  (*(pkt+1) + 1) << 3;
                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }

                if (p->IPV6_EH_CNT < IPV6_MAX_OPT)
                {
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].type = nh;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].next = *pkt;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].len = hdrextlen;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].data = pkt+2;
                    p->IPV6_EH_CNT++;
                }

                uint8_t *ptr = pkt + 2; /* +2 to go past nxthdr and len */

                /* point the pointers to right structures
                 * in Packet. */
                if (nh == IPPROTO_HOPOPTS) {
                    if (IPV6_EXTHDR_ISSET_HH(p)) {
                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_HH);
                        /* skip past this extension so we can continue parsing the rest
                         * of the packet */
                        nh = *pkt;
                        pkt += hdrextlen;
                        plen -= hdrextlen;
                        break;
                    }

                    IPV6_EXTHDR_SET_HH(p, pkt);
                    hao = &IPV6_EXTHDR_HH_HAO(p);
                    ra = &IPV6_EXTHDR_HH_RA(p);
                    jumbo = &IPV6_EXTHDR_HH_JUMBO(p);

                    optslen = ((IPV6_EXTHDR_HH(p)->ip6hh_len+1)<<3)-2;
                }
                else if (nh == IPPROTO_DSTOPTS)
                {
                    if (dstopts == 0) {
                        IPV6_EXTHDR_SET_DH1(p, pkt);
                        hao = &IPV6_EXTHDR_DH1_HAO(p);
                        ra = &IPV6_EXTHDR_DH1_RA(p);
                        jumbo = &IPV6_EXTHDR_DH2_JUMBO(p);
                        optslen = ((IPV6_EXTHDR_DH1(p)->ip6dh_len+1)<<3)-2;
                        dstopts = 1;
                    } else if (dstopts == 1) {
                        IPV6_EXTHDR_SET_DH2(p, pkt);
                        hao = &IPV6_EXTHDR_DH2_HAO(p);
                        ra = &IPV6_EXTHDR_DH2_RA(p);
                        jumbo = &IPV6_EXTHDR_DH2_JUMBO(p);
                        optslen = ((IPV6_EXTHDR_DH2(p)->ip6dh_len+1)<<3)-2;
                        dstopts = 2;
                    } else {
                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_DH);
                        /* skip past this extension so we can continue parsing the rest
                         * of the packet */
                        nh = *pkt;
                        pkt += hdrextlen;
                        plen -= hdrextlen;
                        break;
                    }
                }

                if (optslen > plen) {
                    /* since the packet is long enough (we checked
                     * plen against hdrlen, the optlen must be malformed. */
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                    /* skip past this extension so we can continue parsing the rest
                     * of the packet */
                    nh = *pkt;
                    pkt += hdrextlen;
                    plen -= hdrextlen;
                    break;
                }
/** \todo move into own function to loaded on demand */
                uint16_t padn_cnt = 0;
                uint16_t other_cnt = 0;
                uint16_t offset = 0;
                while(offset < optslen)
                {
                    if (*ptr == IPV6OPT_PAD1)
                    {
                        padn_cnt++;
                        offset++;
                        ptr++;
                        continue;
                    }

                    if (offset + 1 >= optslen) {
                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                        break;
                    }

                    /* length field for each opt */
                    uint8_t ip6_optlen = *(ptr + 1);

                    /* see if the optlen from the packet fits the total optslen */
                    if ((offset + 1 + ip6_optlen) > optslen) {
                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                        break;
                    }

                    if (*ptr == IPV6OPT_PADN) /* PadN */
                    {
                        //printf("PadN option\n");
                        padn_cnt++;

                        /* a zero padN len would be weird */
                        if (ip6_optlen == 0)
                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_ZERO_LEN_PADN);
                    }
                    else if (*ptr == IPV6OPT_RA) /* RA */
                    {
                        ra->ip6ra_type = *(ptr);
                        ra->ip6ra_len  = ip6_optlen;

                        if (ip6_optlen < sizeof(ra->ip6ra_value)) {
                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                            break;
                        }

                        memcpy(&ra->ip6ra_value, (ptr + 2), sizeof(ra->ip6ra_value));
                        ra->ip6ra_value = ntohs(ra->ip6ra_value);
                        //printf("RA option: type %" PRIu32 " len %" PRIu32 " value %" PRIu32 "\n",
                        //    ra->ip6ra_type, ra->ip6ra_len, ra->ip6ra_value);
                        other_cnt++;
                    }
                    else if (*ptr == IPV6OPT_JUMBO) /* Jumbo */
                    {
                        jumbo->ip6j_type = *(ptr);
                        jumbo->ip6j_len  = ip6_optlen;

                        if (ip6_optlen < sizeof(jumbo->ip6j_payload_len)) {
                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                            break;
                        }

                        memcpy(&jumbo->ip6j_payload_len, (ptr+2), sizeof(jumbo->ip6j_payload_len));
                        jumbo->ip6j_payload_len = ntohl(jumbo->ip6j_payload_len);
                        //printf("Jumbo option: type %" PRIu32 " len %" PRIu32 " payload len %" PRIu32 "\n",
                        //    jumbo->ip6j_type, jumbo->ip6j_len, jumbo->ip6j_payload_len);
                    }
                    else if (*ptr == IPV6OPT_HAO) /* HAO */
                    {
                        hao->ip6hao_type = *(ptr);
                        hao->ip6hao_len  = ip6_optlen;

                        if (ip6_optlen < sizeof(hao->ip6hao_hoa)) {
                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                            break;
                        }

                        memcpy(&hao->ip6hao_hoa, (ptr+2), sizeof(hao->ip6hao_hoa));
                        //printf("HAO option: type %" PRIu32 " len %" PRIu32 " ",
                        //    hao->ip6hao_type, hao->ip6hao_len);
                        //char addr_buf[46];
                        //PrintInet(AF_INET6, (char *)&(hao->ip6hao_hoa),
                        //    addr_buf,sizeof(addr_buf));
                        //printf("home addr %s\n", addr_buf);
                        other_cnt++;
                    } else {
                        if (nh == IPPROTO_HOPOPTS)
                            ENGINE_SET_EVENT(p, IPV6_HOPOPTS_UNKNOWN_OPT);
                        else
                            ENGINE_SET_EVENT(p, IPV6_DSTOPTS_UNKNOWN_OPT);

                        other_cnt++;
                    }
                    uint16_t optlen = (*(ptr + 1) + 2);
                    ptr += optlen; /* +2 for opt type and opt len fields */
                    offset += optlen;
                }
                /* flag packets that have only padding */
                if (padn_cnt > 0 && other_cnt == 0) {
                    if (nh == IPPROTO_HOPOPTS)
                        ENGINE_SET_EVENT(p, IPV6_HOPOPTS_ONLY_PADDING);
                    else
                        ENGINE_SET_EVENT(p, IPV6_DSTOPTS_ONLY_PADDING);
                }

                nh = *pkt;
                pkt += hdrextlen;
                plen -= hdrextlen;
                break;
            }

            case IPPROTO_FRAGMENT:
                IPV6_SET_L4PROTO(p,nh);
                /* store the offset of this extension into the packet
                 * past the ipv6 header. We use it in defrag for creating
                 * a defragmented packet without the frag header */
                if (exthdr_fh_done == 0) {
                    p->ip6eh.fh_offset = pkt - orig_pkt;
                    exthdr_fh_done = 1;
                }

                hdrextlen = sizeof(IPV6FragHdr);
                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }

                /* for the frag header, the length field is reserved */
                if (*(pkt + 1) != 0) {
                    ENGINE_SET_EVENT(p, IPV6_FH_NON_ZERO_RES_FIELD);
                    /* non fatal, lets try to continue */
                }

                if(p->IPV6_EH_CNT<IPV6_MAX_OPT)
                {
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].type = nh;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].next = *pkt;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].len = hdrextlen;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].data = pkt+2;
                    p->IPV6_EH_CNT++;
                }

                if (IPV6_EXTHDR_ISSET_FH(p)) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_FH);
                    nh = *pkt;
                    pkt += hdrextlen;
                    plen -= hdrextlen;
                    break;
                }

                /* set the header ptr first */
                IPV6_EXTHDR_SET_FH(p, pkt);

                /* if FH has offset 0 and no more fragments are coming, we
                 * parse this packet further right away, no defrag will be
                 * needed. It is a useless FH then though, so we do set an
                 * decoder event. */
                if (IPV6_EXTHDR_GET_FH_FLAG(p) == 0 && IPV6_EXTHDR_GET_FH_OFFSET(p) == 0) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_USELESS_FH);

                    nh = *pkt;
                    pkt += hdrextlen;
                    plen -= hdrextlen;
                    break;
                }

                /* the rest is parsed upon reassembly */
                p->flags |= PKT_IS_FRAGMENT;
                SCReturn;

            case IPPROTO_ESP:
            {
                IPV6_SET_L4PROTO(p,nh);
                hdrextlen = sizeof(IPV6EspHdr);
                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }

                if(p->IPV6_EH_CNT<IPV6_MAX_OPT)
                {
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].type = nh;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].next = IPPROTO_NONE;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].len = hdrextlen;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].data = pkt+2;
                    p->IPV6_EH_CNT++;
                }

                if (IPV6_EXTHDR_ISSET_EH(p)) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_EH);
                    SCReturn;
                }

                IPV6_EXTHDR_SET_EH(p, pkt);

                nh = IPPROTO_NONE;
                pkt += hdrextlen;
                plen -= hdrextlen;
                break;
            }
            case IPPROTO_AH:
            {
                IPV6_SET_L4PROTO(p,nh);
                /* we need the header as a minimum */
                hdrextlen = sizeof(IPV6AuthHdr);
                /* the payload len field is the number of extra 4 byte fields,
                 * IPV6AuthHdr already contains the first */
                if (*(pkt+1) > 0)
                    hdrextlen += ((*(pkt+1) - 1) * 4);

                SCLogDebug("hdrextlen %"PRIu8, hdrextlen);

                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }

                IPV6AuthHdr *ahhdr = (IPV6AuthHdr *)pkt;
                if (ahhdr->ip6ah_reserved != 0x0000) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_AH_RES_NOT_NULL);
                }

                if(p->IPV6_EH_CNT < IPV6_MAX_OPT)
                {
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].type = nh;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].next = *pkt;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].len = hdrextlen;
                    p->IPV6_EXTHDRS[p->IPV6_EH_CNT].data = pkt+2;
                    p->IPV6_EH_CNT++;
                }

                if (IPV6_EXTHDR_ISSET_AH(p)) {
                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_DUPL_AH);
                    nh = *pkt;
                    pkt += hdrextlen;
                    plen -= hdrextlen;
                    break;
                }

                IPV6_EXTHDR_SET_AH(p, pkt);

                nh = *pkt;
                pkt += hdrextlen;
                plen -= hdrextlen;
                break;
            }
            case IPPROTO_IPIP:
                IPV6_SET_L4PROTO(p,nh);
                DecodeIPv4inIPv6(tv, dtv, p, pkt, plen, pq);
                SCReturn;
            /* none, last header */
            case IPPROTO_NONE:
                IPV6_SET_L4PROTO(p,nh);
                SCReturn;
            case IPPROTO_ICMP:
                ENGINE_SET_EVENT(p,IPV6_WITH_ICMPV4);
                SCReturn;
            /* no parsing yet, just skip it */
            case IPPROTO_MH:
            case IPPROTO_HIP:
            case IPPROTO_SHIM6:
                hdrextlen = 8 + (*(pkt+1) * 8);  /* 8 bytes + length in 8 octet units */
                if (hdrextlen > plen) {
                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
                    SCReturn;
                }
                nh = *pkt;
                pkt += hdrextlen;
                plen -= hdrextlen;
                break;
            default:
                ENGINE_SET_EVENT(p, IPV6_UNKNOWN_NEXT_HEADER);
                IPV6_SET_L4PROTO(p,nh);
                SCReturn;
        }
    }

    SCReturn;
}

static int DecodeIPV6Packet (ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < IPV6_HEADER_LEN)) {
        return -1;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 6)) {
        SCLogDebug("wrong ip version %" PRIu8 "",IP_GET_RAW_VER(pkt));
        ENGINE_SET_INVALID_EVENT(p, IPV6_WRONG_IP_VER);
        return -1;
    }

    p->ip6h = (IPV6Hdr *)pkt;

    if (unlikely(len < (IPV6_HEADER_LEN + IPV6_GET_PLEN(p))))
    {
        ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_PKT);
        return -1;
    }

    SET_IPV6_SRC_ADDR(p,&p->src);
    SET_IPV6_DST_ADDR(p,&p->dst);

    return 0;
}

int DecodeIPV6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int ret;

    StatsIncr(tv, dtv->counter_ipv6);

    /* do the actual decoding */
    ret = DecodeIPV6Packet (tv, dtv, p, pkt, len);
    if (unlikely(ret < 0)) {
        p->ip6h = NULL;
        return TM_ECODE_FAILED;
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) { /* only convert the addresses if debug is really enabled */
        /* debug print */
        char s[46], d[46];
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), s, sizeof(s));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), d, sizeof(d));
        SCLogDebug("IPV6 %s->%s - CLASS: %" PRIu32 " FLOW: %" PRIu32 " NH: %" PRIu32 " PLEN: %" PRIu32 " HLIM: %" PRIu32 "", s,d,
                IPV6_GET_CLASS(p), IPV6_GET_FLOW(p), IPV6_GET_NH(p), IPV6_GET_PLEN(p),
                IPV6_GET_HLIM(p));
    }
#endif /* DEBUG */

    /* now process the Ext headers and/or the L4 Layer */
    switch(IPV6_GET_NH(p)) {
        case IPPROTO_TCP:
            IPV6_SET_L4PROTO (p, IPPROTO_TCP);
            DecodeTCP(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_UDP:
            IPV6_SET_L4PROTO (p, IPPROTO_UDP);
            DecodeUDP(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_ICMPV6:
            IPV6_SET_L4PROTO (p, IPPROTO_ICMPV6);
            DecodeICMPV6(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_SCTP:
            IPV6_SET_L4PROTO (p, IPPROTO_SCTP);
            DecodeSCTP(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_IPIP:
            IPV6_SET_L4PROTO(p, IPPROTO_IPIP);
            DecodeIPv4inIPv6(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_IPV6:
            DecodeIP6inIP6(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            return TM_ECODE_OK;
        case IPPROTO_FRAGMENT:
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_NONE:
        case IPPROTO_DSTOPTS:
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_MH:
        case IPPROTO_HIP:
        case IPPROTO_SHIM6:
            DecodeIPV6ExtHdrs(tv, dtv, p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p), pq);
            break;
        case IPPROTO_ICMP:
            ENGINE_SET_EVENT(p,IPV6_WITH_ICMPV4);
            break;
        default:
            ENGINE_SET_EVENT(p, IPV6_UNKNOWN_NEXT_HEADER);
            IPV6_SET_L4PROTO (p, IPV6_GET_NH(p));
            break;
    }
    p->proto = IPV6_GET_L4PROTO (p);

    /* Pass to defragger if a fragment. */
    if (IPV6_EXTHDR_ISSET_FH(p)) {
        Packet *rp = Defrag(tv, dtv, p, pq);
        if (rp != NULL) {
            PacketEnqueue(pq,rp);
        }
    }

#ifdef DEBUG
    if (IPV6_EXTHDR_ISSET_FH(p)) {
        SCLogDebug("IPV6 FRAG - HDRLEN: %" PRIuMAX " NH: %" PRIu32 " OFFSET: %" PRIu32 " ID: %" PRIu32 "",
            (uintmax_t)IPV6_EXTHDR_GET_FH_HDRLEN(p), IPV6_EXTHDR_GET_FH_NH(p),
            IPV6_EXTHDR_GET_FH_OFFSET(p), IPV6_EXTHDR_GET_FH_ID(p));
    }
    if (IPV6_EXTHDR_ISSET_RH(p)) {
        SCLogDebug("IPV6 ROUTE - HDRLEN: %" PRIu32 " NH: %" PRIu32 " TYPE: %" PRIu32 "",
            IPV6_EXTHDR_GET_RH_HDRLEN(p), IPV6_EXTHDR_GET_RH_NH(p),
            IPV6_EXTHDR_GET_RH_TYPE(p));
    }
    if (IPV6_EXTHDR_ISSET_HH(p)) {
        SCLogDebug("IPV6 HOPOPT - HDRLEN: %" PRIu32 " NH: %" PRIu32 "",
            IPV6_EXTHDR_GET_HH_HDRLEN(p), IPV6_EXTHDR_GET_HH_NH(p));
    }
    if (IPV6_EXTHDR_ISSET_DH1(p)) {
        SCLogDebug("IPV6 DSTOPT1 - HDRLEN: %" PRIu32 " NH: %" PRIu32 "",
            IPV6_EXTHDR_GET_DH1_HDRLEN(p), IPV6_EXTHDR_GET_DH1_NH(p));
    }
    if (IPV6_EXTHDR_ISSET_DH2(p)) {
        SCLogDebug("IPV6 DSTOPT2 - HDRLEN: %" PRIu32 " NH: %" PRIu32 "",
            IPV6_EXTHDR_GET_DH2_HDRLEN(p), IPV6_EXTHDR_GET_DH2_NH(p));
    }
#endif
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test fragment decoding
 */
static int DecodeIPV6FragTest01 (void)
{

    uint8_t raw_frag1[] = {
        0x60, 0x0f, 0x1a, 0xcf, 0x05, 0xa8, 0x2c, 0x36, 0x20, 0x01, 0x04, 0x70, 0x00, 0x01, 0x00, 0x18,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x09, 0x80, 0x32, 0xb2, 0x00, 0x01,
        0x2e, 0x41, 0x38, 0xff, 0xfe, 0xa7, 0xea, 0xeb, 0x06, 0x00, 0x00, 0x01, 0xdf, 0xf8, 0x11, 0xd7,
        0x00, 0x50, 0xa6, 0x5c, 0xcc, 0xd7, 0x28, 0x9f, 0xc3, 0x34, 0xc6, 0x58, 0x80, 0x10, 0x20, 0x13,
        0x18, 0x1f, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xcd, 0xf9, 0x3a, 0x41, 0x00, 0x1a, 0x91, 0x8a,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x30, 0x32, 0x20, 0x44,
        0x65, 0x63, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20, 0x30, 0x38, 0x3a, 0x33, 0x32, 0x3a, 0x35, 0x37,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d, 0x43, 0x6f, 0x6e, 0x74,
        0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65, 0x0d, 0x0a, 0x50,
        0x72, 0x61, 0x67, 0x6d, 0x61, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65, 0x0d,
        0x0a, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x3a, 0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30,
        0x31, 0x20, 0x4a, 0x61, 0x6e, 0x20, 0x31, 0x39, 0x37, 0x31, 0x20, 0x30, 0x30, 0x3a, 0x30, 0x30,
        0x3a, 0x30, 0x30, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
        0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x31, 0x35, 0x39, 0x39, 0x0d, 0x0a, 0x4b,
        0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c, 0x69, 0x76, 0x65, 0x3a, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f,
        0x75, 0x74, 0x3d, 0x35, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x3d, 0x39, 0x39, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41,
        0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f,
        0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3b, 0x63, 0x68, 0x61, 0x72, 0x73,
        0x65, 0x74, 0x3d, 0x61, 0x73, 0x63, 0x69, 0x69, 0x0d, 0x0a, 0x0d, 0x0a, 0x5f, 0x6a, 0x71, 0x6a,
        0x73, 0x70, 0x28, 0x7b, 0x22, 0x69, 0x70, 0x22, 0x3a, 0x22, 0x32, 0x30, 0x30, 0x31, 0x3a, 0x39,
        0x38, 0x30, 0x3a, 0x33, 0x32, 0x62, 0x32, 0x3a, 0x31, 0x3a, 0x32, 0x65, 0x34, 0x31, 0x3a, 0x33,
        0x38, 0x66, 0x66, 0x3a, 0x66, 0x65, 0x61, 0x37, 0x3a, 0x65, 0x61, 0x65, 0x62, 0x22, 0x2c, 0x22,
        0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22, 0x69, 0x70, 0x76, 0x36, 0x22, 0x2c, 0x22, 0x73, 0x75,
        0x62, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22, 0x22, 0x2c, 0x22, 0x76, 0x69, 0x61, 0x22, 0x3a,
        0x22, 0x22, 0x2c, 0x22, 0x70, 0x61, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x22, 0x3a, 0x22, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };
    uint8_t raw_frag2[] = {
        0x60, 0x0f, 0x1a, 0xcf, 0x00, 0x1c, 0x2c, 0x36, 0x20, 0x01, 0x04, 0x70, 0x00, 0x01, 0x00, 0x18,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x09, 0x80, 0x32, 0xb2, 0x00, 0x01,
        0x2e, 0x41, 0x38, 0xff, 0xfe, 0xa7, 0xea, 0xeb, 0x06, 0x00, 0x05, 0xa0, 0xdf, 0xf8, 0x11, 0xd7,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20,
    };
    Packet *pkt;
    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = PacketGetFromAlloc();
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 0;
    PacketQueue pq;

    FlowInitConfig(FLOW_QUIET);
    DefragInit();

    memset(&pq, 0, sizeof(PacketQueue));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    PacketCopyData(p1, raw_frag1, sizeof(raw_frag1));
    PacketCopyData(p2, raw_frag2, sizeof(raw_frag2));

    DecodeIPV6(&tv, &dtv, p1, GET_PKT_DATA(p1), GET_PKT_LEN(p1), &pq);

    if (!(IPV6_EXTHDR_ISSET_FH(p1))) {
        printf("ipv6 frag header not detected: ");
        goto end;
    }

    DecodeIPV6(&tv, &dtv, p2, GET_PKT_DATA(p2), GET_PKT_LEN(p2), &pq);

    if (!(IPV6_EXTHDR_ISSET_FH(p2))) {
        printf("ipv6 frag header not detected: ");
        goto end;
    }

    if (pq.len != 1) {
        printf("no reassembled packet: ");
        goto end;
    }

    result = 1;
end:
    PACKET_RECYCLE(p1);
    PACKET_RECYCLE(p2);
    SCFree(p1);
    SCFree(p2);
    pkt = PacketDequeue(&pq);
    while (pkt != NULL) {
        PACKET_RECYCLE(pkt);
        SCFree(pkt);
        pkt = PacketDequeue(&pq);
    }
    DefragDestroy();
    FlowShutdown();
    return result;
}

/**
 * \test routing header decode
 */
static int DecodeIPV6RouteTest01 (void)
{

    uint8_t raw_pkt1[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x2b, 0x40,
        0x20, 0x01, 0xaa, 0xaa, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x20, 0x01, 0xaa, 0xaa, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        0xb2, 0xed, 0x00, 0x50, 0x1b, 0xc7, 0x6a, 0xdf,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xfa, 0x87, 0x00, 0x00,
    };
    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 0;
    PacketQueue pq;

    FlowInitConfig(FLOW_QUIET);

    memset(&pq, 0, sizeof(PacketQueue));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    PacketCopyData(p1, raw_pkt1, sizeof(raw_pkt1));

    DecodeIPV6(&tv, &dtv, p1, GET_PKT_DATA(p1), GET_PKT_LEN(p1), &pq);

    if (!(IPV6_EXTHDR_ISSET_RH(p1))) {
        printf("ipv6 routing header not detected: ");
        goto end;
    }

    if (p1->ip6eh.ip6_exthdrs[0].len != 8) {
        printf("ipv6 routing length incorrect: ");
        goto end;
    }

    result = 1;
end:
    PACKET_RECYCLE(p1);
    SCFree(p1);
    FlowShutdown();
    return result;
}

/**
 * \test HOP header decode
 */
static int DecodeIPV6HopTest01 (void)
{
    uint8_t raw_pkt1[] = {
        0x60,0x00,0x00,0x00,0x00,0x20,0x00,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
        0x02,0x0f,0xfe,0xff,0xfe,0x98,0x3d,0x01,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x3a,0x00,0x05,0x02,0x00,0x00,0x00,0x00,
        0x82,0x00,0x1c,0x6f,0x27,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    Packet *p1 = PacketGetFromAlloc();
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 0;
    PacketQueue pq;

    FlowInitConfig(FLOW_QUIET);

    memset(&pq, 0, sizeof(PacketQueue));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    PacketCopyData(p1, raw_pkt1, sizeof(raw_pkt1));

    DecodeIPV6(&tv, &dtv, p1, GET_PKT_DATA(p1), GET_PKT_LEN(p1), &pq);

    if (!(IPV6_EXTHDR_ISSET_HH(p1))) {
        printf("ipv6 routing header not detected: ");
        goto end;
    }

    if (p1->ip6eh.ip6_exthdrs[0].len != 8) {
        printf("ipv6 routing length incorrect: ");
        goto end;
    }

    if (ENGINE_ISSET_EVENT(p1, IPV6_HOPOPTS_UNKNOWN_OPT)) {
        printf("engine event IPV6_HOPOPTS_UNKNOWN_OPT set: ");
        goto end;
    }

    result = 1;
end:
    PACKET_RECYCLE(p1);
    SCFree(p1);
    FlowShutdown();
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for IPV6 decoder
 */

void DecodeIPV6RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeIPV6FragTest01", DecodeIPV6FragTest01, 1);
    UtRegisterTest("DecodeIPV6RouteTest01", DecodeIPV6RouteTest01, 1);
    UtRegisterTest("DecodeIPV6HopTest01", DecodeIPV6HopTest01, 1);
#endif /* UNITTESTS */
}

/**
 * @}
 */
