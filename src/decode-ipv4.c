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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Decode IPv4
 */

#include "suricata-common.h"
#include "decode-ipv4.h"
#include "defrag.h"
#include "pkt-var.h"

#include "util-unittest.h"
#include "util-profiling.h"

#ifdef DEBUG
#include "util-print.h"
#include "util-optimize.h"
#include "util-debug.h"
#include "host.h"
#include "decode-events.h"
#include "decode.h"
#include "packet-queue.h"
#endif
/* Generic validation
 *
 * [--type--][--len---]
 *
 * \todo This function needs removed in favor of specific validation.
 *
 * See: RFC 791
 */
static int IPV4OptValidateGeneric(Packet *p, const IPV4Opt *o)
{
    switch (o->type) {
        /* See: RFC 4782 */
        case IPV4_OPT_QS:
            if (o->len < IPV4_OPT_QS_MIN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        /* See: RFC 1108 */
        case IPV4_OPT_SEC:
            if (o->len != IPV4_OPT_SEC_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        case IPV4_OPT_SID:
            if (o->len != IPV4_OPT_SID_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        /* See: RFC 2113 */
        case IPV4_OPT_RTRALT:
            if (o->len != IPV4_OPT_RTRALT_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        default:
            /* Should never get here unless there is a coding error */
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_UNKNOWN);
            return -1;
    }

    return 0;
}

/* Validate route type options
 *
 * [--type--][--len---][--ptr---][address1]...[addressN]
 *
 * See: RFC 791
 */
static int IPV4OptValidateRoute(Packet *p, const IPV4Opt *o)
{
    uint8_t ptr;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_ROUTE_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    ptr = *o->data;

    /* Address pointer is 1 based and points at least after type+len+ptr,
     * must be a incremented by 4 bytes (address size) and cannot extend
     * past option length.
     */
    if (unlikely((ptr < 4) || (ptr % 4) || (ptr > o->len + 1))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }

    return 0;
}

/* Validate timestamp type options
 *
 * [--type--][--len---][--ptr---][ovfl][flag][rec1----...]...[recN----...]
 * NOTE: rec could be 4 (ts only) or 8 (ip+ts) bytes in length.
 *
 * See: RFC 781
 */
static int IPV4OptValidateTimestamp(Packet *p, const IPV4Opt *o)
{
    uint8_t ptr;
    uint8_t flag;
    uint8_t rec_size;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_TS_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    ptr = *o->data;

    /* We need the flag to determine what is in the option payload */
    if (unlikely(ptr < 5)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    flag = *(o->data + 1) & 0x0f;

    /* A flag of 1|3 means we have both the ip+ts in each record */
    rec_size = ((flag == 1) || (flag == 3)) ? 8 : 4;

    /* Address pointer is 1 based and points at least after
     * type+len+ptr+ovfl+flag, must be incremented by by the rec_size
     * and cannot extend past option length.
     */
    if (unlikely(((ptr - 5) % rec_size) || (ptr > o->len + 1))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }

    return 0;
}

/* Validate CIPSO option
 *
 * [--type--][--len---][--doi---][tags--...]
 *
 * See: draft-ietf-cipso-ipsecurity-01.txt
 * See: FIPS 188 (tags 6 & 7)
 */
static int IPV4OptValidateCIPSO(Packet *p, const IPV4Opt *o)
{
//    uint32_t doi;
    const uint8_t *tag;
    uint16_t len;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_CIPSO_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
//    doi = *o->data;
    tag = o->data + 4;
    len = o->len - 1 - 1 - 4; /* Length of tags after header */


#if 0
    /* Domain of Interest (DOI) of 0 is reserved and thus invalid */
    /** \todo Aparently a DOI of zero is fine in practice - verify. */
    if (doi == 0) {
        ENGINE_SET_EVENT(p,IPV4_OPT_MALFORMED);
        return -1;
    }
#endif

    /* NOTE: We know len has passed min tests prior to this call */

    /* Check that tags are formatted correctly
     * [-ttype--][--tlen--][-tagdata-...]
     */
    while (len) {
        uint8_t ttype;
        uint8_t tlen;

        /* Tag header must fit within option length */
        if (unlikely(len < 2)) {
            //printf("CIPSO tag header too large %" PRIu16 " < 2\n", len);
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
            return -1;
        }

        /* Tag header is type+len */
        ttype = *(tag++);
        tlen = *(tag++);

        /* Tag length must fit within the option length */
        if (unlikely(tlen > len)) {
            //printf("CIPSO tag len too large %" PRIu8 " > %" PRIu16 "\n", tlen, len);
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
            return -1;
        }

        switch(ttype) {
            case 1:
            case 2:
            case 5:
            case 6:
            case 7:
                /* Tag is at least 4 and at most the remainder of option len */
                if (unlikely((tlen < 4) || (tlen > len))) {
                    //printf("CIPSO tag %" PRIu8 " bad tlen=%" PRIu8 " len=%" PRIu8 "\n", ttype, tlen, len);
                    ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                    return -1;
                }

                /* The alignment octet is always 0 except tag
                 * type 7, which has no such field.
                 */
                if (unlikely((ttype != 7) && (*tag != 0))) {
                    //printf("CIPSO tag %" PRIu8 " ao=%" PRIu8 "\n", ttype, tlen);
                    ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                    return -1;
                }

                /* Skip the rest of the tag payload */
                tag += tlen - 2;
                len -= tlen;

                continue;
            case 0:
                /* Tag type 0 is reserved and thus invalid */
                /** \todo Wireshark marks this a padding, but spec says reserved. */
                ENGINE_SET_INVALID_EVENT(p,IPV4_OPT_MALFORMED);
                return -1;
            default:
                //printf("CIPSO tag %" PRIu8 " unknown tag\n", ttype);
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                /** \todo May not want to return error here on unknown tag type (at least not for 3|4) */
                return -1;
        }
    }

    return 0;
}

typedef struct IPV4Options_ {
    IPV4Opt o_rr;
    IPV4Opt o_qs;
    IPV4Opt o_ts;
    IPV4Opt o_sec;
    IPV4Opt o_lsrr;
    IPV4Opt o_cipso;
    IPV4Opt o_sid;
    IPV4Opt o_ssrr;
    IPV4Opt o_rtralt;
} IPV4Options;

/**
 * Decode/Validate IPv4 Options.
 */
static int DecodeIPV4Options(Packet *p, const uint8_t *pkt, uint16_t len, IPV4Options *opts)
{
    uint16_t plen = len;

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        uint16_t i;
        char buf[256] = "";
        int offset = 0;

        for (i = 0; i < len; i++) {
            offset += snprintf(buf + offset, (sizeof(buf) - offset), "%02" PRIx8 " ", pkt[i]);
        }
        SCLogDebug("IPV4OPTS: { %s}", buf);
    }
#endif

    /* Options length must be padded to 8byte boundary */
    if (plen % 8) {
        ENGINE_SET_EVENT(p,IPV4_OPT_PAD_REQUIRED);
        /* Warn - we can keep going */
    }

    while (plen)
    {
        p->ip4vars.opt_cnt++;

        /* single byte options */
        if (*pkt == IPV4_OPT_EOL) {
            /** \todo What if more data exist after EOL (possible covert channel or data leakage)? */
            SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                   *pkt, (len - plen), (len - 1));
            p->ip4vars.opts_set |= IPV4_OPT_FLAG_EOL;
            break;
        } else if (*pkt == IPV4_OPT_NOP) {
            SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                   *pkt, (len - plen), (len - 1));
            pkt++;
            plen--;

            p->ip4vars.opts_set |= IPV4_OPT_FLAG_NOP;

        /* multibyte options */
        } else {
            if (unlikely(plen < 2)) {
                /** \todo What if padding is non-zero (possible covert channel or data leakage)? */
                /** \todo Spec seems to indicate EOL required if there is padding */
                ENGINE_SET_EVENT(p,IPV4_OPT_EOL_REQUIRED);
                break;
            }

            /* Option length is too big for packet */
            if (unlikely(*(pkt+1) > plen)) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }

            IPV4Opt opt = {*pkt, *(pkt+1), plen > 2 ? (pkt + 2) : NULL };

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(opt.len > plen || opt.len < 2)) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            /** \todo Figure out which IP options are more common and list them first */
            switch (opt.type) {
                case IPV4_OPT_TS:
                    if (opts->o_ts.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateTimestamp(p, &opt) == 0) {
                        opts->o_ts = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_TS;
                    }
                    break;
                case IPV4_OPT_RR:
                    if (opts->o_rr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_rr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_RR;
                    }
                    break;
                case IPV4_OPT_QS:
                    if (opts->o_qs.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_qs = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_QS;
                    }
                    break;
                case IPV4_OPT_SEC:
                    if (opts->o_sec.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_sec = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SEC;
                    }
                    break;
                case IPV4_OPT_LSRR:
                    if (opts->o_lsrr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_lsrr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_LSRR;
                    }
                    break;
                case IPV4_OPT_CIPSO:
                    if (opts->o_cipso.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateCIPSO(p, &opt) == 0) {
                        opts->o_cipso = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_CIPSO;
                    }
                    break;
                case IPV4_OPT_SID:
                    if (opts->o_sid.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_sid = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SID;
                    }
                    break;
                case IPV4_OPT_SSRR:
                    if (opts->o_ssrr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_ssrr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SSRR;
                    }
                    break;
                case IPV4_OPT_RTRALT:
                    if (opts->o_rtralt.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_rtralt = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_RTRALT;
                    }
                    break;
                default:
                    SCLogDebug("IPV4OPT <unknown> (%" PRIu8 ") len %" PRIu8,
                           opt.type, opt.len);
                    ENGINE_SET_EVENT(p,IPV4_OPT_INVALID);
                    /* Warn - we can keep going */
                    break;
            }

            pkt += opt.len;
            plen -= opt.len;
        }
    }

    return 0;
}

static int DecodeIPV4Packet(Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 4)) {
        SCLogDebug("wrong ip version %d",IP_GET_RAW_VER(pkt));
        ENGINE_SET_INVALID_EVENT(p, IPV4_WRONG_IP_VER);
        return -1;
    }

    p->ip4h = (IPV4Hdr *)pkt;

    if (unlikely(IPV4_GET_HLEN(p) < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_HLEN_TOO_SMALL);
        return -1;
    }

    if (unlikely(IPV4_GET_IPLEN(p) < IPV4_GET_HLEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_IPLEN_SMALLER_THAN_HLEN);
        return -1;
    }

    if (unlikely(len < IPV4_GET_IPLEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_TRUNC_PKT);
        return -1;
    }

    /* set the address struct */
    SET_IPV4_SRC_ADDR(p,&p->src);
    SET_IPV4_DST_ADDR(p,&p->dst);

    /* save the options len */
    uint8_t ip_opt_len = IPV4_GET_HLEN(p) - IPV4_HEADER_LEN;
    if (ip_opt_len > 0) {
        IPV4Options opts;
        memset(&opts, 0x00, sizeof(opts));
        if (DecodeIPV4Options(p, pkt + IPV4_HEADER_LEN, ip_opt_len, &opts) < 0) {
            return -1;
        }
    }

    return 0;
}

int DecodeIPV4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_ipv4);

    SCLogDebug("pkt %p len %"PRIu16"", pkt, len);

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    /* do the actual decoding */
    if (unlikely(DecodeIPV4Packet (p, pkt, len) < 0)) {
        SCLogDebug("decoding IPv4 packet failed");
        CLEAR_IPV4_PACKET((p));
        return TM_ECODE_FAILED;
    }
    p->proto = IPV4_GET_IPPROTO(p);

    /* If a fragment, pass off for re-assembly. */
    if (unlikely(IPV4_GET_IPOFFSET(p) > 0 || IPV4_GET_MF(p) == 1)) {
        Packet *rp = Defrag(tv, dtv, p);
        if (rp != NULL) {
            PacketEnqueueNoLock(&tv->decode_pq, rp);
        }
        p->flags |= PKT_IS_FRAGMENT;
        return TM_ECODE_OK;
    }

    /* do hdr test, process hdr rules */

#ifdef DEBUG
    if (SCLogDebugEnabled()) { /* only convert the addresses if debug is really enabled */
        /* debug print */
        char s[16], d[16];
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), s, sizeof(s));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), d, sizeof(d));
        SCLogDebug("IPV4 %s->%s PROTO: %" PRIu32 " OFFSET: %" PRIu32 " RF: %" PRIu32 " DF: %" PRIu32 " MF: %" PRIu32 " ID: %" PRIu32 "", s,d,
                IPV4_GET_IPPROTO(p), IPV4_GET_IPOFFSET(p), IPV4_GET_RF(p),
                IPV4_GET_DF(p), IPV4_GET_MF(p), IPV4_GET_IPID(p));
    }
#endif /* DEBUG */

    /* check what next decoder to invoke */
    switch (IPV4_GET_IPPROTO(p)) {
        case IPPROTO_TCP:
            DecodeTCP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_UDP:
            DecodeUDP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_ICMP:
            DecodeICMPV4(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                         IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_GRE:
            DecodeGRE(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_SCTP:
            DecodeSCTP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;

        case IPPROTO_ESP:
            DecodeESP(tv, dtv, p, pkt + IPV4_GET_HLEN(p), IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;

        case IPPROTO_IPV6:
            {
                /* spawn off tunnel packet */
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                        IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p),
                        DECODE_TUNNEL_IPV6);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_IPV4);
                    PacketEnqueueNoLock(&tv->decode_pq,tp);
                }
                FlowSetupPacket(p);
                break;
            }
        case IPPROTO_IP:
            /* check PPP VJ uncompressed packets and decode tcp dummy */
            if(p->ppph != NULL && SCNtohs(p->ppph->protocol) == PPP_VJ_UCOMP)    {
                DecodeTCP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                          IPV4_GET_IPLEN(p) -  IPV4_GET_HLEN(p));
            }
            break;
        case IPPROTO_ICMPV6:
            ENGINE_SET_INVALID_EVENT(p, IPV4_WITH_ICMPV6);
            break;
    }

    return TM_ECODE_OK;
}

/* UNITTESTS */
#ifdef UNITTESTS

/** \test IPV4 with no options. */
static int DecodeIPV4OptionsNONETest01(void)
{
    uint8_t raw_opts[] = { };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);

    SCFree(p);
    PASS;
}

/** \test IPV4 with EOL option. */
static int DecodeIPV4OptionsEOLTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_EOL, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    SCFree(p);
    PASS;
}

/** \test IPV4 with NOP option. */
static int DecodeIPV4OptionsNOPTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_NOP, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RR option. */
static int DecodeIPV4OptionsRRTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RR, 0x27, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_rr.type != IPV4_OPT_RR);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RR option (len too large). */
static int DecodeIPV4OptionsRRTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RR, 0xff, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    FAIL_IF(DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts) != -1);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_rr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RR option (ptr too large). */
static int DecodeIPV4OptionsRRTest03(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RR, 0x27, 0xff, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_rr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RR option (ptr not in 4 byte increment). */
static int DecodeIPV4OptionsRRTest04(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RR, 0x27, 0x05, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_rr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with QS option. */
static int DecodeIPV4OptionsQSTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_QS, 0x08, 0x0d, 0x00, 0xbe, 0xef, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_qs.type != IPV4_OPT_QS);
    SCFree(p);
    PASS;
}

/** \test IPV4 with QS option (len too small) */
static int DecodeIPV4OptionsQSTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_QS, 0x07, 0x0d, 0x00, 0xbe, 0xef, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_qs.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with TS option. */
static int DecodeIPV4OptionsTSTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_TS, 0x24, 0x0d, 0x01, 0x0a, 0x0a, 0x0a, 0x69,
        0x04, 0xce, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_ts.type != IPV4_OPT_TS);
    SCFree(p);
    PASS;
}

/** \test IPV4 with TS option (ptr too small). */
static int DecodeIPV4OptionsTSTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_TS, 0x24, 0x04, 0x01, 0x0a, 0x0a, 0x0a, 0x69,
        0x04, 0xce, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ts.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with TS option (ptr too large). */
static int DecodeIPV4OptionsTSTest03(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_TS, 0x24, 0xff, 0x01, 0x0a, 0x0a, 0x0a, 0x69,
        0x04, 0xce, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ts.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with TS option (ptr not valid). */
static int DecodeIPV4OptionsTSTest04(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_TS, 0x24, 0x0a, 0x01, 0x0a, 0x0a, 0x0a, 0x69,
        0x04, 0xce, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ts.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SEC option. */
static int DecodeIPV4OptionsSECTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SEC, 0x0b, 0xf1, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_sec.type != IPV4_OPT_SEC);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SEC option (invalid length). */
static int DecodeIPV4OptionsSECTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SEC, 0x0a, 0xf1, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_sec.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with LSRR option. */
static int DecodeIPV4OptionsLSRRTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_LSRR, 0x27, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_lsrr.type != IPV4_OPT_LSRR);
    SCFree(p);
    PASS;
}

/** \test IPV4 with LSRR option (len too large). */
static int DecodeIPV4OptionsLSRRTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_LSRR, 0xff, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_lsrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with LSRR option (ptr too large). */
static int DecodeIPV4OptionsLSRRTest03(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_LSRR, 0x27, 0xff, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_lsrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with LSRR option (ptr not in 4 byte increment). */
static int DecodeIPV4OptionsLSRRTest04(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_LSRR, 0x27, 0x05, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_lsrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with CIPSO option. */
static int DecodeIPV4OptionsCIPSOTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_CIPSO, 0x18, 0x00, 0x00, 0x00, 0x05, 0x05, 0x12,
        0x00, 0x03, 0x00, 0xef, 0x00, 0xef, 0x00, 0x06,
        0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_cipso.type != IPV4_OPT_CIPSO);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SID option. */
static int DecodeIPV4OptionsSIDTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SID, 0x04, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_sid.type != IPV4_OPT_SID);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SID option (len invalid. */
static int DecodeIPV4OptionsSIDTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SID, 0x05, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_sid.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SSRR option. */
static int DecodeIPV4OptionsSSRRTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SSRR, 0x27, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_ssrr.type != IPV4_OPT_SSRR);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SSRR option (len too large). */
static int DecodeIPV4OptionsSSRRTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SSRR, 0xff, 0x08, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ssrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SSRR option (ptr too large). */
static int DecodeIPV4OptionsSSRRTest03(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SSRR, 0x27, 0xff, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ssrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with SSRR option (ptr not in 4 byte increment). */
static int DecodeIPV4OptionsSSRRTest04(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_SSRR, 0x27, 0x05, 0xc0, 0xa8, 0x2a, 0x64, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_ssrr.type != 0);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RTRALT option. */
static int DecodeIPV4OptionsRTRALTTest01(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RTRALT, 0x04, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF(p->flags & PKT_IS_INVALID);
    FAIL_IF(opts.o_rtralt.type != IPV4_OPT_RTRALT);
    SCFree(p);
    PASS;
}

/** \test IPV4 with RTRALT option (len invalid. */
static int DecodeIPV4OptionsRTRALTTest02(void)
{
    uint8_t raw_opts[] = {
        IPV4_OPT_RTRALT, 0x05, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));

    IPV4Options opts;
    memset(&opts, 0x00, sizeof(opts));
    DecodeIPV4Options(p, raw_opts, sizeof(raw_opts), &opts);
    FAIL_IF((p->flags & PKT_IS_INVALID) == 0);
    FAIL_IF(opts.o_rtralt.type != 0);
    SCFree(p);
    PASS;
}

static int IPV4CalculateValidChecksumtest01(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x03};

    csum = *( ((uint16_t *)raw_ipv4) + 5);

    FAIL_IF(IPV4Checksum((uint16_t *)raw_ipv4, sizeof(raw_ipv4), csum) != 0);
    PASS;
}

static int IPV4CalculateInvalidChecksumtest02(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x07};

    csum = *( ((uint16_t *)raw_ipv4) + 5);

    FAIL_IF(IPV4Checksum((uint16_t *)raw_ipv4, sizeof(raw_ipv4), csum) == 0);
    PASS;
}

/**
 * \test IPV4 defrag and packet recursion level test
 */
static int DecodeIPV4DefragTest01(void)
{
    uint8_t pkt1[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x1c, 0xe9, 0xef, 0x20, 0x00, 0x40, 0x06,
        0x9a, 0xc8, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5e
    };
    uint8_t pkt2[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x1c, 0xe9, 0xef, 0x20, 0x01, 0x40, 0x06,
        0x9a, 0xc7, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10,
        0x80, 0x00
    };
    uint8_t pkt3[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x18, 0xe9, 0xef, 0x00, 0x02, 0x40, 0x06,
        0xba, 0xca, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0xb1, 0xa3, 0x00, 0x00
    };
    uint8_t tunnel_pkt[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x28, 0xe9, 0xef, 0x00, 0x00, 0x40, 0x06,
        0xba, 0xbc, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5e, 0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10,
        0x80, 0x00, 0xb1, 0xa3, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 1;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DefragInit();

    PacketCopyData(p, pkt1, sizeof(pkt1));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt2, sizeof(pkt2));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt3, sizeof(pkt3));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }
    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    if (tp == NULL) {
        printf("Failed to get defragged pseudo packet\n");
        result = 0;
        goto end;
    }
    if (tp->recursion_level != p->recursion_level) {
        printf("defragged pseudo packet's and parent packet's recursion "
               "level don't match\n %d != %d",
               tp->recursion_level, p->recursion_level);
        result = 0;
        goto end;
    }
    if (tp->ip4h == NULL || tp->tcph == NULL) {
        printf("pseudo packet's ip header and tcp header shouldn't be NULL, "
               "but it is\n");
        result = 0;
        goto end;
    }
    if (GET_PKT_LEN(tp) != sizeof(tunnel_pkt)) {
        printf("defragged pseudo packet's and parent packet's pkt lens "
               "don't match\n %u != %"PRIuMAX,
               GET_PKT_LEN(tp), (uintmax_t)sizeof(tunnel_pkt));
        result = 0;
        goto end;
    }
    if (memcmp(GET_PKT_DATA(tp), tunnel_pkt, sizeof(tunnel_pkt)) != 0) {
            result = 0;
            goto end;
    }

    PACKET_RECYCLE(tp);
    SCFree(tp);

end:
    DefragDestroy();
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return result;
}

/**
 * \test Don't send IPv4 fragments to the upper layer decoder and
 *       and packet recursion level test.
 */
static int DecodeIPV4DefragTest02(void)
{
    uint8_t pkt1[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x24, 0xe9, 0xef, 0x20, 0x00, 0x40, 0x06,
        0x9a, 0xc8, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c,
        /* first frag */
        0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5e, 0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10,
        0x80, 0x00,
    };
    uint8_t pkt2[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x2c, 0xe9, 0xef, 0x20, 0x02, 0x40, 0x06,
        0xba, 0xca, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c,
        /* second frag */
        0xb1, 0xa3, 0x00, 0x10, 0x5b, 0xa3, 0x81, 0x5e,
        0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10, 0x80, 0x00,
        0xb1, 0xa3, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04
    };
    uint8_t pkt3[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x16, 0xe9, 0xef, 0x00, 0x05, 0x40, 0x06,
        0xba, 0xca, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c,
        /* final frag */
        0xb1, 0xa3,
    };

    uint8_t tunnel_pkt[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3e, 0xe9, 0xef, 0x00, 0x00, 0x40, 0x06,
        0xba, 0xae, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c,
        0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3, 0x81, 0x5e,
        0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10, 0x80, 0x00,
        0xb1, 0xa3, 0x00, 0x10, 0x5b, 0xa3, 0x81, 0x5e,
        0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10, 0x80, 0x00,
        0xb1, 0xa3, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04,
        0xb1, 0xa3,
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 0;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DefragInit();

    PacketCopyData(p, pkt1, sizeof(pkt1));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt2, sizeof(pkt2));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        goto end;
    }
    PACKET_RECYCLE(p);

    p->recursion_level = 3;
    PacketCopyData(p, pkt3, sizeof(pkt3));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        goto end;
    }
    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    if (tp == NULL) {
        printf("Failed to get defragged pseudo packet\n");
        goto end;
    }
    if (tp->recursion_level != p->recursion_level) {
        printf("defragged pseudo packet's and parent packet's recursion "
               "level don't match %d != %d: ",
               tp->recursion_level, p->recursion_level);
        goto end;
    }
    if (tp->ip4h == NULL || tp->tcph == NULL) {
        printf("pseudo packet's ip header and tcp header shouldn't be NULL, "
               "but it is\n");
        goto end;
    }
    if (GET_PKT_LEN(tp) != sizeof(tunnel_pkt)) {
        printf("defragged pseudo packet's and parent packet's pkt lens "
               "don't match %u != %"PRIuMAX": ",
               GET_PKT_LEN(tp), (uintmax_t)sizeof(tunnel_pkt));
        goto end;
    }

    if (memcmp(GET_PKT_DATA(tp), tunnel_pkt, sizeof(tunnel_pkt)) != 0) {
        goto end;
    }

    result = 1;
    PACKET_RECYCLE(tp);
    SCFree(tp);

end:
    DefragDestroy();
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return result;
}

/**
 * \test IPV4 defrag and flow retrieval test.
 */
static int DecodeIPV4DefragTest03(void)
{
    uint8_t pkt[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x28, 0xe9, 0xee, 0x00, 0x00, 0x40, 0x06,
        0xba, 0xbd, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
        0x80, 0x00, 0x0c, 0xee, 0x00, 0x00
    };
    uint8_t pkt1[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x1c, 0xe9, 0xef, 0x20, 0x00, 0x40, 0x06,
        0x9a, 0xc8, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5e
    };
    uint8_t pkt2[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x1c, 0xe9, 0xef, 0x20, 0x01, 0x40, 0x06,
        0x9a, 0xc7, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10,
        0x80, 0x00
    };
    uint8_t pkt3[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x18, 0xe9, 0xef, 0x00, 0x02, 0x40, 0x06,
        0xba, 0xca, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0xb1, 0xa3, 0x00, 0x00
    };
    uint8_t tunnel_pkt[] = {
        0x00, 0x50, 0x56, 0x00, 0x03, 0x05, 0xde, 0xad,
        0x01, 0xa3, 0xa2, 0x2f, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x28, 0xe9, 0xef, 0x00, 0x00, 0x40, 0x06,
        0xba, 0xbc, 0x0a, 0x00, 0xe1, 0x17, 0x0a, 0x00,
        0xe1, 0x0c, 0x6e, 0x12, 0x01, 0xbd, 0x5b, 0xa3,
        0x81, 0x5e, 0xac, 0xb0, 0xae, 0x8a, 0x50, 0x10,
        0x80, 0x00, 0xb1, 0xa3, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int result = 1;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DefragInit();

    PacketCopyData(p, pkt, sizeof(pkt));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph == NULL) {
        printf("tcp header shouldn't be NULL, but it is\n");
        result = 0;
        goto end;
    }
    if (!(p->flags & PKT_WANTS_FLOW)) {
        printf("packet flow shouldn't be NULL\n");
        result = 0;
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt1, sizeof(pkt1));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt2, sizeof(pkt2));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }
    PACKET_RECYCLE(p);

    PacketCopyData(p, pkt3, sizeof(pkt3));
    DecodeIPV4(&tv, &dtv, p, GET_PKT_DATA(p) + ETHERNET_HEADER_LEN,
               GET_PKT_LEN(p) - ETHERNET_HEADER_LEN);
    if (p->tcph != NULL) {
        printf("tcp header should be NULL for ip fragment, but it isn't\n");
        result = 0;
        goto end;
    }

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    if (tp == NULL) {
        printf("Failed to get defragged pseudo packet\n");
        result = 0;
        goto end;
    }
    if (!(tp->flags & PKT_WANTS_FLOW)) {
        result = 0;
        goto end;
    }
    if (tp->flow_hash != p->flow_hash) {
        result = 0;
        goto end;
    }
    if (tp->recursion_level != p->recursion_level) {
        printf("defragged pseudo packet's and parent packet's recursion "
               "level don't match\n %d != %d",
               tp->recursion_level, p->recursion_level);
        result = 0;
        goto end;
    }
    if (tp->ip4h == NULL || tp->tcph == NULL) {
        printf("pseudo packet's ip header and tcp header shouldn't be NULL, "
               "but it is\n");
        result = 0;
        goto end;
    }
    if (GET_PKT_LEN(tp) != sizeof(tunnel_pkt)) {
        printf("defragged pseudo packet's and parent packet's pkt lens "
               "don't match\n %u != %"PRIuMAX,
               GET_PKT_LEN(tp), (uintmax_t)sizeof(tunnel_pkt));
        result = 0;
        goto end;
    }

    if (memcmp(GET_PKT_DATA(tp), tunnel_pkt, sizeof(tunnel_pkt)) != 0) {
            result = 0;
            goto end;
    }

    PACKET_RECYCLE(tp);
    SCFree(tp);

end:
    DefragDestroy();
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return result;
}

/**
 */
static int DecodeEthernetTestIPv4Opt(void)
{
    uint8_t raw_eth[] = {
        0xae, 0x71, 0x00, 0x00, 0x00, 0x4b, 0x06, 0x90, 0x61, 0x02, 0x00, 0xcd, 0x88, 0x64, 0x11, 0x00,
        0x15, 0x00, 0x80, 0x64, 0x00, 0x21, 0x4c, 0x00, 0x00, 0x30, 0x42, 0xd6, 0xff, 0xff, 0xbd, 0x2f,
        0x02, 0x02, 0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x01, 0x44, 0x05, 0x22, 0x02, 0x01
    };

    DefragInit();

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    SCFree(p);
    DefragDestroy();
    PASS;
}

#endif /* UNITTESTS */

void DecodeIPV4RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeIPV4OptionsNONETest01", DecodeIPV4OptionsNONETest01);
    UtRegisterTest("DecodeIPV4OptionsEOLTest01", DecodeIPV4OptionsEOLTest01);
    UtRegisterTest("DecodeIPV4OptionsNOPTest01", DecodeIPV4OptionsNOPTest01);
    UtRegisterTest("DecodeIPV4OptionsRRTest01", DecodeIPV4OptionsRRTest01);
    UtRegisterTest("DecodeIPV4OptionsRRTest02", DecodeIPV4OptionsRRTest02);
    UtRegisterTest("DecodeIPV4OptionsRRTest03", DecodeIPV4OptionsRRTest03);
    UtRegisterTest("DecodeIPV4OptionsRRTest04", DecodeIPV4OptionsRRTest04);
    UtRegisterTest("DecodeIPV4OptionsQSTest01", DecodeIPV4OptionsQSTest01);
    UtRegisterTest("DecodeIPV4OptionsQSTest02", DecodeIPV4OptionsQSTest02);
    UtRegisterTest("DecodeIPV4OptionsTSTest01", DecodeIPV4OptionsTSTest01);
    UtRegisterTest("DecodeIPV4OptionsTSTest02", DecodeIPV4OptionsTSTest02);
    UtRegisterTest("DecodeIPV4OptionsTSTest03", DecodeIPV4OptionsTSTest03);
    UtRegisterTest("DecodeIPV4OptionsTSTest04", DecodeIPV4OptionsTSTest04);
    UtRegisterTest("DecodeIPV4OptionsSECTest01", DecodeIPV4OptionsSECTest01);
    UtRegisterTest("DecodeIPV4OptionsSECTest02", DecodeIPV4OptionsSECTest02);
    UtRegisterTest("DecodeIPV4OptionsLSRRTest01", DecodeIPV4OptionsLSRRTest01);
    UtRegisterTest("DecodeIPV4OptionsLSRRTest02", DecodeIPV4OptionsLSRRTest02);
    UtRegisterTest("DecodeIPV4OptionsLSRRTest03", DecodeIPV4OptionsLSRRTest03);
    UtRegisterTest("DecodeIPV4OptionsLSRRTest04", DecodeIPV4OptionsLSRRTest04);
    UtRegisterTest("DecodeIPV4OptionsCIPSOTest01",
                   DecodeIPV4OptionsCIPSOTest01);
    UtRegisterTest("DecodeIPV4OptionsSIDTest01", DecodeIPV4OptionsSIDTest01);
    UtRegisterTest("DecodeIPV4OptionsSIDTest02", DecodeIPV4OptionsSIDTest02);
    UtRegisterTest("DecodeIPV4OptionsSSRRTest01", DecodeIPV4OptionsSSRRTest01);
    UtRegisterTest("DecodeIPV4OptionsSSRRTest02", DecodeIPV4OptionsSSRRTest02);
    UtRegisterTest("DecodeIPV4OptionsSSRRTest03", DecodeIPV4OptionsSSRRTest03);
    UtRegisterTest("DecodeIPV4OptionsSSRRTest04", DecodeIPV4OptionsSSRRTest04);
    UtRegisterTest("DecodeIPV4OptionsRTRALTTest01",
                   DecodeIPV4OptionsRTRALTTest01);
    UtRegisterTest("DecodeIPV4OptionsRTRALTTest02",
                   DecodeIPV4OptionsRTRALTTest02);
    UtRegisterTest("IPV4CalculateValidChecksumtest01",
                   IPV4CalculateValidChecksumtest01);
    UtRegisterTest("IPV4CalculateInvalidChecksumtest02",
                   IPV4CalculateInvalidChecksumtest02);
    UtRegisterTest("DecodeIPV4DefragTest01", DecodeIPV4DefragTest01);
    UtRegisterTest("DecodeIPV4DefragTest02", DecodeIPV4DefragTest02);
    UtRegisterTest("DecodeIPV4DefragTest03", DecodeIPV4DefragTest03);
    UtRegisterTest("DecodeEthernetTestIPv4Opt", DecodeEthernetTestIPv4Opt);
#endif /* UNITTESTS */
}
/**
 * @}
 */
