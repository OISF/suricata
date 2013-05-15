/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * Logs alerts in a format compatible to Snort's unified2 format, so it should
 * be readable by Barnyard2.
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "pkt-var.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "alert-unified2-alert.h"
#include "decode-ipv4.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"
#include "util-misc.h"

#include "output.h"
#include "alert-unified2-alert.h"
#include "util-privs.h"

#include "stream.h"
#include "stream-tcp-inline.h"

#include "util-optimize.h"

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#define DEFAULT_LOG_FILENAME "unified2.alert"

/**< Default log file limit in MB. */
#define DEFAULT_LIMIT 32 * 1024 * 1024

/**< Minimum log file limit in MB. */
#define MIN_LIMIT 1 * 1024 * 1024

/* Default Sensor ID value */
static uint32_t sensor_id = 0;

/**
 * Unified2 file header struct
 *
 * Used for storing file header options.
 */
typedef struct Unified2AlertFileHeader_ {
    uint32_t type;      /**< unified2 type header */
    uint32_t length;    /**< unified2 struct size length */
} Unified2AlertFileHeader;

/**
 * Unified2 Ipv4 struct
 *
 * Used for storing ipv4 type values.
 */
typedef struct AlertIPv4Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    uint32_t src_ip;                /**< source ip */
    uint32_t dst_ip;                /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv4Unified2;

/**
 * Unified2 Ipv6 type struct
 *
 * Used for storing ipv6 type values.
 */
typedef struct AlertIPv6Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    struct in6_addr src_ip;         /**< source ip */
    struct in6_addr dst_ip;         /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv6Unified2;

/**
 * Unified2 packet type struct
 *
 * Used for storing packet type values.
 */
typedef struct AlertUnified2Packet_ {
    uint32_t sensor_id;             /**< sensor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t packet_second;         /**< packet second */
    uint32_t packet_microsecond;    /**< packet microsecond */
    uint32_t linktype;              /**< link type */
    uint32_t packet_length;         /**< packet length */
    uint8_t packet_data[4];         /**< packet data */
} Unified2Packet;

/**
 * Unified2 thread vars
 *
 * Used for storing file options.
 */
typedef struct Unified2AlertThread_ {
    LogFileCtx *file_ctx;   /**< LogFileCtx pointer */
    uint8_t *data; /**< Per function and thread data */
    /** Pointer to the Unified2AlertFileHeader contained in
     * the pointer data. */
    Unified2AlertFileHeader *hdr;
    /** Pointer to the Unified2Packet contained in
     * the pointer data. */
    Unified2Packet *phdr;
    /** Pointer to the IPv4 or IPv6 header contained in
     * the pointer data. */
    void *iphdr;
    int datalen; /**< Length of per function and thread data */
    int offset; /**< Offset used to now where to fill data */
    int length; /**< Length of data for current alert */
    uint32_t event_id;
} Unified2AlertThread;

#define UNIFIED2_PACKET_SIZE        (sizeof(Unified2Packet) - 4)

SC_ATOMIC_DECLARE(unsigned int, unified2_event_id);  /**< Atomic counter, to link relative event */

/** prototypes */
TmEcode Unified2Alert (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode Unified2AlertThreadInit(ThreadVars *, void *, void **);
TmEcode Unified2AlertThreadDeinit(ThreadVars *, void *);
int Unified2IPv4TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2IPv6TypeAlert(ThreadVars *, Packet *, void *, PacketQueue *);
int Unified2PacketTypeAlert(Unified2AlertThread *, Packet *, uint32_t, int);
void Unified2RegisterTests();
int Unified2AlertOpenFileCtx(LogFileCtx *, const char *);
static void Unified2AlertDeInitCtx(OutputCtx *);

#define MODULE_NAME "Unified2Alert"

void TmModuleUnified2AlertRegister (void) {
    tmm_modules[TMM_ALERTUNIFIED2ALERT].name = MODULE_NAME;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].ThreadInit = Unified2AlertThreadInit;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].Func = Unified2Alert;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].ThreadDeinit = Unified2AlertThreadDeinit;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].RegisterTests = Unified2RegisterTests;
    tmm_modules[TMM_ALERTUNIFIED2ALERT].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "unified2-alert", Unified2AlertInitCtx);
}

/**
 *  \brief Function to close unified2 file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param aun Unified2 thread variable.
 */

int Unified2AlertCloseFile(ThreadVars *t, Unified2AlertThread *aun) {
    if (aun->file_ctx->fp != NULL) {
        fclose(aun->file_ctx->fp);
    }
    aun->file_ctx->size_current = 0;

    return 0;
}

/**
 *  \brief Function to rotate unified2 file
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param aun Unified2 thread variable.
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2AlertRotateFile(ThreadVars *t, Unified2AlertThread *aun) {
    if (Unified2AlertCloseFile(t,aun) < 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC,
                   "Error: Unified2AlertCloseFile failed");
        return -1;
    }
    if (Unified2AlertOpenFileCtx(aun->file_ctx,aun->file_ctx->prefix) < 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC,
                   "Error: Unified2AlertOpenFileCtx, open new log file failed");
        return -1;
    }
    return 0;
}

/**
 * \brief Wrapper for fwrite
 *
 * This function is basically a wrapper for fwrite which take
 * in charge a size counter.
 *
 * \return 1 in case of success
 */
static int Unified2Write(Unified2AlertThread *aun)
{
    int ret;

    ret = fwrite(aun->data, aun->length, 1, aun->file_ctx->fp);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
        return -1;
    }

    aun->file_ctx->size_current += aun->length;
    return 1;
}

/**
 *  \brief Unified2 main entry function
 *
 *  \retval TM_ECODE_OK all is good
 *  \retval TM_ECODE_FAILED serious error
 */
TmEcode Unified2Alert (ThreadVars *t, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        ret = Unified2IPv4TypeAlert (t, p, data, pq);
    } else if(PKT_IS_IPV6(p)) {
        ret = Unified2IPv6TypeAlert (t, p, data, pq);
    } else {
        /* we're only supporting IPv4 and IPv6 */
        return TM_ECODE_OK;
    }

    if (ret != 0) {
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

typedef struct _FakeIPv4Hdr {
    IPV4Hdr ip4h;
    TCPHdr tcph;
} FakeIPv4Hdr;

static int Unified2ForgeFakeIPv4Header(FakeIPv4Hdr *fakehdr, Packet *p, int pkt_len, char invert)
{
    fakehdr->ip4h.ip_verhl = p->ip4h->ip_verhl;
    fakehdr->ip4h.ip_proto = p->ip4h->ip_proto;
    if (! invert) {
        fakehdr->ip4h.s_ip_src.s_addr = p->ip4h->s_ip_src.s_addr;
        fakehdr->ip4h.s_ip_dst.s_addr = p->ip4h->s_ip_dst.s_addr;
    } else {
        fakehdr->ip4h.s_ip_dst.s_addr = p->ip4h->s_ip_src.s_addr;
        fakehdr->ip4h.s_ip_src.s_addr = p->ip4h->s_ip_dst.s_addr;
    }
    fakehdr->ip4h.ip_len = htons((uint16_t)pkt_len);

    if (! invert) {
        fakehdr->tcph.th_sport = p->tcph->th_sport;
        fakehdr->tcph.th_dport = p->tcph->th_dport;
    } else {
        fakehdr->tcph.th_dport = p->tcph->th_sport;
        fakehdr->tcph.th_sport = p->tcph->th_dport;
    }
    fakehdr->tcph.th_offx2 = 0x50; /* just the TCP header, no options */

    return 1;
}

typedef struct _FakeIPv6Hdr {
    IPV6Hdr ip6h;
    TCPHdr tcph;
} FakeIPv6Hdr;

/**
 *  \param payload_len length of the payload
 */
static int Unified2ForgeFakeIPv6Header(FakeIPv6Hdr *fakehdr, Packet *p, int payload_len, char invert)
{
    fakehdr->ip6h.s_ip6_vfc = p->ip6h->s_ip6_vfc;
    fakehdr->ip6h.s_ip6_nxt = IPPROTO_TCP;
    fakehdr->ip6h.s_ip6_plen = htons(sizeof(TCPHdr) + payload_len);
    if (!invert) {
        memcpy(fakehdr->ip6h.s_ip6_addrs, p->ip6h->s_ip6_addrs, 32);
    } else {
        memcpy(fakehdr->ip6h.s_ip6_src, p->ip6h->s_ip6_dst, 16);
        memcpy(fakehdr->ip6h.s_ip6_dst, p->ip6h->s_ip6_src, 16);
    }
    if (! invert) {
        fakehdr->tcph.th_sport = p->tcph->th_sport;
        fakehdr->tcph.th_dport = p->tcph->th_dport;
    } else {
        fakehdr->tcph.th_dport = p->tcph->th_sport;
        fakehdr->tcph.th_sport = p->tcph->th_dport;
    }
    fakehdr->tcph.th_offx2 = 0x50; /* just the TCP header, no options */

    return 1;
}

/**
 * \brief Write a faked Packet in unified2 file for each stream segment.
 */
static int Unified2PrintStreamSegmentCallback(Packet *p, void *data, uint8_t *buf, uint32_t buflen)
{
    int ret = 1;
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    Unified2AlertFileHeader *hdr = (Unified2AlertFileHeader*)(aun->data);
    Unified2Packet *phdr = (Unified2Packet *)(hdr + 1);
    int ethh_offset = 0;
    EthernetHdr ethhdr = { {0,0,0,0,0,0}, {0,0,0,0,0,0}, htons(ETHERNET_TYPE_IPV6) };
    uint32_t hdr_length = 0;
    int datalink = p->datalink;

    memset(hdr, 0, sizeof(Unified2AlertFileHeader));
    memset(phdr, 0, sizeof(Unified2Packet));

    hdr->type = htonl(UNIFIED2_PACKET_TYPE);
    aun->hdr = hdr;

    phdr->sensor_id = htonl(sensor_id);
    phdr->linktype = htonl(datalink);
    phdr->event_id = aun->event_id;
    phdr->event_second = phdr->packet_second = htonl(p->ts.tv_sec);
    phdr->packet_microsecond = htonl(p->ts.tv_usec);
    aun->phdr = phdr;

    if (p->datalink != DLT_EN10MB) {
        /* We have raw data here */
        phdr->linktype = htonl(DLT_RAW);
        datalink = DLT_RAW;
    }

    aun->length = sizeof(Unified2AlertFileHeader) + UNIFIED2_PACKET_SIZE;
    aun->offset = sizeof(Unified2AlertFileHeader) + UNIFIED2_PACKET_SIZE;

    /* Include Packet header */
    if (PKT_IS_IPV4(p)) {
        FakeIPv4Hdr fakehdr;
        hdr_length = sizeof(FakeIPv4Hdr);

        if (p->datalink == DLT_EN10MB) {
            /* Fake this */
            ethh_offset = 14;
            datalink = DLT_EN10MB;
            phdr->linktype = htonl(datalink);
            aun->length += ethh_offset;

            if (aun->length > aun->datalen) {
                SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data");
                goto error;
            }
            ethhdr.eth_type = htons(ETHERNET_TYPE_IP);

            memcpy(aun->data + aun->offset, &ethhdr, 14);
            aun->offset += ethh_offset;
        }

        memset(&fakehdr, 0, hdr_length);
        aun->length += hdr_length;
        Unified2ForgeFakeIPv4Header(&fakehdr, p, hdr_length + buflen, 0);
        if (aun->length > aun->datalen) {
            SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data");
            goto error;
        }
        memcpy(aun->data + aun->offset, &fakehdr, hdr_length);
        aun->iphdr = (void *)(aun->data + aun->offset);
        aun->offset += hdr_length;

    } else if (PKT_IS_IPV6(p)) {
        FakeIPv6Hdr fakehdr;
        hdr_length = sizeof(FakeIPv6Hdr);

        if (p->datalink == DLT_EN10MB) {
            /* Fake this */
            ethh_offset = 14;
            datalink = DLT_EN10MB;
            phdr->linktype = htonl(datalink);
            aun->length += ethh_offset;
            if (aun->length > aun->datalen) {
                SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data");
                goto error;
            }
            ethhdr.eth_type = htons(ETHERNET_TYPE_IPV6);

            memcpy(aun->data + aun->offset, &ethhdr, 14);
            aun->offset += ethh_offset;
        }

        memset(&fakehdr, 0, hdr_length);
        Unified2ForgeFakeIPv6Header(&fakehdr, p, buflen, 1);

        aun->length += hdr_length;
        if (aun->length > aun->datalen) {
            SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data");
            goto error;
        }
        memcpy(aun->data + aun->offset, &fakehdr, hdr_length);
        aun->iphdr = (void *)(aun->data + aun->offset);
        aun->offset += hdr_length;
    } else {
        goto error;
    }

    /* update unified2 headers for length */
    aun->hdr->length = htonl(UNIFIED2_PACKET_SIZE + ethh_offset +
            hdr_length + buflen);
    aun->phdr->packet_length = htonl(ethh_offset + hdr_length + buflen);

    /* copy stream segment payload in */
    aun->length += buflen;

    if (aun->length > aun->datalen) {
        SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread"
                   " data: %d vs %d", aun->length, aun->datalen);
        goto error;
    }

    memcpy(aun->data + aun->offset, buf, buflen);
    aun->offset += buflen;

    /* rebuild checksum */
    if (PKT_IS_IPV6(p)) {
        FakeIPv6Hdr *fakehdr = (FakeIPv6Hdr *)aun->iphdr;

        fakehdr->tcph.th_sum = TCPV6CalculateChecksum(fakehdr->ip6h.s_ip6_addrs,
                (uint16_t *)&fakehdr->tcph, buflen + sizeof(TCPHdr));
    } else {
        FakeIPv4Hdr *fakehdr = (FakeIPv4Hdr *)aun->iphdr;

        fakehdr->tcph.th_sum = TCPCalculateChecksum(fakehdr->ip4h.s_ip_addrs,
                (uint16_t *)&fakehdr->tcph, buflen + sizeof(TCPHdr));
        fakehdr->ip4h.ip_csum = IPV4CalculateChecksum((uint16_t *)&fakehdr->ip4h,
                IPV4_GET_RAW_HLEN(&fakehdr->ip4h));
    }

    /* write out */
    ret = Unified2Write(aun);
    if (ret != 1) {
        goto error;
    }
    return 1;

error:
    aun->length = 0;
    aun->offset = 0;
    return -1;
}


/**
 *  \brief Function to fill unified2 packet format into the file. If the alert
 *         was generated based on a stream chunk we call the stream function
 *         to generate the record.
 *
 *  Barnyard2 doesn't like DLT_RAW + IPv6, so if we don't have an ethernet
 *  header, we create a fake one.
 *
 *  No need to lock here, since it's already locked.
 *
 *  \param aun thread local data
 *  \param p Packet
 *  \param stream pointer to stream chunk
 *  \param event_id unique event id
 *  \param stream state/stream match, try logging stream segments
 *
 *  \retval 0 on succces
 *  \retval -1 on failure
 */
int Unified2PacketTypeAlert (Unified2AlertThread *aun, Packet *p, uint32_t event_id, int stream)
{
    int ret = 0;

    /* try stream logging first */
    if (stream) {
        SCLogDebug("logging the state");
        uint8_t flag;

        if (p->flowflags & FLOW_PKT_TOSERVER) {
            flag = FLOW_PKT_TOCLIENT;
        } else {
            flag = FLOW_PKT_TOSERVER;
        }

        /* make event id available to callback */
        aun->event_id = event_id;

        /* run callback for all segments in the stream */
        ret = StreamSegmentForEach(p, flag, Unified2PrintStreamSegmentCallback, (void *)aun);
    }

    /* or no segment could been logged or no segment have been logged */
    if (ret == 0) {
        SCLogDebug("no stream, no state: falling back to payload logging");

        Unified2AlertFileHeader *hdr = (Unified2AlertFileHeader*)(aun->data);
        Unified2Packet *phdr = (Unified2Packet *)(hdr + 1);
        int len = (sizeof(Unified2AlertFileHeader) + UNIFIED2_PACKET_SIZE);
        int datalink = p->datalink;
#ifdef HAVE_OLD_BARNYARD2
        int ethh_offset = 0;
        EthernetHdr ethhdr = { {0,0,0,0,0,0}, {0,0,0,0,0,0}, htons(ETHERNET_TYPE_IPV6) };
#endif
        memset(hdr, 0, sizeof(Unified2AlertFileHeader));
        memset(phdr, 0, sizeof(Unified2Packet));

        hdr->type = htonl(UNIFIED2_PACKET_TYPE);
        aun->hdr = hdr;

        phdr->sensor_id = htonl(sensor_id);
        phdr->linktype = htonl(datalink);
        phdr->event_id =  event_id;
        phdr->event_second = phdr->packet_second = htonl(p->ts.tv_sec);
        phdr->packet_microsecond = htonl(p->ts.tv_usec);
        aun->phdr = phdr;

        /* we need to reset offset and length which could
         * have been modified by the segment logging */
        aun->offset = len;
        len += GET_PKT_LEN(p);
        aun->length = len;

        /* Unified 2 packet header is the one of the packet. */
        phdr->linktype = htonl(p->datalink);
#ifdef HAVE_OLD_BARNYARD2
        /* Fake datalink to avoid bug with old barnyard2 */
        if (PKT_IS_IPV6(p) && (!p->ethh)) {
            /* Fake this */
            ethh_offset = 14;
            datalink = DLT_EN10MB;
            phdr->linktype = htonl(datalink);
            aun->length += ethh_offset;
            if (aun->length > aun->datalen) {
                SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data: %d vs %d",
                        len, aun->datalen - aun->offset);
                return -1;
            }
            ethhdr.eth_type = htons(ETHERNET_TYPE_IPV6);

            memcpy(aun->data + aun->offset, &ethhdr, 14);
            aun->offset += ethh_offset;
        }
#endif

        if (len > aun->datalen) {
            SCLogError(SC_ERR_INVALID_VALUE, "len is too big for thread data: %d vs %d",
                    len, aun->datalen - aun->offset);
            return -1;
        }
        hdr->length = htonl(UNIFIED2_PACKET_SIZE + GET_PKT_LEN(p));
        phdr->packet_length = htonl(GET_PKT_LEN(p));
        memcpy(aun->data + aun->offset, GET_PKT_DATA(p), GET_PKT_LEN(p));

        ret = Unified2Write(aun);
    }

    if (ret < 1) {
        return -1;
    }

    return 1;
}

/**
 *  \brief Function to fill unified2 ipv6 ids type format into the file.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param p Packet struct used to decide for ipv4 or ipv6
 *  \param data Unified2 thread data.
 *  \param pq Packet queue
 *
 *  \retval 0 on succces
 *  \retval -1 on failure
 */
int Unified2IPv6TypeAlert (ThreadVars *t, Packet *p, void *data, PacketQueue *pq)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    Unified2AlertFileHeader hdr;
    AlertIPv6Unified2 *phdr = (AlertIPv6Unified2 *)(aun->data +
                                sizeof(Unified2AlertFileHeader));
    AlertIPv6Unified2 gphdr;
    PacketAlert *pa;
    int offset, length;
    int ret;
    unsigned int event_id;

    if (p->alerts.cnt == 0)
        return 0;

    length = (sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv6Unified2));
    offset = length;

    memset(aun->data, 0, aun->datalen);

    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_TYPE);
    hdr.length = htonl(sizeof(AlertIPv6Unified2));

    /* fill the gphdr structure with the data of the packet */
    memset(&gphdr, 0, sizeof(gphdr));
    /* FIXME this need to be copied for each alert */
    gphdr.sensor_id = htonl(sensor_id);
    gphdr.event_second =  htonl(p->ts.tv_sec);
    gphdr.event_microsecond = htonl(p->ts.tv_usec);
    gphdr.src_ip = *(struct in6_addr*)GET_IPV6_SRC_ADDR(p);
    gphdr.dst_ip = *(struct in6_addr*)GET_IPV6_DST_ADDR(p);
    gphdr.protocol = p->proto;

    if(p->action & ACTION_DROP)
        gphdr.packet_action = UNIFIED2_BLOCKED_FLAG;
    else
        gphdr.packet_action = 0;

    switch(gphdr.protocol)  {
        case IPPROTO_ICMPV6:
            if(p->icmpv6h)  {
                gphdr.sp = htons(p->icmpv6h->type);
                gphdr.dp = htons(p->icmpv6h->code);
            } else {
                gphdr.sp = 0;
                gphdr.dp = 0;
            }
            break;
        case IPPROTO_ICMP:
            if(p->icmpv4h)  {
                gphdr.sp = htons(p->icmpv4h->type);
                gphdr.dp = htons(p->icmpv4h->code);
            } else {
                gphdr.sp = 0;
                gphdr.dp = 0;
            }
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            gphdr.sp = htons(p->sp);
            gphdr.dp = htons(p->dp);
            break;
        default:
            gphdr.sp = 0;
            gphdr.dp = 0;
            break;
    }

    uint16_t i = 0;
    for (; i < p->alerts.cnt + 1; i++) {
        if (i < p->alerts.cnt)
            pa = &p->alerts.alerts[i];
        else {
            if (!(p->flags & PKT_HAS_TAG))
                break;
            pa = PacketAlertGetTag();
        }

        if (unlikely(pa->s == NULL))
            continue;

        /* reset length and offset */
        aun->offset = offset;
        aun->length = length;
        memset(aun->data + aun->offset, 0, aun->datalen - aun->offset);

        /* copy the part common to all alerts */
        memcpy(aun->data, &hdr, sizeof(hdr));
        memcpy(phdr, &gphdr, sizeof(gphdr));

        /* fill the header structure with the data of the alert */
        event_id = htonl(SC_ATOMIC_ADD(unified2_event_id, 1));
        phdr->event_id = event_id;
        phdr->generator_id = htonl(pa->s->gid);
        phdr->signature_id = htonl(pa->s->id);
        phdr->signature_revision = htonl(pa->s->rev);
        phdr->classification_id = htonl(pa->s->class);
        phdr->priority_id = htonl(pa->s->prio);

        SCMutexLock(&aun->file_ctx->fp_mutex);
        if ((aun->file_ctx->size_current + length) > aun->file_ctx->size_limit) {
            if (Unified2AlertRotateFile(t,aun) < 0) {
                aun->file_ctx->alerts += i;
                SCMutexUnlock(&aun->file_ctx->fp_mutex);
                return -1;
            }
        }

        if (Unified2Write(aun) != 1) {
            aun->file_ctx->alerts += i;
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }

        memset(aun->data, 0, aun->length);
        aun->length = 0;
        aun->offset = 0;

        /* stream flag based on state match, but only for TCP */
        int stream = (gphdr.protocol == IPPROTO_TCP) ?
            (pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_STREAM_MATCH) ? 1 : 0) : 0;
        ret = Unified2PacketTypeAlert(aun, p, phdr->event_id, stream);
        if (ret != 1) {
            SCLogError(SC_ERR_FWRITE, "Error: fwrite failed: %s", strerror(errno));
            aun->file_ctx->alerts += i;
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }
        fflush(aun->file_ctx->fp);
        aun->file_ctx->alerts++;
        SCMutexUnlock(&aun->file_ctx->fp_mutex);
    }

    return 0;
}

/**
 *  \brief Function to fill unified2 ipv4 ids type format into the file.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param p Packet struct used to decide for ipv4 or ipv6
 *  \param data Unified2 thread data.
 *  \param pq Packet queue
 *  \retval 0 on succces
 *  \retval -1 on failure
 */

int Unified2IPv4TypeAlert (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    Unified2AlertFileHeader hdr;
    AlertIPv4Unified2 *phdr = (AlertIPv4Unified2 *)(aun->data +
                                sizeof(Unified2AlertFileHeader));
    AlertIPv4Unified2 gphdr;
    PacketAlert *pa;
    int offset, length;
    int ret;
    unsigned int event_id;

    if (p->alerts.cnt == 0)
        return 0;

    length = (sizeof(Unified2AlertFileHeader) + sizeof(AlertIPv4Unified2));
    offset = length;

    memset(aun->data, 0, aun->datalen);

    hdr.type = htonl(UNIFIED2_IDS_EVENT_TYPE);
    hdr.length = htonl(sizeof(AlertIPv4Unified2));

    /* fill the gphdr structure with the data of the packet */
    memset(&gphdr, 0, sizeof(gphdr));
    gphdr.sensor_id = htonl(sensor_id);
    gphdr.event_id = 0;
    gphdr.event_second =  htonl(p->ts.tv_sec);
    gphdr.event_microsecond = htonl(p->ts.tv_usec);
    gphdr.src_ip = p->ip4h->s_ip_src.s_addr;
    gphdr.dst_ip = p->ip4h->s_ip_dst.s_addr;
    gphdr.protocol = IPV4_GET_RAW_IPPROTO(p->ip4h);

    if(p->action & ACTION_DROP)
        gphdr.packet_action = UNIFIED2_BLOCKED_FLAG;
    else
        gphdr.packet_action = 0;

    /* TODO inverse order if needed, this should be done on a
     * alert basis */
    switch(gphdr.protocol)  {
        case IPPROTO_ICMP:
            if(p->icmpv4h)  {
                gphdr.sp = htons(p->icmpv4h->type);
                gphdr.dp = htons(p->icmpv4h->code);
            }
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            gphdr.sp = htons(p->sp);
            gphdr.dp = htons(p->dp);
            break;
        default:
            gphdr.sp = 0;
            gphdr.dp = 0;
            break;
    }

    uint16_t i = 0;
    for (; i < p->alerts.cnt + 1; i++) {
        if (i < p->alerts.cnt)
            pa = &p->alerts.alerts[i];
        else {
            if (!(p->flags & PKT_HAS_TAG))
                break;
            pa = PacketAlertGetTag();
        }

        if (unlikely(pa->s == NULL))
            continue;

        /* reset length and offset */
        aun->offset = offset;
        aun->length = length;
        memset(aun->data + aun->offset, 0, aun->datalen - aun->offset);

        /* copy the part common to all alerts */
        memcpy(aun->data, &hdr, sizeof(hdr));
        memcpy(phdr, &gphdr, sizeof(gphdr));

        /* fill the hdr structure with the alert data */
        event_id = htonl(SC_ATOMIC_ADD(unified2_event_id, 1));
        phdr->event_id = event_id;
        phdr->generator_id = htonl(pa->s->gid);
        phdr->signature_id = htonl(pa->s->id);
        phdr->signature_revision = htonl(pa->s->rev);
        phdr->classification_id = htonl(pa->s->class);
        phdr->priority_id = htonl(pa->s->prio);

        /* check and enforce the filesize limit */
        SCMutexLock(&aun->file_ctx->fp_mutex);

        if ((aun->file_ctx->size_current + length) > aun->file_ctx->size_limit) {
            if (Unified2AlertRotateFile(tv,aun) < 0) {
                aun->file_ctx->alerts += i;
                SCMutexUnlock(&aun->file_ctx->fp_mutex);
                return -1;
            }
        }

        if (Unified2Write(aun) != 1) {
            aun->file_ctx->alerts += i;
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }

        memset(aun->data, 0, aun->length);
        aun->length = 0;
        aun->offset = 0;

        /* Write the alert (it doesn't lock inside, since we
         * already locked here for rotation check)
         */
        int stream = (gphdr.protocol == IPPROTO_TCP) ?
            (pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_STREAM_MATCH) ? 1 : 0) : 0;
        ret = Unified2PacketTypeAlert(aun, p, event_id, stream);
        if (ret != 1) {
            aun->file_ctx->alerts += i;
            SCMutexUnlock(&aun->file_ctx->fp_mutex);
            return -1;
        }

        fflush(aun->file_ctx->fp);
        aun->file_ctx->alerts++;
        SCMutexUnlock(&aun->file_ctx->fp_mutex);
    }

    return 0;
}

/**
 *  \brief Thread init function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param initdata Unified2 thread initial data.
 *  \param data Unified2 thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */

TmEcode Unified2AlertThreadInit(ThreadVars *t, void *initdata, void **data)
{
    Unified2AlertThread *aun = SCMalloc(sizeof(Unified2AlertThread));
    if (unlikely(aun == NULL))
        return TM_ECODE_FAILED;
    memset(aun, 0, sizeof(Unified2AlertThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for Unified2Alert.  \"initdata\" argument NULL");
        SCFree(aun);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aun->file_ctx = ((OutputCtx *)initdata)->data;

    aun->data = SCMalloc(sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet) + IPV4_MAXPACKET_LEN);
    if (aun->data == NULL) {
        SCFree(aun);
        return TM_ECODE_FAILED;
    }
    aun->datalen = sizeof(Unified2AlertFileHeader) + sizeof(Unified2Packet) + IPV4_MAXPACKET_LEN;

    *data = (void *)aun;

    return TM_ECODE_OK;
}

/**
 *  \brief Thread deinit function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param data Unified2 thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */

TmEcode Unified2AlertThreadDeinit(ThreadVars *t, void *data)
{
    Unified2AlertThread *aun = (Unified2AlertThread *)data;
    if (aun == NULL) {
        goto error;
    }

    if (!(aun->file_ctx->flags & LOGFILE_ALERTS_PRINTED)) {
        SCLogInfo("Alert unified2 module wrote %"PRIu64" alerts",
                aun->file_ctx->alerts);

        /* Do not print it for each thread */
        aun->file_ctx->flags |= LOGFILE_ALERTS_PRINTED;

    }

    if (aun->data != NULL) {
        SCFree(aun->data);
        aun->data = NULL;
    }
    aun->datalen = 0;
    /* clear memory */
    memset(aun, 0, sizeof(Unified2AlertThread));
    SCFree(aun);
    return TM_ECODE_OK;

error:
    return TM_ECODE_FAILED;
}

/** \brief Create a new LogFileCtx from the provided ConfNode.
 *  \param conf The configuration node for this output.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *Unified2AlertInitCtx(ConfNode *conf)
{
    int ret = 0;
    LogFileCtx* file_ctx = NULL;

    file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC, "Couldn't create new file_ctx");
        goto error;
    }

    const char *filename = NULL;
    if (conf != NULL) { /* To faciliate unit tests. */
        filename = ConfNodeLookupChildValue(conf, "filename");
    }
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;
    file_ctx->prefix = SCStrdup(filename);

    const char *s_limit = NULL;
    file_ctx->size_limit = DEFAULT_LIMIT;
    if (conf != NULL) {
        s_limit = ConfNodeLookupChildValue(conf, "limit");
        if (s_limit != NULL) {
            if (ParseSizeStringU64(s_limit, &file_ctx->size_limit) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize unified2 output, invalid limit: %s",
                    s_limit);
                exit(EXIT_FAILURE);
            }
            if (file_ctx->size_limit < 4096) {
                SCLogInfo("unified2-alert \"limit\" value of %"PRIu64" assumed to be pre-1.2 "
                        "style: setting limit to %"PRIu64"mb", file_ctx->size_limit, file_ctx->size_limit);
                uint64_t size = file_ctx->size_limit * 1024 * 1024;
                file_ctx->size_limit = size;
            } else if (file_ctx->size_limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize unified2 output, limit less than "
                    "allowed minimum: %d.", MIN_LIMIT);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (conf != NULL) {
        const char *sensor_id_s = NULL;
        sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (ByteExtractStringUint32(&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize unified2 output, invalid sensor-id: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
        }
    }

    ret = Unified2AlertOpenFileCtx(file_ctx, filename);
    if (ret < 0)
        goto error;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto error;
    output_ctx->data = file_ctx;
    output_ctx->DeInit = Unified2AlertDeInitCtx;

    SCLogInfo("Unified2-alert initialized: filename %s, limit %"PRIu64" MB",
              filename, file_ctx->size_limit / (1024*1024));

    SC_ATOMIC_INIT(unified2_event_id);

    return output_ctx;

error:
    if (file_ctx != NULL) {
        LogFileFreeCtx(file_ctx);
    }

    return NULL;
}

static void Unified2AlertDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx != NULL) {
        LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
        if (logfile_ctx != NULL) {
            LogFileFreeCtx(logfile_ctx);
        }
        SCFree(output_ctx);
    }
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param prefix Prefix of the log file.
 *  \return -1 if failure, 0 if succesful
 * */
int Unified2AlertOpenFileCtx(LogFileCtx *file_ctx, const char *prefix)
{
    int ret = 0;
    char *filename = NULL;
    if (file_ctx->filename != NULL)
        filename = file_ctx->filename;
    else {
        filename = file_ctx->filename = SCMalloc(PATH_MAX); /* XXX some sane default? */
        if (filename == NULL)
            return -1;

        memset(filename, 0x00, PATH_MAX);
    }

    /** get the time so we can have a filename with seconds since epoch */
    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));

    extern int run_mode;
    if (run_mode == RUNMODE_UNITTEST)
        TimeGet(&ts);
    else
        gettimeofday(&ts, NULL);

    /* create the filename to use */
    char *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;

    snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, log_dir, prefix, (uint32_t)ts.tv_sec);

    file_ctx->fp = fopen(filename, "ab");
    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", filename,
            strerror(errno));
        ret = -1;
    }

    return ret;
}


#ifdef UNITTESTS

/**
 *  \test Test the ethernet+ipv4+tcp unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test01 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    OutputCtx *oc;
    LogFileCtx *lf;
    Signature s;

    uint8_t raw_ipv4_tcp[] = {
        0x00, 0x14, 0xbf, 0xe8, 0xcb, 0x26, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x8c, 0x55, 0x40, 0x00, 0x40, 0x06,
        0x69, 0x86, 0xc0, 0xa8, 0x0a, 0x68, 0x4a, 0x7d,
        0x2f, 0x53, 0xc2, 0x40, 0x00, 0x50, 0x1f, 0x00,
        0xa4, 0xd4, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x3d, 0x4e, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x1c,
        0x28, 0x81, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&s, 0, sizeof(Signature));

    PACKET_INITIALIZE(p);

    p->alerts.cnt++;
    p->alerts.alerts[p->alerts.cnt-1].s = &s;
    p->alerts.alerts[p->alerts.cnt-1].s->id = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->gid = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->rev = 1;
    SET_PKT_LEN(p, sizeof(raw_ipv4_tcp));

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_ipv4_tcp, sizeof(raw_ipv4_tcp), &pq);

    FlowShutdown();

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL) {
        SCFree(p);
        return 0;
    }
    lf = (LogFileCtx *)oc->data;
    if(lf == NULL) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2Alert(&tv, p, data, &pq, NULL);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }

    Unified2AlertDeInitCtx(oc);

    PACKET_CLEANUP(p);
    SCFree(p);
    return 1;
}

/**
 *  \test Test the ethernet+ipv6+tcp unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test02 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    OutputCtx *oc;
    LogFileCtx *lf;
    Signature s;

    uint8_t raw_ipv6_tcp[] = {
        0x00, 0x11, 0x25, 0x82, 0x95, 0xb5, 0x00, 0xd0,
        0x09, 0xe3, 0xe8, 0xde, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x28, 0x06, 0x40, 0x20, 0x01,
        0x06, 0xf8, 0x10, 0x2d, 0x00, 0x00, 0x02, 0xd0,
        0x09, 0xff, 0xfe, 0xe3, 0xe8, 0xde, 0x20, 0x01,
        0x06, 0xf8, 0x09, 0x00, 0x07, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xe7, 0x41,
        0x00, 0x50, 0xab, 0xdc, 0xd6, 0x60, 0x00, 0x00,
        0x00, 0x00, 0xa0, 0x02, 0x16, 0x80, 0x41, 0xa2,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xa0, 0x04, 0x02,
        0x08, 0x0a, 0x00, 0x0a, 0x22, 0xa8, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x03, 0x03, 0x05 };
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&s, 0, sizeof(Signature));

    PACKET_INITIALIZE(p);

    p->alerts.cnt++;
    p->alerts.alerts[p->alerts.cnt-1].s = &s;
    p->alerts.alerts[p->alerts.cnt-1].s->id = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->gid = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->rev = 1;
    SET_PKT_LEN(p, sizeof(raw_ipv6_tcp));

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_ipv6_tcp, sizeof(raw_ipv6_tcp), &pq);

    FlowShutdown();

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL) {
        SCFree(p);
        return 0;
    }
    lf = (LogFileCtx *)oc->data;
    if(lf == NULL) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }
    ret = Unified2Alert(&tv, p, data, &pq, NULL);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }

    Unified2AlertDeInitCtx(oc);

    PACKET_CLEANUP(p);
    SCFree(p);
    return 1;
}


/**
 *  \test Test the GRE unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test03 (void) {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    OutputCtx *oc;
    LogFileCtx *lf;
    Signature s;

    uint8_t raw_gre[] = {
        0x00, 0x0e, 0x50, 0x06, 0x42, 0x96, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x74, 0x35, 0xa2, 0x40, 0x00, 0x40, 0x2f,
        0xef, 0xcb, 0x0a, 0x00, 0x00, 0x64, 0x0a, 0x00,
        0x00, 0x8a, 0x30, 0x01, 0x88, 0x0b, 0x00, 0x54,
        0x00, 0x00, 0x00, 0x18, 0x29, 0x5f, 0xff, 0x03,
        0x00, 0x21, 0x45, 0x00, 0x00, 0x50, 0xf4, 0x05,
        0x40, 0x00, 0x3f, 0x06, 0x20, 0xb8, 0x50, 0x7e,
        0x2b, 0x2d, 0xd4, 0xcc, 0xd6, 0x72, 0x0a, 0x92,
        0x1a, 0x0b, 0xc9, 0xaf, 0x24, 0x02, 0x8c, 0xdd,
        0x45, 0xf6, 0x80, 0x18, 0x21, 0xfc, 0x10, 0x7c,
        0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x08, 0x19,
        0x1a, 0xda, 0x84, 0xd6, 0xda, 0x3e, 0x50, 0x49,
        0x4e, 0x47, 0x20, 0x73, 0x74, 0x65, 0x72, 0x6c,
        0x69, 0x6e, 0x67, 0x2e, 0x66, 0x72, 0x65, 0x65,
        0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x65, 0x74,
        0x0d, 0x0a};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&s, 0, sizeof(Signature));

    PACKET_INITIALIZE(p);

    p->alerts.cnt++;
    p->alerts.alerts[p->alerts.cnt-1].s = &s;
    p->alerts.alerts[p->alerts.cnt-1].s->id = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->gid = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->rev = 1;
    SET_PKT_LEN(p, sizeof(raw_gre));

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_gre, sizeof(raw_gre), &pq);

    FlowShutdown();

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL) {
        SCFree(p);
        return 0;
    }
    lf = (LogFileCtx *)oc->data;
    if(lf == NULL) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }
    ret = Unified2Alert(&tv, p, data, &pq, NULL);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }

    Unified2AlertDeInitCtx(oc);

    Packet *pkt = PacketDequeue(&pq);
    while (pkt != NULL) {
        SCFree(pkt);
        pkt = PacketDequeue(&pq);
    }

    PACKET_CLEANUP(p);
    SCFree(p);
    return 1;
}

/**
 *  \test Test the PPP unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test04 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    OutputCtx *oc;
    LogFileCtx *lf;
    Signature s;

    uint8_t raw_ppp[] = {
        0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c,
        0x4d, 0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17,
        0xbf, 0x01, 0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03,
        0xea, 0x37, 0x00, 0x17, 0x6d, 0x0b, 0xba, 0xc3,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0x10, 0x20,
        0xdd, 0xe1, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&s, 0, sizeof(Signature));

    PACKET_INITIALIZE(p);

    p->alerts.cnt++;
    p->alerts.alerts[p->alerts.cnt-1].s = &s;
    p->alerts.alerts[p->alerts.cnt-1].s->id = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->gid = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->rev = 1;
    SET_PKT_LEN(p, sizeof(raw_ppp));

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &dtv, p, raw_ppp, sizeof(raw_ppp), &pq);

    FlowShutdown();

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL) {
        SCFree(p);
        return 0;
    }
    lf = (LogFileCtx *)oc->data;
    if(lf == NULL) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }
    ret = Unified2Alert(&tv, p, data, &pq, NULL);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }

    Unified2AlertDeInitCtx(oc);

    PACKET_CLEANUP(p);
    SCFree(p);
    return 1;
}

/**
 *  \test Test the ethernet+ipv4+tcp droped unified2 test
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int Unified2Test05 (void)   {
    ThreadVars tv;
    DecodeThreadVars dtv;
    PacketQueue pq;
    void *data = NULL;
    OutputCtx *oc;
    LogFileCtx *lf;
    Signature s;

    uint8_t raw_ipv4_tcp[] = {
        0x00, 0x14, 0xbf, 0xe8, 0xcb, 0x26, 0xaa, 0x00,
        0x04, 0x00, 0x0a, 0x04, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x8c, 0x55, 0x40, 0x00, 0x40, 0x06,
        0x69, 0x86, 0xc0, 0xa8, 0x0a, 0x68, 0x4a, 0x7d,
        0x2f, 0x53, 0xc2, 0x40, 0x00, 0x50, 0x1f, 0x00,
        0xa4, 0xd4, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x3d, 0x4e, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x1c,
        0x28, 0x81, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    int ret;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&pq, 0, sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&s, 0, sizeof(Signature));

    PACKET_INITIALIZE(p);

    p->alerts.cnt++;
    p->alerts.alerts[p->alerts.cnt-1].s = &s;
    p->alerts.alerts[p->alerts.cnt-1].s->id = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->gid = 1;
    p->alerts.alerts[p->alerts.cnt-1].s->rev = 1;
    SET_PKT_LEN(p, sizeof(raw_ipv4_tcp));

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_ipv4_tcp, sizeof(raw_ipv4_tcp), &pq);

    FlowShutdown();

    p->action = ACTION_DROP;

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL) {
        SCFree(p);
        return 0;
    }
    lf = (LogFileCtx *)oc->data;
    if(lf == NULL) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if(ret == -1) {
        SCFree(p);
        return 0;
    }
    ret = Unified2Alert(&tv, p, data, &pq, NULL);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == TM_ECODE_FAILED) {
        SCFree(p);
        return 0;
    }

    Unified2AlertDeInitCtx(oc);

    PACKET_CLEANUP(p);
    SCFree(p);
    return 1;
}

/**
 *  \test Test the Rotate process
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int Unified2TestRotate01(void)
{
    int ret = 0;
    int r = 0;
    ThreadVars tv;
    OutputCtx *oc;
    LogFileCtx *lf;
    void *data = NULL;
    char *filename = NULL;

    oc = Unified2AlertInitCtx(NULL);
    if (oc == NULL)
        return 0;
    lf = (LogFileCtx *)oc->data;
    if (lf == NULL)
        return 0;
    filename = SCStrdup(lf->filename);
    if (unlikely(filename == NULL))
        return 0;

    memset(&tv, 0, sizeof(ThreadVars));

    ret = Unified2AlertThreadInit(&tv, oc, &data);
    if (ret == TM_ECODE_FAILED) {
        LogFileFreeCtx(lf);
        if (filename != NULL)
            SCFree(filename);
        return 0;
    }

    TimeSetIncrementTime(1);

    ret = Unified2AlertRotateFile(&tv, data);
    if (ret == -1)
        goto error;

    if (strcmp(filename, lf->filename) == 0) {
        SCLogError(SC_ERR_UNIFIED2_ALERT_GENERIC,
                   "filename \"%s\" == \"%s\": ", filename, lf->filename);
        goto error;
    }

    r = 1;

error:
    ret = Unified2AlertThreadDeinit(&tv, data);
    if(ret == TM_ECODE_FAILED) {
        printf("Unified2AlertThreadDeinit error");
    }
    if (oc != NULL)
        Unified2AlertDeInitCtx(oc);
    if (filename != NULL)
        SCFree(filename);
    return r;
}
#endif

/**
 * \brief this function registers unit tests for Unified2
 */
void Unified2RegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("Unified2Test01 -- Ipv4 test", Unified2Test01, 1);
    UtRegisterTest("Unified2Test02 -- Ipv6 test", Unified2Test02, 1);
    UtRegisterTest("Unified2Test03 -- GRE test", Unified2Test03, 1);
    UtRegisterTest("Unified2Test04 -- PPP test", Unified2Test04, 1);
    UtRegisterTest("Unified2Test05 -- Inline test", Unified2Test05, 1);
    UtRegisterTest("Unified2TestRotate01 -- Rotate File", Unified2TestRotate01, 1);
#endif /* UNITTESTS */
}
