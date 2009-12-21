/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "decode.h"
#include "decode-udp.h"
#include "decode-events.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow.h"

/**
 * \brief Calculates the checksum for the UDP packet
 *
 * \param shdr Pointer to source address field from the IP packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the UDP packet
 * \param hlen Total length of the UDP packet(header + payload)
 *
 * \retval csum Checksum for the UDP packet
 */
inline uint16_t UDPV4CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                       uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + htons(17 + tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);

    return (uint16_t) ~csum;
}

/**
 * \brief Calculates the checksum for the UDP packet
 *
 * \param shdr Pointer to source address field from the IPV6 packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the UDP packet
 * \param tlen Total length of the UDP packet(header + payload)
 *
 * \retval csum Checksum for the UDP packet
 */
inline uint16_t UDPV6CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                       uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + shdr[4] + shdr[5] + shdr[6] +
        shdr[7] + shdr[8] + shdr[9] + shdr[10] + shdr[11] + shdr[12] +
        shdr[13] + shdr[14] + shdr[15] + htons(17 + tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);

    return (uint16_t) ~csum;
}

static int DecodeUDPPacket(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (len < UDP_HEADER_LEN) {
        DECODER_SET_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    if (len < UDP_GET_LEN(p)) {
        DECODER_SET_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (len != UDP_GET_LEN(p)) {
        DECODER_SET_EVENT(p, UDP_HLEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(p,&p->sp);
    SET_UDP_DST_PORT(p,&p->dp);

    p->udpvars.hlen = UDP_HEADER_LEN;
    p->payload = pkt + UDP_HEADER_LEN;
    p->payload_len = len - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

void DecodeUDP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_udp, tv->sc_perf_pca);

    if (DecodeUDPPacket(tv, p,pkt,len) < 0) {
        p->udph = NULL;
        return;
    }

    SCLogDebug("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 "",
        UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN, p->payload_len);

    /* Flow is an integral part of us */
    FlowHandlePacket(tv, p);

    return;
}

#ifdef UNITTESTS
static int UDPV4CalculateValidChecksumtest01(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0xd0, 0x43, 0xdc, 0xdc, 0xc0, 0xa8, 0x01, 0x3};

    uint8_t raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    csum = *( ((uint16_t *)raw_udp) + 3);

    return (csum == UDPV4CalculateChecksum((uint16_t *) raw_ipshdr,
                                           (uint16_t *)raw_udp,
                                           sizeof(raw_udp)));
}

static int UDPV4CalculateInvalidChecksumtest02(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0xd0, 0x43, 0xdc, 0xdc, 0xc0, 0xa8, 0x01, 0x3};

    uint8_t raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    csum = *( ((uint16_t *)raw_udp) + 3);

    return (csum == UDPV4CalculateChecksum((uint16_t *) raw_ipshdr,
                                           (uint16_t *)raw_udp,
                                           sizeof(raw_udp)));
}

static int UDPV6CalculateValidChecksumtest03(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    csum = *( ((uint16_t *)(raw_ipv6 + 60)));

    return (csum == UDPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                           (uint16_t *)(raw_ipv6 + 54), 20));
}

static int UDPV6CalculateInvalidChecksumtest04(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    csum = *( ((uint16_t *)(raw_ipv6 + 60)));

    return (csum == UDPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                           (uint16_t *)(raw_ipv6 + 54), 20));
}
#endif /* UNITTESTS */

void DecodeUDPV4RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("UDPV4CalculateValidChecksumtest01",
                   UDPV4CalculateValidChecksumtest01, 1);
    UtRegisterTest("UDPV4CalculateInvalidChecksumtest02",
                   UDPV4CalculateInvalidChecksumtest02, 0);
    UtRegisterTest("UDPV6CalculateValidChecksumtest03",
                   UDPV6CalculateValidChecksumtest03, 1);
    UtRegisterTest("UDPV6CalculateInvalidChecksumtest04",
                   UDPV6CalculateInvalidChecksumtest04, 0);
#endif /* UNITTESTS */
}
