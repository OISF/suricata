/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author William Metcalf <william.metcalf@gmail.com>
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-raw.h"
#include "decode-events.h"

#include "util-unittest.h"
#include "util-debug.h"

void DecodeRaw(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_raw, tv->sc_perf_pca);

    /* If it is ipv4 or ipv6 it should at least be the size of ipv4 */
    if (len < IPV4_HEADER_LEN) {
        DECODER_SET_EVENT(p,IPV4_PKT_TOO_SMALL);
        return;
    }

    if (IP_GET_RAW_VER(pkt) == 4) {
        SCLogDebug("IPV4 Packet");
        DecodeIPV4(tv, dtv, p, p->pkt, p->pktlen, pq);
    } else if (IP_GET_RAW_VER(pkt) == 6) {
        SCLogDebug("IPV6 Packet");
        DecodeIPV6(tv, dtv, p, p->pkt, p->pktlen, pq);
    } else {
        SCLogDebug("Unknown ip version %" PRIu8 "", IP_GET_RAW_VER(pkt));
        DECODER_SET_EVENT(p,IPRAW_INVALID_IPV);
    }
    return;
}

#ifdef UNITTESTS
/** DecodeRawtest01
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest01 (void)   {

    /* IPV6/TCP/no eth header */
    uint8_t raw_ip[] = {
        0xff, 0x00, 0xac, 0x83, 0xfd, 0xcf, 0xea, 0x6a,
        0x24, 0xfb, 0x91, 0xff, 0x00, 0xbd, 0x45, 0x14,
        0xca, 0x8f, 0x51, 0xf7, 0x1f, 0xeb, 0x6e, 0x3f,
        0xdf, 0x3f, 0xd2, 0x9d, 0x65, 0xfe, 0xbd, 0x7f,
        0xeb, 0x89, 0xff, 0x00, 0xd0, 0x4d, 0x14, 0x54,
        0xad, 0x83, 0xa9, 0x0f, 0x65, 0xfa, 0xd2, 0x93,
        0xfb, 0x8b, 0x9f, 0xaa, 0xff, 0x00, 0xec, 0xd4,
        0x51, 0x43, 0x1a, 0x12, 0x4f, 0xf5, 0xaf, 0xff,
        0x00, 0x5c, 0xea, 0x2a, 0x28, 0xa6, 0x89, 0x67,
        0xff, 0xd9 };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(&p,   0, sizeof(Packet));

    DecodeRaw(&tv, &dtv, &p, raw_ip, sizeof(raw_ip), NULL);
    if (p.ip6h == NULL) {
        printf("expected a valid ipv6 header but it was NULL");
        return 0;
    }

    return 1;

}
/** DecodeRawtest02
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest02 (void)   {

    /* IPV4/TCP/no eth header */
    uint8_t raw_ip[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x2f, 0x72, 0x6f,
        0x75, 0x6e, 0x64, 0x31, 0x37, 0x39, 0x2e, 0x78,
        0x6d, 0x6c, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f,
        0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x43, 0x6f, 0x6e,
        0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a,
        0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c,
        0x69, 0x76, 0x65, 0x0d, 0x0a, 0x48, 0x6f, 0x73,
        0x74, 0x3a, 0x20, 0x31, 0x39, 0x32, 0x2e, 0x31,
        0x36, 0x38, 0x2e, 0x31, 0x30, 0x32, 0x2e, 0x32,
        0x0d, 0x0a, 0x0d, 0x0a };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(&p,   0, sizeof(Packet));

    DecodeRaw(&tv, &dtv, &p, raw_ip, sizeof(raw_ip), NULL);
    if (p.ip4h == NULL) {
        printf("expected a valid ipv4 header but it was NULL");
        return 0;
    }

    return 1;
}
/** DecodeRawtest03
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest03 (void)   {

    /* IPV13 */
    uint8_t raw_ip[] = {
        0xdf, 0x00, 0x00, 0x3d, 0x49, 0x42, 0x40, 0x00,
        0x40, 0x06, 0xcf, 0x8a, 0x0a, 0x1f, 0x03, 0xaf,
        0x0a, 0x1f, 0x0a, 0x02, 0xa5, 0xe7, 0xde, 0xad,
        0x00, 0x0c, 0xe2, 0x0e, 0x8b, 0xfe, 0x0c, 0xe7,
        0x80, 0x18, 0x00, 0xb7, 0xaf, 0xeb, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xab, 0x4f,
        0x34, 0x40, 0x67, 0x31, 0x3b, 0x63, 0x61, 0x74,
        0x20, 0x6b, 0x65, 0x79, 0x3b };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(&p,   0, sizeof(Packet));

    DecodeRaw(&tv, &dtv, &p, raw_ip, sizeof(raw_ip), NULL);
    if (DECODER_ISSET_EVENT(&p,IPRAW_INVALID_IPV)) {
        return 0;
    } else {
        printf("expected IPRAW_INVALID_IPV to be set but it wasn't");
    }
    return 1;
}

#endif /* UNITTESTS */

/**
 * \brief Registers Raw unit tests
 * \todo More Raw tests
 */
void DecodeRawRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DecodeRawTest01", DecodeRawTest01, 0);
    UtRegisterTest("DecodeRawTest02", DecodeRawTest02, 0);
    UtRegisterTest("DecodeRawTest03", DecodeRawTest03, 0);
#endif /* UNITTESTS */
}
