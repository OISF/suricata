/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements checksum keyword.
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-csum.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"
#include "detect-engine-build.h"

#define DETECT_CSUM_VALID   "valid"
#define DETECT_CSUM_INVALID "invalid"

typedef struct DetectCsumData_ {
    /* Indicates if the csum-<protocol> keyword in a rule holds the
       keyvalue "valid" or "invalid" */
    int16_t valid;
} DetectCsumData;

/* prototypes for the "ipv4-csum" rule keyword */
static int DetectIPV4CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectIPV4CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectIPV4CsumFree(DetectEngineCtx *, void *);

/* prototypes for the "tcpv4-csum" rule keyword */
static int DetectTCPV4CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTCPV4CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTCPV4CsumFree(DetectEngineCtx *, void *);

/* prototypes for the "tcpv6-csum" rule keyword */
static int DetectTCPV6CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTCPV6CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTCPV6CsumFree(DetectEngineCtx *, void *);

/* prototypes for the "udpv4-csum" rule keyword */
static int DetectUDPV4CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectUDPV4CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectUDPV4CsumFree(DetectEngineCtx *, void *);

/* prototypes for the "udpv6-csum" rule keyword */
static int DetectUDPV6CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectUDPV6CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectUDPV6CsumFree(DetectEngineCtx *de_ctx, void *);

/* prototypes for the "icmpv4-csum" rule keyword */
static int DetectICMPV4CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectICMPV4CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectICMPV4CsumFree(DetectEngineCtx *, void *);

/* prototypes for the "icmpv6-csum" rule keyword */
static int DetectICMPV6CsumMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectICMPV6CsumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectICMPV6CsumFree(DetectEngineCtx *, void *);

#ifdef UNITTESTS
static void DetectCsumRegisterTests(void);
#endif

/**
 * \brief Registers handlers for all the checksum keywords.  The checksum
 *        keywords that are registered are ipv4-sum, tcpv4-csum, tcpv6-csum,
 *        udpv4-csum, udpv6-csum, icmpv4-csum and icmpv6-csum.
 *
 *        Each of the checksum keywords implemented here takes 2 arguments -
 *        "valid" or "invalid".  If the rule keyword in the signature is
 *        specified as "valid", the Match function would return TRUE if the
 *        checksum for that particular packet and protocol is valid.  Similarly
 *        for "invalid".
 *
 *        The Setup functions takes 4 arguments -
 *
 *        DetectEngineCtx * (de_ctx) - A pointer to the detection engine context
 *        Signature *(s) - Pointer to signature for the current Signature being
 *                         parsed from the rules
 *        SigMatchCtx * (m) - Pointer to the head of the SigMatchs added to the
 *                         current Signature being parsed
 *        char * (csum_str) - Pointer to a string holding the keyword value
 *
 *        The Setup function returns 0 if it successfully parses the keyword
 *        value, and -1 otherwise.
 *
 *        The Match function takes 5 arguments -
 *
 *        ThreadVars * (t) - Pointer to the tv for the detection module instance
 *        DetectEngineThreadCtx * (det_ctx) - Pointer to the detection engine
 *                                            thread context
 *        Packet * (p) - Pointer to the Packet currently being handled
 *        Signature * (s) - Pointer to the Signature, the packet is being
 *                          currently matched with
 *        SigMatchCtx * (m) - Pointer to the keyword structure from the above
 *                         Signature, the Packet is being currently matched
 *                         with
 *
 *        The Match function returns 1 if the Packet contents match the keyword,
 *        and 0 otherwise
 *
 *        The Free function takes a single argument -
 *
 *        void * (ptr) - Pointer to the DetectCsumData for a keyword
 */
void DetectCsumRegister (void)
{
    sigmatch_table[DETECT_IPV4_CSUM].name = "ipv4-csum";
    sigmatch_table[DETECT_IPV4_CSUM].Match = DetectIPV4CsumMatch;
    sigmatch_table[DETECT_IPV4_CSUM].Setup = DetectIPV4CsumSetup;
    sigmatch_table[DETECT_IPV4_CSUM].Free  = DetectIPV4CsumFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPV4_CSUM].RegisterTests = DetectCsumRegisterTests;
#endif

    sigmatch_table[DETECT_TCPV4_CSUM].name = "tcpv4-csum";
    sigmatch_table[DETECT_TCPV4_CSUM].Match = DetectTCPV4CsumMatch;
    sigmatch_table[DETECT_TCPV4_CSUM].Setup = DetectTCPV4CsumSetup;
    sigmatch_table[DETECT_TCPV4_CSUM].Free  = DetectTCPV4CsumFree;

    sigmatch_table[DETECT_TCPV6_CSUM].name = "tcpv6-csum";
    sigmatch_table[DETECT_TCPV6_CSUM].Match = DetectTCPV6CsumMatch;
    sigmatch_table[DETECT_TCPV6_CSUM].Setup = DetectTCPV6CsumSetup;
    sigmatch_table[DETECT_TCPV6_CSUM].Free  = DetectTCPV6CsumFree;

    sigmatch_table[DETECT_UDPV4_CSUM].name = "udpv4-csum";
    sigmatch_table[DETECT_UDPV4_CSUM].Match = DetectUDPV4CsumMatch;
    sigmatch_table[DETECT_UDPV4_CSUM].Setup = DetectUDPV4CsumSetup;
    sigmatch_table[DETECT_UDPV4_CSUM].Free  = DetectUDPV4CsumFree;

    sigmatch_table[DETECT_UDPV6_CSUM].name = "udpv6-csum";
    sigmatch_table[DETECT_UDPV6_CSUM].Match = DetectUDPV6CsumMatch;
    sigmatch_table[DETECT_UDPV6_CSUM].Setup = DetectUDPV6CsumSetup;
    sigmatch_table[DETECT_UDPV6_CSUM].Free  = DetectUDPV6CsumFree;

    sigmatch_table[DETECT_ICMPV4_CSUM].name = "icmpv4-csum";
    sigmatch_table[DETECT_ICMPV4_CSUM].Match = DetectICMPV4CsumMatch;
    sigmatch_table[DETECT_ICMPV4_CSUM].Setup = DetectICMPV4CsumSetup;
    sigmatch_table[DETECT_ICMPV4_CSUM].Free  = DetectICMPV4CsumFree;

    sigmatch_table[DETECT_ICMPV6_CSUM].name = "icmpv6-csum";
    sigmatch_table[DETECT_ICMPV6_CSUM].Match = DetectICMPV6CsumMatch;
    sigmatch_table[DETECT_ICMPV6_CSUM].Setup = DetectICMPV6CsumSetup;
    sigmatch_table[DETECT_ICMPV6_CSUM].Free  = DetectICMPV6CsumFree;
}

/**
 * \brief Validates and parses the argument supplied with the checksum keyword.
 *        Accepts strings both with and without quotes, i.e. valid, \"valid\",
 *        invalid and \"invalid\"
 *
 * \param key Pointer to a const character string holding the csum keyword value
 * \param cd  Pointer to the DetectCsumData structure that holds the keyword
 *            value sent as argument
 *
 * \retval 1 the keyvalue has been parsed successfully
 * \retval 0 error
 */
static int DetectCsumParseArg(const char *key, DetectCsumData *cd)
{
    char *str;

    if (key[0] == '\"' && key[strlen(key) - 1] == '\"') {
        str = SCStrdup(key + 1);
        if (unlikely(str == NULL)) {
            return 0;
        }
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (unlikely(str == NULL)) {
            return 0;
        }
    }

    if (strcasecmp(str, DETECT_CSUM_VALID) == 0 ||
        strcasecmp(str, DETECT_CSUM_INVALID) == 0) {
        cd->valid = (strcasecmp(key, DETECT_CSUM_VALID) == 0);
        SCFree(str);
        return 1;
    }

    SCFree(str);
    return 0;
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        ipv4 checksum, based on whether ipv4-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectIPV4CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv4(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l3.csum_set) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        p->l3.csum = IPV4Checksum((uint16_t *)ip4h, IPV4_GET_RAW_HLEN(ip4h), ip4h->ip_csum);
        p->l3.csum_set = true;
    }

    if (p->l3.csum == 0 && cd->valid == 1)
        return 1;
    else if (p->l3.csum != 0 && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the ipv4-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectIPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_IPV4_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectIPV4CsumFree(de_ctx, cd);
    return -1;
}

static void DetectIPV4CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        tcpv4 checksum, based on whether tcpv4-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectTCPV4CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv4(p) || !PacketIsTCP(p) || p->proto != IPPROTO_TCP)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l4.csum_set) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        const TCPHdr *tcph = PacketGetTCP(p);
        p->l4.csum = TCPChecksum(ip4h->s_ip_addrs, (uint16_t *)tcph,
                (p->payload_len + TCP_GET_RAW_HLEN(tcph)), tcph->th_sum);
        p->l4.csum_set = true;
    }
    if (p->l4.csum == 0 && cd->valid == 1)
        return 1;
    else if (p->l4.csum != 0 && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the tcpv4-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectTCPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_TCPV4_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectTCPV4CsumFree(de_ctx, cd);
    return -1;
}

static void DetectTCPV4CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        tcpv6 checksum, based on whether tcpv6-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectTCPV6CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv6(p) || !PacketIsTCP(p) || p->proto != IPPROTO_TCP)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l4.csum_set) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        const TCPHdr *tcph = PacketGetTCP(p);
        p->l4.csum = TCPV6Checksum(ip6h->s_ip6_addrs, (uint16_t *)tcph,
                (p->payload_len + TCP_GET_RAW_HLEN(tcph)), tcph->th_sum);
        p->l4.csum_set = true;
    }

    if (p->l4.csum == 0 && cd->valid == 1)
        return 1;
    else if (p->l4.csum != 0 && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the tcpv6-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectTCPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_TCPV6_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectTCPV6CsumFree(de_ctx, cd);
    return -1;
}

static void DetectTCPV6CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        udpv4 checksum, based on whether udpv4-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectUDPV4CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv4(p) || !PacketIsUDP(p) || p->proto != IPPROTO_UDP)
        return 0;

    const UDPHdr *udph = PacketGetUDP(p);
    if (udph->uh_sum == 0)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l4.csum_set) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        p->l4.csum = UDPV4Checksum(ip4h->s_ip_addrs, (uint16_t *)udph,
                (p->payload_len + UDP_HEADER_LEN), udph->uh_sum);
        p->l4.csum_set = true;
    }
    if (p->l4.csum == 0 && cd->valid == 1)
        return 1;
    else if (p->l4.csum != 0 && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the udpv4-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectUDPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_UDPV4_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectUDPV4CsumFree(de_ctx, cd);
    return -1;
}

static void DetectUDPV4CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        udpv6 checksum, based on whether udpv6-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectUDPV6CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv6(p) || !PacketIsUDP(p) || p->proto != IPPROTO_UDP)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l4.csum_set) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        const UDPHdr *udph = PacketGetUDP(p);
        p->l4.csum = UDPV6Checksum(ip6h->s_ip6_addrs, (uint16_t *)udph,
                (p->payload_len + UDP_HEADER_LEN), udph->uh_sum);
        p->l4.csum_set = true;
    }
    if (p->l4.csum == 0 && cd->valid == 1)
        return 1;
    else if (p->l4.csum != 0 && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the udpv6-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectUDPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_UDPV6_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectUDPV6CsumFree(de_ctx, cd);
    return -1;
}

static void DetectUDPV6CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        icmpv4 checksum, based on whether icmpv4-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectICMPV4CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv4(p) || !PacketIsICMPv4(p) || p->proto != IPPROTO_ICMP)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    if (!p->l4.csum_set) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        p->l4.csum = ICMPV4CalculateChecksum(
                (uint16_t *)icmpv4h, IPV4_GET_RAW_IPLEN(ip4h) - IPV4_GET_RAW_HLEN(ip4h));
        p->l4.csum_set = true;
    }
    if (p->l4.csum == icmpv4h->checksum && cd->valid == 1)
        return 1;
    else if (p->l4.csum != icmpv4h->checksum && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the icmpv4-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectICMPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_ICMPV4_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectICMPV4CsumFree(de_ctx, cd);
    return -1;
}

static void DetectICMPV4CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Checks if the packet sent as the argument, has a valid or invalid
 *        icmpv6 checksum, based on whether icmpv6-csum option for this rule
 *        has been supplied with "valid" or "invalid" argument
 *
 * \param t       Pointer to the tv for this detection module instance
 * \param det_ctx Pointer to the detection engine thread context
 * \param p       Pointer to the Packet currently being matched
 * \param s       Pointer to the Signature, the packet is being currently
 *                matched with
 * \param m       Pointer to the keyword_structure(SigMatch) from the above
 *                Signature, the Packet is being currently matched with
 *
 * \retval 1 if the Packet contents match the keyword option; 0 otherwise
 */
static int DetectICMPV6CsumMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (!PacketIsIPv6(p) || !PacketIsICMPv6(p) || p->proto != IPPROTO_ICMPV6) {
        return 0;
    }
    const ICMPV6Hdr *icmpv6h = PacketGetICMPv6(p);
    if ((GET_PKT_LEN(p) - ((uint8_t *)icmpv6h - GET_PKT_DATA(p))) <= 0) {
        return 0;
    }

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (!p->l4.csum_set) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        uint16_t len = IPV6_GET_RAW_PLEN(ip6h) -
                       (uint16_t)((uint8_t *)icmpv6h - (uint8_t *)ip6h - IPV6_HEADER_LEN);
        p->l4.csum = ICMPV6CalculateChecksum(ip6h->s_ip6_addrs, (uint16_t *)icmpv6h, len);
        p->l4.csum_set = true;
    }

    if (p->l4.csum == icmpv6h->csum && cd->valid == 1)
        return 1;
    else if (p->l4.csum != icmpv6h->csum && cd->valid == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a SigMatch for the icmpv6-csum keyword being sent as argument,
 *        and appends it to the Signature(s).  Accepts 2 values for the
 *        keyword - "valid" and "invalid", both with and without quotes
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param csum_str  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
static int DetectICMPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *csum_str)
{
    DetectCsumData *cd = SCCalloc(1, sizeof(DetectCsumData));
    if (cd == NULL)
        return -1;

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_ICMPV6_CSUM, (SigMatchCtx *)cd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }

    return 0;

error:
    DetectICMPV6CsumFree(de_ctx, cd);
    return -1;
}

static void DetectICMPV6CsumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/* ---------------------------------- Unit Tests --------------------------- */

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "detect-engine.h"
#include "detect-engine-alert.h"
#include "packet.h"

#define mystr(s) #s
#define TEST1(kwstr) {\
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();\
    FAIL_IF_NULL(de_ctx);\
    de_ctx->flags = DE_QUIET;\
    \
    Signature *s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:valid; sid:1;)");\
    FAIL_IF_NULL(s);\
    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:invalid; sid:2;)");\
    FAIL_IF_NULL(s);\
    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:vaLid; sid:3;)");\
    FAIL_IF_NULL(s);\
    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:VALID; sid:4;)");\
    FAIL_IF_NULL(s);\
    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:iNvaLid; sid:5;)");\
    FAIL_IF_NULL(s);\
    DetectEngineCtxFree(de_ctx);\
}


static int DetectCsumValidArgsTestParse01(void)
{
    TEST1(ipv4);
    TEST1(tcpv4);
    TEST1(tcpv6);
    TEST1(udpv4);
    TEST1(udpv6);
    TEST1(icmpv4);
    TEST1(icmpv6);
    PASS;
}
#undef TEST1

#define TEST2(kwstr)                                                                               \
    {                                                                                              \
        DetectEngineCtx *de_ctx = DetectEngineCtxInit();                                           \
        FAIL_IF_NULL(de_ctx);                                                                      \
        Signature *s = DetectEngineAppendSig(                                                      \
                de_ctx, "alert ip any any -> any any (" mystr(kwstr) "-csum:xxxx; sid:1;)");       \
        FAIL_IF(s);                                                                                \
        s = DetectEngineAppendSig(                                                                 \
                de_ctx, "alert ip any any -> any any (" mystr(kwstr) "-csum:xxxxxxxx; sid:2;)");   \
        FAIL_IF(s);                                                                                \
        s = DetectEngineAppendSig(                                                                 \
                de_ctx, "alert ip any any -> any any (" mystr(kwstr) "-csum:xxxxxx; sid:3;)");     \
        FAIL_IF(s);                                                                                \
        s = DetectEngineAppendSig(                                                                 \
                de_ctx, "alert ip any any -> any any (" mystr(kwstr) "-csum:XXXXXX; sid:4;)");     \
        FAIL_IF(s);                                                                                \
        s = DetectEngineAppendSig(                                                                 \
                de_ctx, "alert ip any any -> any any (" mystr(kwstr) "-csum:XxXxXxX; sid:5;)");    \
        FAIL_IF(s);                                                                                \
        DetectEngineCtxFree(de_ctx);                                                               \
    }

static int DetectCsumInvalidArgsTestParse02(void)
{
    TEST2(ipv4);
    TEST2(tcpv4);
    TEST2(tcpv6);
    TEST2(udpv4);
    TEST2(udpv6);
    TEST2(icmpv4);
    TEST2(icmpv6);
    PASS;
}
#undef TEST2

#define TEST3(kwstr, kwtype) { \
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();\
    FAIL_IF_NULL(de_ctx);\
    Signature *s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:valid; sid:1;)");\
    FAIL_IF_NULL(s);\
    SigMatch *sm = DetectGetLastSMFromLists(s, (kwtype), -1);\
    FAIL_IF_NULL(sm);\
    FAIL_IF_NULL(sm->ctx);\
    FAIL_IF_NOT(((DetectCsumData *)sm->ctx)->valid == 1);\
    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any ("mystr(kwstr)"-csum:INVALID; sid:2;)");\
    FAIL_IF_NULL(s);\
    sm = DetectGetLastSMFromLists(s, (kwtype), -1);\
    FAIL_IF_NULL(sm);\
    FAIL_IF_NULL(sm->ctx);\
    FAIL_IF_NOT(((DetectCsumData *)sm->ctx)->valid == 0);\
    DetectEngineCtxFree(de_ctx);\
}

static int DetectCsumValidArgsTestParse03(void)
{
    TEST3(ipv4, DETECT_IPV4_CSUM);
    TEST3(tcpv4, DETECT_TCPV4_CSUM);
    TEST3(tcpv6, DETECT_TCPV6_CSUM);
    TEST3(udpv4, DETECT_UDPV4_CSUM);
    TEST3(udpv6, DETECT_UDPV6_CSUM);
    TEST3(icmpv4, DETECT_ICMPV4_CSUM);
    TEST3(icmpv6, DETECT_ICMPV6_CSUM);
    PASS;
}
#undef TEST3
#undef mystr

#include "stream-tcp.h"

static int DetectCsumICMPV6Test01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DecodeThreadVars dtv;

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    uint8_t pkt[] = {
        0x00, 0x30, 0x18, 0xa8, 0x7c, 0x23, 0x2c, 0x41,
        0x38, 0xa7, 0xea, 0xeb, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x3c, 0x40, 0xad, 0xa1,
        0x09, 0x80, 0x00, 0x01, 0xd6, 0xf3, 0x20, 0x01,
        0xf4, 0xbe, 0xea, 0x3c, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x32, 0xb2, 0x00, 0x01, 0x32, 0xb2,
        0x09, 0x80, 0x20, 0x01, 0x00, 0x00, 0x3c, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x63, 0xc2, 0x00, 0x00, 0x00, 0x00 };

    PacketCopyData(p, pkt, sizeof(pkt));

    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    StreamTcpInitConfig(true);
    FlowInitConfig(FLOW_QUIET);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ip any any -> any any "
                                   "(icmpv6-csum:valid; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);

    DecodeEthernet(&tv, &dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(!PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    PacketRecycle(p);
    FlowShutdown();
    SCFree(p);
    PASS;
}

static void DetectCsumRegisterTests(void)
{
    UtRegisterTest("DetectCsumValidArgsTestParse01",
                   DetectCsumValidArgsTestParse01);
    UtRegisterTest("DetectCsumInvalidArgsTestParse02",
                   DetectCsumInvalidArgsTestParse02);
    UtRegisterTest("DetectCsumValidArgsTestParse03",
                   DetectCsumValidArgsTestParse03);

    UtRegisterTest("DetectCsumICMPV6Test01",
            DetectCsumICMPV6Test01);
}
#endif /* UNITTESTS */
