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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements checksum keyword.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-csum.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

/* prototypes for the "ipv4-csum" rule keyword */
int DetectIPV4CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                        Signature *, const SigMatchCtx *);
static int DetectIPV4CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectIPV4CsumFree(void *);

/* prototypes for the "tcpv4-csum" rule keyword */
int DetectTCPV4CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectTCPV4CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectTCPV4CsumFree(void *);

/* prototypes for the "tcpv6-csum" rule keyword */
int DetectTCPV6CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectTCPV6CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectTCPV6CsumFree(void *);

/* prototypes for the "udpv4-csum" rule keyword */
int DetectUDPV4CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectUDPV4CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectUDPV4CsumFree(void *);

/* prototypes for the "udpv6-csum" rule keyword */
int DetectUDPV6CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectUDPV6CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectUDPV6CsumFree(void *);

/* prototypes for the "icmpv4-csum" rule keyword */
int DetectICMPV4CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectICMPV4CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectICMPV4CsumFree(void *);

/* prototypes for the "icmpv6-csum" rule keyword */
int DetectICMPV6CsumMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                         Signature *, const SigMatchCtx *);
static int DetectICMPV6CsumSetup(DetectEngineCtx *, Signature *, char *);
void DetectICMPV6CsumFree(void *);

void DetectCsumRegisterTests(void);

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
    sigmatch_table[DETECT_IPV4_CSUM].RegisterTests = DetectCsumRegisterTests;

    sigmatch_table[DETECT_TCPV4_CSUM].name = "tcpv4-csum";
    sigmatch_table[DETECT_TCPV4_CSUM].Match = DetectTCPV4CsumMatch;
    sigmatch_table[DETECT_TCPV4_CSUM].Setup = DetectTCPV4CsumSetup;
    sigmatch_table[DETECT_TCPV4_CSUM].Free  = DetectTCPV4CsumFree;
    sigmatch_table[DETECT_TCPV4_CSUM].RegisterTests = NULL;

    sigmatch_table[DETECT_TCPV6_CSUM].name = "tcpv6-csum";
    sigmatch_table[DETECT_TCPV6_CSUM].Match = DetectTCPV6CsumMatch;
    sigmatch_table[DETECT_TCPV6_CSUM].Setup = DetectTCPV6CsumSetup;
    sigmatch_table[DETECT_TCPV6_CSUM].Free  = DetectTCPV6CsumFree;
    sigmatch_table[DETECT_TCPV6_CSUM].RegisterTests = NULL;

    sigmatch_table[DETECT_UDPV4_CSUM].name = "udpv4-csum";
    sigmatch_table[DETECT_UDPV4_CSUM].Match = DetectUDPV4CsumMatch;
    sigmatch_table[DETECT_UDPV4_CSUM].Setup = DetectUDPV4CsumSetup;
    sigmatch_table[DETECT_UDPV4_CSUM].Free  = DetectUDPV4CsumFree;
    sigmatch_table[DETECT_UDPV4_CSUM].RegisterTests = NULL;

    sigmatch_table[DETECT_UDPV6_CSUM].name = "udpv6-csum";
    sigmatch_table[DETECT_UDPV6_CSUM].Match = DetectUDPV6CsumMatch;
    sigmatch_table[DETECT_UDPV6_CSUM].Setup = DetectUDPV6CsumSetup;
    sigmatch_table[DETECT_UDPV6_CSUM].Free  = DetectUDPV6CsumFree;
    sigmatch_table[DETECT_UDPV6_CSUM].RegisterTests = NULL;

    sigmatch_table[DETECT_ICMPV4_CSUM].name = "icmpv4-csum";
    sigmatch_table[DETECT_ICMPV4_CSUM].Match = DetectICMPV4CsumMatch;
    sigmatch_table[DETECT_ICMPV4_CSUM].Setup = DetectICMPV4CsumSetup;
    sigmatch_table[DETECT_ICMPV4_CSUM].Free  = DetectICMPV4CsumFree;
    sigmatch_table[DETECT_ICMPV4_CSUM].RegisterTests = NULL;

    sigmatch_table[DETECT_ICMPV6_CSUM].name = "icmpv6-csum";
    sigmatch_table[DETECT_ICMPV6_CSUM].Match = DetectICMPV6CsumMatch;
    sigmatch_table[DETECT_ICMPV6_CSUM].Setup = DetectICMPV6CsumSetup;
    sigmatch_table[DETECT_ICMPV6_CSUM].Free  = DetectICMPV6CsumFree;
    sigmatch_table[DETECT_ICMPV6_CSUM].RegisterTests = NULL;

    return;
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
            goto error;
        }
        str[strlen(key) - 2] = '\0';
    } else {
        str = SCStrdup(key);
        if (unlikely(str == NULL)) {
            goto error;
        }
    }

    if (strcasecmp(str, DETECT_CSUM_VALID) == 0 ||
        strcasecmp(str, DETECT_CSUM_INVALID) == 0) {
        cd->valid = (strcasecmp(key, DETECT_CSUM_VALID) == 0);
        SCFree(str);
        return 1;
    }

error:
    if (str != NULL)
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
int DetectIPV4CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip4h == NULL || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level3_comp_csum == -1)
        p->level3_comp_csum = IPV4CalculateChecksum((uint16_t *)p->ip4h,
                                                    IPV4_GET_HLEN(p));

    if (p->level3_comp_csum == p->ip4h->ip_csum && cd->valid == 1)
        return 1;
    else if (p->level3_comp_csum != p->ip4h->ip_csum && cd->valid == 0)
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
static int DetectIPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPV4_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectIPV4CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectIPV4CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectTCPV4CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                         Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip4h == NULL || p->tcph == NULL || p->proto != IPPROTO_TCP || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = TCPCalculateChecksum(p->ip4h->s_ip_addrs,
                                                   (uint16_t *)p->tcph,
                                                   (p->payload_len + TCP_GET_HLEN(p)));

    if (p->level4_comp_csum == p->tcph->th_sum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->tcph->th_sum && cd->valid == 0)
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
static int DetectTCPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TCPV4_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectTCPV4CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectTCPV4CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectTCPV6CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                         Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip6h == NULL || p->tcph == NULL || p->proto != IPPROTO_TCP || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = TCPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                                                     (uint16_t *)p->tcph,
                                                     (p->payload_len + TCP_GET_HLEN(p)));

    if (p->level4_comp_csum == p->tcph->th_sum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->tcph->th_sum && cd->valid == 0)
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
static int DetectTCPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TCPV6_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectTCPV6CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectTCPV6CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectUDPV4CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                         Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip4h == NULL || p->udph == NULL || p->proto != IPPROTO_UDP || PKT_IS_PSEUDOPKT(p) || p->udph->uh_sum == 0)
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = UDPV4CalculateChecksum(p->ip4h->s_ip_addrs,
                                                     (uint16_t *)p->udph,
                                                     (p->payload_len +
                                                      UDP_HEADER_LEN) );

    if (p->level4_comp_csum == p->udph->uh_sum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->udph->uh_sum && cd->valid == 0)
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
static int DetectUDPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_UDPV4_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectUDPV4CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectUDPV4CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectUDPV6CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                         Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip6h == NULL || p->udph == NULL || p->proto != IPPROTO_UDP || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = UDPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                                                     (uint16_t *)p->udph,
                                                     (p->payload_len +
                                                      UDP_HEADER_LEN) );

    if (p->level4_comp_csum == p->udph->uh_sum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->udph->uh_sum && cd->valid == 0)
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
static int DetectUDPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_UDPV6_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (void *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectUDPV6CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectUDPV6CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectICMPV4CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip4h == NULL || p->icmpv4h == NULL || p->proto != IPPROTO_ICMP || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = ICMPV4CalculateChecksum((uint16_t *)p->icmpv4h,
                                                      ntohs(IPV4_GET_RAW_IPLEN(p->ip4h)) -
                                                      IPV4_GET_RAW_HLEN(p->ip4h) * 4);

    if (p->level4_comp_csum == p->icmpv4h->checksum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->icmpv4h->checksum && cd->valid == 0)
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
static int DetectICMPV4CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectCsumSetup: \'%s\'\n", csum_str);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ICMPV4_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectICMPV4CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectICMPV4CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
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
int DetectICMPV6CsumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectCsumData *cd = (const DetectCsumData *)ctx;

    if (p->ip6h == NULL || p->icmpv6h == NULL || p->proto != IPPROTO_ICMPV6 || PKT_IS_PSEUDOPKT(p) ||
        (GET_PKT_LEN(p) - ((uint8_t *)p->icmpv6h - GET_PKT_DATA(p))) <= 0) {
        return 0;
    }

    if (p->flags & PKT_IGNORE_CHECKSUM) {
        return cd->valid;
    }

    if (p->level4_comp_csum == -1)
        p->level4_comp_csum = ICMPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                                                      (uint16_t *)p->icmpv6h,
                                                      GET_PKT_LEN(p) - ((uint8_t *)p->icmpv6h - GET_PKT_DATA(p)));

    if (p->level4_comp_csum == p->icmpv6h->csum && cd->valid == 1)
        return 1;
    else if (p->level4_comp_csum != p->icmpv6h->csum && cd->valid == 0)
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
static int DetectICMPV6CsumSetup(DetectEngineCtx *de_ctx, Signature *s, char *csum_str)
{
    DetectCsumData *cd = NULL;
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ICMPV6_CSUM;

    if ( (cd = SCMalloc(sizeof(DetectCsumData))) == NULL)
        goto error;
    memset(cd, 0, sizeof(DetectCsumData));

    if (DetectCsumParseArg(csum_str, cd) == 0)
        goto error;

    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (cd != NULL) DetectICMPV6CsumFree(cd);
    if (sm != NULL) SCFree(sm);

    return -1;
}

void DetectICMPV6CsumFree(void *ptr)
{
    DetectCsumData *cd = (DetectCsumData *)ptr;

    if (cd != NULL)
        SCFree(cd);

    return;
}

/* ---------------------------------- Unit Tests --------------------------- */

#ifdef UNITTESTS

int DetectCsumIPV4ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectIPV4CsumSetup(NULL, &s, "\"valid\"") == 0);
    result &= (DetectIPV4CsumSetup(NULL, &s, "\"invalid\"") == 0);
    result &= (DetectIPV4CsumSetup(NULL, &s, "\"vaLid\"") == 0);
    result &= (DetectIPV4CsumSetup(NULL, &s, "\"VALID\"") == 0);
    result &= (DetectIPV4CsumSetup(NULL, &s, "\"iNvaLid\"") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectIPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumIPV4InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectIPV4CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectIPV4CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectIPV4CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectIPV4CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectIPV4CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectIPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumIPV4ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectIPV4CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectIPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectIPV4CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectIPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV4ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV4CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectICMPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV4InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV4CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectICMPV4CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectICMPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV4ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV4CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectICMPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectICMPV4CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectICMPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV4ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV4CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectTCPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV4InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV4CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectTCPV4CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectTCPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV4ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV4CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectTCPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectTCPV4CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectTCPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV4ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV4CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectUDPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV4InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV4CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectUDPV4CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectUDPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV4ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV4CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectUDPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectUDPV4CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectUDPV4CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV6ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV6CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectTCPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV6InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV6CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectTCPV6CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectTCPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumTCPV6ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectTCPV6CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectTCPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectTCPV6CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectTCPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV6ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV6CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectUDPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV6InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV6CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectUDPV6CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectUDPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumUDPV6ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectUDPV6CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectUDPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectUDPV6CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectUDPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV6ValidArgsTestParse01(void)
{
    Signature s;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV6CsumSetup(NULL, &s, "valid") == 0);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "invalid") == 0);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "vaLid") == 0);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "VALID") == 0);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "iNvaLid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectICMPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV6InValidArgsTestParse02(void)
{
    Signature s;
    int result = -1;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV6CsumSetup(NULL, &s, "vaid") == -1);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "invaalid") == -1);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "vaLiid") == -1);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "VALieD") == -1);
    result &= (DetectICMPV6CsumSetup(NULL, &s, "iNvamid") == -1);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        DetectICMPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

int DetectCsumICMPV6ValidArgsTestParse03(void)
{
    Signature s;
    DetectCsumData *cd = NULL;
    int result = 0;
    SigMatch *temp = NULL;

    memset(&s, 0, sizeof(Signature));

    result = (DetectICMPV6CsumSetup(NULL, &s, "valid") == 0);

    while (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 1);
        }
        DetectICMPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }
    s.sm_lists[DETECT_SM_LIST_MATCH] = NULL;

    result &= (DetectICMPV6CsumSetup(NULL, &s, "INVALID") == 0);

    if (s.sm_lists[DETECT_SM_LIST_MATCH] != NULL) {
        if (s.sm_lists[DETECT_SM_LIST_MATCH]->ctx != NULL) {
            cd = (DetectCsumData *)s.sm_lists[DETECT_SM_LIST_MATCH]->ctx;
            result &= (cd->valid == 0);
        }
        DetectICMPV6CsumFree(s.sm_lists[DETECT_SM_LIST_MATCH]->ctx);
        temp = s.sm_lists[DETECT_SM_LIST_MATCH];
        s.sm_lists[DETECT_SM_LIST_MATCH] = s.sm_lists[DETECT_SM_LIST_MATCH]->next;
        SCFree(temp);
    }

    return result;
}

#include "detect-engine.h"
#include "stream-tcp.h"

int DetectCsumICMPV6Test01(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DecodeThreadVars dtv;

    Packet *p = PacketGetFromAlloc();
    if (p == NULL) {
        printf("failure PacketGetFromAlloc\n");
        goto end;
    }

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

    StreamTcpInitConfig(TRUE);
    FlowInitConfig(FLOW_QUIET);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        printf("DetectEngineCtxInit failure\n");
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ip any any -> any any "
                                   "(icmpv6-csum:valid; sid:1;)");
    if (s == NULL) {
        printf("SigInit failed\n");
        goto end;
    }
    SigGroupBuild(de_ctx);

    DecodeEthernet(&tv, &dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), NULL);

    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert on p, but it should: ");
        goto end;
    }

    result = 1;

 end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);

    return result;
}

#endif /* UNITTESTS */

void DetectCsumRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("DetectCsumIPV4ValidArgsTestParse01",
                   DetectCsumIPV4ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumIPV4InValidArgsTestParse02",
                   DetectCsumIPV4InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumIPV4ValidArgsTestParse03",
                   DetectCsumIPV4ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumICMPV4ValidArgsTestParse01",
                   DetectCsumICMPV4ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumICMPV4InValidArgsTestParse02",
                   DetectCsumICMPV4InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumICMPV4ValidArgsTestParse03",
                   DetectCsumICMPV4ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumTCPV4ValidArgsTestParse01",
                   DetectCsumTCPV4ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumTCPV4InValidArgsTestParse02",
                   DetectCsumTCPV4InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumTCPV4ValidArgsTestParse03",
                   DetectCsumTCPV4ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumUDPV4ValidArgsTestParse01",
                   DetectCsumUDPV4ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumUDPV4InValidArgsTestParse02",
                   DetectCsumUDPV4InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumUDPV4ValidArgsTestParse03",
                   DetectCsumUDPV4ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumUDPV6ValidArgsTestParse01",
                   DetectCsumUDPV6ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumUDPV6InValidArgsTestParse02",
                   DetectCsumUDPV6InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumUDPV6ValidArgsTestParse03",
                   DetectCsumUDPV6ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumTCPV6ValidArgsTestParse01",
                   DetectCsumTCPV6ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumTCPV6InValidArgsTestParse02",
                   DetectCsumTCPV6InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumTCPV6ValidArgsTestParse03",
                   DetectCsumTCPV6ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumICMPV6ValidArgsTestParse01",
                   DetectCsumICMPV6ValidArgsTestParse01, 1);
    UtRegisterTest("DetectCsumICMPV6InValidArgsTestParse02",
                   DetectCsumICMPV6InValidArgsTestParse02, 1);
    UtRegisterTest("DetectCsumICMPV6ValidArgsTestParse03",
                   DetectCsumICMPV6ValidArgsTestParse03, 1);

    UtRegisterTest("DetectCsumICMPV6Test01",
                   DetectCsumICMPV6Test01, 1);


#endif /* UNITTESTS */

}
