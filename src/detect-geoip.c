/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 *
 * Implements the geoip keyword.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-geoip.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifndef HAVE_GEOIP

static int DetectGeoipSetupNoSupport (DetectEngineCtx *a, Signature *b, const char *c)
{
    SCLogError(SC_ERR_NO_GEOIP_SUPPORT, "no GeoIP support built in, needed for geoip keyword");
    return -1;
}

/**
 * \brief Registration function for geoip keyword (no libgeoip support)
 * \todo add support for src_only and dst_only
 */
void DetectGeoipRegister(void)
{
    sigmatch_table[DETECT_GEOIP].name = "geoip";
    sigmatch_table[DETECT_GEOIP].Setup = DetectGeoipSetupNoSupport;
    sigmatch_table[DETECT_GEOIP].Free = NULL;
    sigmatch_table[DETECT_GEOIP].RegisterTests = NULL;
}

#else /* HAVE_GEOIP */

#include <GeoIP.h>

static int DetectGeoipMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                            const Signature *, const SigMatchCtx *);
static int DetectGeoipSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectGeoipRegisterTests(void);
static void DetectGeoipDataFree(void *);

/**
 * \brief Registration function for geoip keyword
 * \todo add support for src_only and dst_only
 */
void DetectGeoipRegister(void)
{
    sigmatch_table[DETECT_GEOIP].name = "geoip";
    sigmatch_table[DETECT_GEOIP].Match = DetectGeoipMatch;
    sigmatch_table[DETECT_GEOIP].Setup = DetectGeoipSetup;
    sigmatch_table[DETECT_GEOIP].Free = DetectGeoipDataFree;
    sigmatch_table[DETECT_GEOIP].RegisterTests = DetectGeoipRegisterTests;
}

/**
 * \internal
 * \brief This function is used to initialize the geolocation MaxMind engine
 *
 * \retval NULL if the engine couldn't be initialized
 * \retval (GeoIP *) to the geolocation engine
 */
static GeoIP *InitGeolocationEngine(void)
{
    return GeoIP_new(GEOIP_MEMORY_CACHE);
}

/**
 * \internal
 * \brief This function is used to geolocate the IP using the MaxMind libraries
 *
 * \param ip IP to geolocate (uint32_t ip)
 *
 * \retval NULL if it couldn't be geolocated
 * \retval ptr (const char *) to the country code string
 */
static const char *GeolocateIPv4(GeoIP *geoengine, uint32_t ip)
{
    if (geoengine != NULL)
        return GeoIP_country_code_by_ipnum(geoengine,  ntohl(ip));
    return NULL;
}

/* Match-on conditions supported */
#define GEOIP_MATCH_SRC_STR     "src"
#define GEOIP_MATCH_DST_STR     "dst"
#define GEOIP_MATCH_BOTH_STR    "both"
#define GEOIP_MATCH_ANY_STR     "any"

#define GEOIP_MATCH_NO_FLAG     0
#define GEOIP_MATCH_SRC_FLAG    1
#define GEOIP_MATCH_DST_FLAG    2
#define GEOIP_MATCH_ANY_FLAG    3 /* default src and dst*/
#define GEOIP_MATCH_BOTH_FLAG   4
#define GEOIP_MATCH_NEGATED     8

/**
 * \internal
 * \brief This function is used to geolocate the IP using the MaxMind libraries
 *
 * \param ip IP to geolocate (uint32_t ip)
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int CheckGeoMatchIPv4(const DetectGeoipData *geoipdata, uint32_t ip)
{
    const char *country;
    int i;
    country = GeolocateIPv4(geoipdata->geoengine, ip);
    /* Check if NOT NEGATED match-on condition */
    if ((geoipdata->flags & GEOIP_MATCH_NEGATED) == 0)
    {
        for (i = 0; i < geoipdata->nlocations; i++)
            if (country != NULL && strcmp(country, (char *)geoipdata->location[i])==0)
                return 1;
    } else {
        /* Check if NEGATED match-on condition */
        for (i = 0; i < geoipdata->nlocations; i++)
            if (country != NULL && strcmp(country, (char *)geoipdata->location[i])==0)
                return 0; /* if one matches, rule does NOT match (negated) */
        return 1; /* returns 1 if no location matches (negated) */
    }
    return 0;
}

/**
 * \internal
 * \brief This function is used to match packets with a IPs in an specified country
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectGeoipData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectGeoipMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                            Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectGeoipData *geoipdata = (const DetectGeoipData *)ctx;
    int matches = 0;

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    if (PKT_IS_IPV4(p))
    {
        if (geoipdata->flags & ( GEOIP_MATCH_SRC_FLAG | GEOIP_MATCH_BOTH_FLAG ))
        {
            if (CheckGeoMatchIPv4(geoipdata, GET_IPV4_SRC_ADDR_U32(p)))
            {
                if (geoipdata->flags & GEOIP_MATCH_BOTH_FLAG)
                    matches++;
                else
                    return 1;
            }
        }
        if (geoipdata->flags & ( GEOIP_MATCH_DST_FLAG | GEOIP_MATCH_BOTH_FLAG ))
        {
            if (CheckGeoMatchIPv4(geoipdata, GET_IPV4_DST_ADDR_U32(p)))
            {
                if (geoipdata->flags & GEOIP_MATCH_BOTH_FLAG)
                    matches++;
                else
                    return 1;
            }
        }
        /* if matches == 2 is because match-on is "both" */
        if (matches == 2)
            return 1;
    }

    return 0;
}

/**
 * \brief This function is used to parse geoipdata
 *
 * \param str Pointer to the geoipdata value string
 *
 * \retval pointer to DetectGeoipData on success
 * \retval NULL on failure
 */
static DetectGeoipData *DetectGeoipDataParse (const char *str)
{
    DetectGeoipData *geoipdata = NULL;
    uint16_t pos = 0;
    uint16_t prevpos = 0;
    uint16_t slen = 0;
    int skiplocationparsing = 0;

    slen = strlen(str);
    if (slen == 0)
        goto error;

    /* We have a correct geoip options string */
    geoipdata = SCMalloc(sizeof(DetectGeoipData));
    if (unlikely(geoipdata == NULL))
        goto error;

    memset(geoipdata, 0x00, sizeof(DetectGeoipData));

    /* Parse the geoip option string */
    while (pos <= slen)
    {
        /* search for ',' or end of string */
        if (str[pos] == ',' || pos == slen)
        {
            if (geoipdata->flags == GEOIP_MATCH_NO_FLAG)
            {
                /* Parse match-on condition */
                if (pos == slen) /* if end of option str then there are no match-on cond. */
                {
                    /* There was NO match-on condition! we default to ANY*/
                    skiplocationparsing = 0;
                    geoipdata->flags |= GEOIP_MATCH_ANY_FLAG;
                } else {
                    skiplocationparsing = 1;
                    if (strncmp(&str[prevpos], GEOIP_MATCH_SRC_STR, pos-prevpos) == 0)
                        geoipdata->flags |= GEOIP_MATCH_SRC_FLAG;
                    else if (strncmp(&str[prevpos], GEOIP_MATCH_DST_STR, pos-prevpos) == 0)
                        geoipdata->flags |= GEOIP_MATCH_DST_FLAG;
                    else if (strncmp(&str[prevpos], GEOIP_MATCH_BOTH_STR, pos-prevpos) == 0)
                        geoipdata->flags |= GEOIP_MATCH_BOTH_FLAG;
                    else if (strncmp(&str[prevpos], GEOIP_MATCH_ANY_STR, pos-prevpos) == 0)
                        geoipdata->flags |= GEOIP_MATCH_ANY_FLAG;
                    else {
                        /* There was NO match-on condition! we default to ANY*/
                        skiplocationparsing = 0;
                        geoipdata->flags |= GEOIP_MATCH_ANY_FLAG;
                    }
                }
            }
            if (geoipdata->flags != GEOIP_MATCH_NO_FLAG && skiplocationparsing == 0)
            {
                /* Parse location string: for now just the country code(s) */
                if (str[prevpos] == '!') {
                    geoipdata->flags |= GEOIP_MATCH_NEGATED;
                    prevpos++; /* dot not copy the ! */
                }

                if (geoipdata->nlocations >= GEOOPTION_MAXLOCATIONS) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "too many arguements for geoip keyword");
                    goto error;
                }

                if (pos-prevpos > GEOOPTION_MAXSIZE)
                    strlcpy((char *)geoipdata->location[geoipdata->nlocations], &str[prevpos],
                                                                            GEOOPTION_MAXSIZE);
                else
                    strlcpy((char *)geoipdata->location[geoipdata->nlocations], &str[prevpos],
                                                                                pos-prevpos+1);

                if (geoipdata->nlocations < GEOOPTION_MAXLOCATIONS)
                    geoipdata->nlocations++;
            }
            prevpos = pos+1;
            skiplocationparsing = 0; /* match-on condition for sure has been parsed already */
        }
        pos++;
    }

    SCLogDebug("GeoIP: %"PRIu32" countries loaded", geoipdata->nlocations);
    for (int i=0; i<geoipdata->nlocations; i++)
        SCLogDebug("GeoIP country code: %s", geoipdata->location[i]);

    SCLogDebug("flags %02X", geoipdata->flags);
    if (geoipdata->flags & GEOIP_MATCH_NEGATED) {
        SCLogDebug("negated geoip");
    }

    /* Initialize the geolocation engine */
    geoipdata->geoengine = InitGeolocationEngine();
    if (geoipdata->geoengine == NULL)
        goto error;

    return geoipdata;

error:
    if (geoipdata != NULL)
        DetectGeoipDataFree(geoipdata);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the geoip option into the signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectGeoipSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    DetectGeoipData *geoipdata = NULL;
    SigMatch *sm = NULL;

    geoipdata = DetectGeoipDataParse(optstr);
    if (geoipdata == NULL)
        goto error;

    /* Get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_GEOIP;
    sm->ctx = (SigMatchCtx *)geoipdata;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (geoipdata != NULL)
        DetectGeoipDataFree(geoipdata);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectGeoipData
 *
 * \param geoipdata pointer to DetectGeoipData
 */
static void DetectGeoipDataFree(void *ptr)
{
    if (ptr != NULL) {
        DetectGeoipData *geoipdata = (DetectGeoipData *)ptr;
        SCFree(geoipdata);
    }
}

#ifdef UNITTESTS

static int GeoipParseTest(const char *rule, int ncountries, const char **countries, uint32_t flags)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    DetectGeoipData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);
    FAIL_IF(de_ctx->sig_list == NULL);

    s = de_ctx->sig_list;
    FAIL_IF(s->sm_lists_tail[DETECT_SM_LIST_MATCH] == NULL);

    FAIL_IF(s->sm_lists_tail[DETECT_SM_LIST_MATCH]->type != DETECT_GEOIP);

    data = (DetectGeoipData *)s->sm_lists_tail[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF(data->flags != flags);

    FAIL_IF(data->nlocations!=ncountries);

    for (int i=0; i<ncountries; i++)
    {
        FAIL_IF(strcmp((char *)data->location[i],countries[i])!=0);
    }

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int GeoipParseTest01(void)
{
    const char *ccodes[1] = {"US"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:US;sid:1;)", 1, ccodes,
                                GEOIP_MATCH_ANY_FLAG);
}

static int GeoipParseTest02(void)
{
    const char *ccodes[1] = {"US"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:!US;sid:1;)", 1, ccodes,
                                GEOIP_MATCH_ANY_FLAG | GEOIP_MATCH_NEGATED);
}

static int GeoipParseTest03(void)
{
    const char *ccodes[1] = {"US"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:!US;sid:1;)", 1, ccodes,
                                GEOIP_MATCH_ANY_FLAG | GEOIP_MATCH_NEGATED);
}

static int GeoipParseTest04(void)
{
    const char *ccodes[1] = {"US"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:src,US;sid:1;)", 1, ccodes,
                                GEOIP_MATCH_SRC_FLAG);
}

static int GeoipParseTest05(void)
{
    const char *ccodes[1] = {"US"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:dst,!US;sid:1;)", 1, ccodes,
                                GEOIP_MATCH_DST_FLAG | GEOIP_MATCH_NEGATED);
}

static int GeoipParseTest06(void)
{
    const char *ccodes[3] = {"US", "ES", "UK"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:US,ES,UK;sid:1;)", 3, ccodes,
                                GEOIP_MATCH_ANY_FLAG);
}

static int GeoipParseTest07(void)
{
    const char *ccodes[3] = {"US", "ES", "UK"};
    return GeoipParseTest("alert tcp any any -> any any (geoip:both,!US,ES,UK;sid:1;)", 3, ccodes,
                                GEOIP_MATCH_BOTH_FLAG | GEOIP_MATCH_NEGATED);
}

/**
 * \internal
 * \brief This test tests geoip success and failure.
 */
static int GeoipMatchTest(const char *rule, const char *srcip, const char *dstip)
{
    uint8_t *buf = (uint8_t *) "GET / HTTP/1.0\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p1 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p1 = UTHBuildPacketSrcDst(buf, buflen, IPPROTO_TCP, srcip, dstip);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, rule);

    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    result = 2;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1) == 0) {
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

static int GeoipMatchTest01(void)
{
    /* Tests with IP of google DNS as US for both src and dst IPs */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:US;sid:1;)", "8.8.8.8", "8.8.8.8");
    /* Expected result 1 = match */
}

static int GeoipMatchTest02(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:JP;sid:1;)", "8.8.8.8",
                    "202.12.27.33");
    /* Expected result 1 = match */
}

static int GeoipMatchTest03(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:dst,JP;sid:1;)",
                    "8.8.8.8", "202.12.27.33");
    /* Expected result 1 = match */
}

static int GeoipMatchTest04(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:src,JP;sid:1;)",
                    "8.8.8.8", "202.12.27.33");
    /* Expected result 2 = NO match */
}

static int GeoipMatchTest05(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:src,JP,US;sid:1;)",
                    "8.8.8.8", "202.12.27.33");
    /* Expected result 1 = match */
}

static int GeoipMatchTest06(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:src,ES,JP,US,UK,PT;sid:1;)",
                    "8.8.8.8", "202.12.27.33");
    /* Expected result 1 = match */
}

static int GeoipMatchTest07(void)
{
    /* Tests with IP of google DNS as US, and m.root-servers.net as japan */
    return GeoipMatchTest("alert tcp any any -> any any (geoip:src,!ES,JP,US,UK,PT;sid:1;)",
                    "8.8.8.8", "202.12.27.33");
    /* Expected result 2 = NO match */
}


#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectGeoip
 */
static void DetectGeoipRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("GeoipParseTest01", GeoipParseTest01);
    UtRegisterTest("GeoipParseTest02", GeoipParseTest02);
    UtRegisterTest("GeoipParseTest03", GeoipParseTest03);
    UtRegisterTest("GeoipParseTest04", GeoipParseTest04);
    UtRegisterTest("GeoipParseTest05", GeoipParseTest05);
    UtRegisterTest("GeoipParseTest06", GeoipParseTest06);
    UtRegisterTest("GeoipParseTest07", GeoipParseTest07);

    UtRegisterTest("GeoipMatchTest01", GeoipMatchTest01);
    UtRegisterTest("GeoipMatchTest02", GeoipMatchTest02);
    UtRegisterTest("GeoipMatchTest03", GeoipMatchTest03);
    UtRegisterTest("GeoipMatchTest04", GeoipMatchTest04);
    UtRegisterTest("GeoipMatchTest05", GeoipMatchTest05);
    UtRegisterTest("GeoipMatchTest06", GeoipMatchTest06);
    UtRegisterTest("GeoipMatchTest07", GeoipMatchTest07);
#endif /* UNITTESTS */
}

#endif /* HAVE_GEOIP */
