/* Copyright (C) 2012-2019 Open Information Security Foundation
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
 * \author Bill Meeks <billmeeks8@gmail.com>
 *
 * Implements the geoip keyword.
 * Updated to use MaxMind GeoIP2 database.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-geoip.h"

#include "util-mem.h"
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
    sigmatch_table[DETECT_GEOIP].desc = "match on the source, destination or source and destination IP addresses of network traffic, and to see to which country it belongs";
    sigmatch_table[DETECT_GEOIP].url = "/rules/header-keywords.html#geoip";
    sigmatch_table[DETECT_GEOIP].Setup = DetectGeoipSetupNoSupport;
    sigmatch_table[DETECT_GEOIP].Free = NULL;
}

#else /* HAVE_GEOIP */

#include <maxminddb.h>

static int DetectGeoipMatch(DetectEngineThreadCtx *, Packet *,
                            const Signature *, const SigMatchCtx *);
static int DetectGeoipSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectGeoipRegisterTests(void);
#endif
static void DetectGeoipDataFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for geoip keyword
 * \todo add support for src_only and dst_only
 */
void DetectGeoipRegister(void)
{
    sigmatch_table[DETECT_GEOIP].name = "geoip";
    sigmatch_table[DETECT_GEOIP].url = "/rules/header-keywords.html#geoip";
    sigmatch_table[DETECT_GEOIP].desc = "keyword to match on country of src and or dst IP";
    sigmatch_table[DETECT_GEOIP].Match = DetectGeoipMatch;
    sigmatch_table[DETECT_GEOIP].Setup = DetectGeoipSetup;
    sigmatch_table[DETECT_GEOIP].Free = DetectGeoipDataFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_GEOIP].RegisterTests = DetectGeoipRegisterTests;
#endif
}

/**
 * \internal
 * \brief This function is used to initialize the geolocation MaxMind engine
 *
 * \retval false if the engine couldn't be initialized
 */
static bool InitGeolocationEngine(DetectGeoipData *geoipdata)
{
    const char *filename = NULL;

    /* Get location and name of GeoIP2 database from YAML conf */
    (void)ConfGet("geoip-database", &filename);

    if (filename == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Unable to locate a GeoIP2"
                     "database filename in YAML conf.  GeoIP rule matching "
                     "is disabled.");
        geoipdata->mmdb_status = MMDB_FILE_OPEN_ERROR;
        return false;
    }

    /* Attempt to open MaxMind DB and save file handle if successful */
    int status = MMDB_open(filename, MMDB_MODE_MMAP, &geoipdata->mmdb);

    if (status == MMDB_SUCCESS) {
        geoipdata->mmdb_status = status;
        return true;
    }

    SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Failed to open GeoIP2 database: %s. "
                 "Error was: %s.  GeoIP rule matching is disabled.", filename,
                 MMDB_strerror(status));
    geoipdata->mmdb_status = status;
    return false;
}

/**
 * \internal
 * \brief This function is used to geolocate the IP using the MaxMind libraries
 *
 * \param ip IPv4 to geolocate (uint32_t ip)
 *
 * \retval NULL if it couldn't be geolocated
 * \retval ptr (const char *) to the country code string
 */
static const char *GeolocateIPv4(const DetectGeoipData *geoipdata, uint32_t ip)
{
    int mmdb_error;
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = ip;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;

    /* Return if no GeoIP database access available */
    if (geoipdata->mmdb_status != MMDB_SUCCESS)
        return NULL;

    /* Attempt to find the IPv4 address in the database */
    result = MMDB_lookup_sockaddr((MMDB_s *)&geoipdata->mmdb,
                                  (struct sockaddr*)&sa, &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS)
        return NULL;

    /* The IPv4 address was found, so grab ISO country code if available */
    if (result.found_entry) {
        mmdb_error = MMDB_get_value(&result.entry, &entry_data, "country",
                                    "iso_code", NULL);
        if (mmdb_error != MMDB_SUCCESS)
            return NULL;

        /* If ISO country code was found, then return it */
        if (entry_data.has_data) {
            if (entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    char *country_code = SCStrndup((char *)entry_data.utf8_string,
                                                    entry_data.data_size);
                    return country_code;
            }
        }
    }

    /* The country code for the IP was not found */
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
 * \param ip IPv4 to geolocate (uint32_t ip)
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int CheckGeoMatchIPv4(const DetectGeoipData *geoipdata, uint32_t ip)
{
    int i;

    /* Attempt country code lookup for the IP address */
    const char *country = GeolocateIPv4(geoipdata, ip);

    /* Skip further checks if did not find a country code */
    if (country == NULL)
        return 0;

    /* Check if NOT NEGATED match-on condition */
    if ((geoipdata->flags & GEOIP_MATCH_NEGATED) == 0)
    {
        for (i = 0; i < geoipdata->nlocations; i++) {
            if (strcmp(country, (char *)geoipdata->location[i])==0) {
                SCFree((void *)country);
                return 1;
            }
        }
    } else {
        /* Check if NEGATED match-on condition */
        for (i = 0; i < geoipdata->nlocations; i++) {
            if (strcmp(country, (char *)geoipdata->location[i])==0) {
                SCFree((void *)country);
                return 0; /* if one matches, rule does NOT match (negated) */
            }
        }
        SCFree((void *)country);
        return 1; /* returns 1 if no location matches (negated) */
    }
    SCFree((void *)country);
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
static int DetectGeoipMatch(DetectEngineThreadCtx *det_ctx,
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
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the geoipdata value string
 *
 * \retval pointer to DetectGeoipData on success
 * \retval NULL on failure
 */
static DetectGeoipData *DetectGeoipDataParse (DetectEngineCtx *de_ctx, const char *str)
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
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "too many arguments for geoip keyword");
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

    /* init geo engine, but not when running as unittests */
    if (!(RunmodeIsUnittests())) {
        /* Initialize the geolocation engine */
        if (InitGeolocationEngine(geoipdata) == false)
            goto error;
    }

    return geoipdata;

error:
    if (geoipdata != NULL)
        DetectGeoipDataFree(de_ctx, geoipdata);
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

    geoipdata = DetectGeoipDataParse(de_ctx, optstr);
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
        DetectGeoipDataFree(de_ctx, geoipdata);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectGeoipData
 *
 * \param geoipdata pointer to DetectGeoipData
 */
static void DetectGeoipDataFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectGeoipData *geoipdata = (DetectGeoipData *)ptr;
        if (geoipdata->mmdb_status == MMDB_SUCCESS)
            MMDB_close(&geoipdata->mmdb);
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
 * \brief This function registers unit tests for DetectGeoip
 */
static void DetectGeoipRegisterTests(void)
{
    UtRegisterTest("GeoipParseTest01", GeoipParseTest01);
    UtRegisterTest("GeoipParseTest02", GeoipParseTest02);
    UtRegisterTest("GeoipParseTest03", GeoipParseTest03);
    UtRegisterTest("GeoipParseTest04", GeoipParseTest04);
    UtRegisterTest("GeoipParseTest05", GeoipParseTest05);
    UtRegisterTest("GeoipParseTest06", GeoipParseTest06);
    UtRegisterTest("GeoipParseTest07", GeoipParseTest07);
}
#endif /* UNITTESTS */
#endif /* HAVE_GEOIP */