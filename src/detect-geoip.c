/* Copyright (C) 2007-2010 Open Information Security Foundation
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

static int DetectGeoipSetupNoSupport (DetectEngineCtx *a, Signature *b, char *c) {
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
                             Signature *, SigMatch *);
static int DetectGeoipSetup(DetectEngineCtx *, Signature *, char *);
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
GeoIP *InitGeolocationEngine(void)
{
    return GeoIP_new(GEOIP_STANDARD);
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
const char *GeolocateIPv4(GeoIP *geoengine, uint32_t ip)
{
    if (geoengine != NULL)
        return GeoIP_country_code_by_ipnum(geoengine,  ntohl(ip));
        //return GeoIP_country_code_by_ipnum(geoengine,  ip);
    return NULL;
}

/**
 * \internal
 * \brief This function is used to match packets with a IPs in an specified country
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSameipData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectGeoipMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                             Packet *p, Signature *s, SigMatch *m)
{
    DetectGeoipData *geoipdata = (DetectGeoipData *)m->ctx;
    const char *country;

    if (PKT_IS_IPV4(p))
    {
        country = GeolocateIPv4(geoipdata->geoengine, GET_IPV4_SRC_ADDR_U32(p));
        if (country != NULL && strncmp(country, (char *)geoipdata->country, strlen(country))==0)
            return 1;
            
        country = GeolocateIPv4(geoipdata->geoengine, GET_IPV4_DST_ADDR_U32(p));
        if (country != NULL && strncmp(country, (char *)geoipdata->country, strlen(country))==0)
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
static DetectGeoipData *DetectGeoipDataParse (char *str)
{
    DetectGeoipData *geoipdata = NULL;

    /* We have a correct country option */
    geoipdata = SCMalloc(sizeof(DetectGeoipData));
    if (unlikely(geoipdata == NULL))
        goto error;

    memset(geoipdata, 0x00, sizeof(DetectGeoipData));

    if (DetectParseContentString (str, &geoipdata->country, &geoipdata->len, &geoipdata->flags) == -1) {
        goto error;
    }

    SCLogDebug("flags %02X", geoipdata->flags);
    if (geoipdata->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated geoip");
    }
    
    /* Initialize the geolocation engine */
    geoipdata->geoengine = InitGeolocationEngine();

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
static int DetectGeoipSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
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
    sm->ctx = (void *)geoipdata;
    
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
static void DetectGeoipDataFree(void *ptr) {
    if (ptr != NULL) {
        DetectGeoipData *geoipdata = (DetectGeoipData *)ptr;
        if (geoipdata->country != NULL)
            SCFree(geoipdata->country);
        SCFree(geoipdata);
    }
}

#ifdef UNITTESTS

/* NOTE: No parameters, so no parse tests */

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectSameip
 */
static void DetectGeoipRegisterTests(void)
{
#ifdef UNITTESTS

#endif /* UNITTESTS */
}

#endif /* HAVE_GEOIP */
