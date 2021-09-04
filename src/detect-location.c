/* Copyright (C) 2021 IPFire Development Team
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
 * \author Michael Tremer <michael.tremer@ipfire.org>
 *
 * Implements IPFire Location support (geoip keyword)
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "detect-location.h"

#ifdef HAVE_LIBLOC

#include <libloc/libloc.h>
#include <libloc/country.h>

/**
 * \brief This function will free all resources used by the location module
 *
 * \param Pointer to DetectLocationData
 */
static void DetectLocationFree(DetectEngineCtx* ctx, void* ptr) {
    if (!ptr)
        return;

    // Cast to DetectLocationData
    struct DetectLocationData* data = (struct DetectLocationData*)ptr;

    // Free countries
    if (data->countries) {
        for (char** country = data->countries; *country; country++)
            SCFree(*country);
        SCFree(data->countries);
    }

    // Free database
    if (data->ctx)
        loc_unref(data->ctx);

    SCFree(data);
}

static const struct keyword {
    const char* keyword;
    int flags;
} keywords[] = {
    { "src,",  LOCATION_FLAG_SRC, },
    { "dst,",  LOCATION_FLAG_DST, },
    { "both,", LOCATION_FLAG_BOTH, },
    { "any,",  LOCATION_FLAG_SRC|LOCATION_FLAG_DST, },
    { NULL, 0 },
};

static size_t count_commas(const char* s) {
    size_t commas = 0;

    for (; *s; s++)
        if (*s == ',')
            commas++;

    return commas;
}

static struct DetectLocationData* DetectLocationParse(DetectEngineCtx* ctx,
        const char* string) {
    // Check for valid input
    if (!string || !*string)
        return NULL;

    // Allocate DetectLocationData
    struct DetectLocationData* data = SCCalloc(1, sizeof(*data));
    if (!data)
        return NULL;

    const char* p = string;

    // Find any keywords
    for (const struct keyword* keyword = keywords; keyword->keyword; keyword++) {
        size_t length = strlen(keyword->keyword);

        if (strncmp(p, keyword->keyword, length) == 0) {
            data->flags |= keyword->flags;
            p += length;
            break;
        }
    }

    // Default to "any" if nothing was set
    if (!data->flags)
        data->flags |= LOCATION_FLAG_SRC|LOCATION_FLAG_DST;

    // Is the list negated?
    if (*p == '!') {
        data->flags |= LOCATION_FLAG_NEGATED;
        p++;
    }

    // If the string ends here, we have some invalid input
    if (!*p) {
         SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid argument for geoip keyword");
         goto ERROR;
    }

    // Parse countries
    const size_t num_countries = count_commas(p) + 1;

    // Allocate space for the list of country codes
    data->countries = SCCalloc(num_countries + 1, sizeof(*data->countries));
    if (!data->countries)
        goto ERROR;

    for (unsigned int i = 0; i < num_countries; i++) {
        const size_t length = strlen(p);

        // Country codes must at least be 
        if (length < 2) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid country code for geoip keyword");
            goto ERROR;
        }

        // Copy country code to heap
        char* country_code = SCStrndup(p, 2);
        if (!country_code)
            goto ERROR;

        // Append country code to array
        data->countries[i] = country_code;

        // Check if the country code is valid
        if (!loc_country_code_is_valid(country_code)) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid country code for geoip keyword: %s",
                country_code);
            goto ERROR;
        }

        // Advance p
        p += 2;

        // End loop if we have read the entire string
        if (!*p)
            break;

        // Otherwise the country code must be followed by a comma
        if (*p != ',') {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid country code for geoip keyword");
            goto ERROR;
        }

        // Skip the comma
        p++;
    }

    SCLogDebug("Location rule parsed (flags = %02x)", data->flags);
    for (char** country = data->countries; *country; country++)
        SCLogDebug("  Country Code: %s", *country);

    return data;

ERROR:
    DetectLocationFree(ctx, data);

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
static int DetectLocationSetup(DetectEngineCtx* ctx, Signature* signature, const char* optstring) {
    struct DetectLocationData* data = NULL;
    SigMatch* match = NULL;

    // Parse the option string
    data = DetectLocationParse(ctx, optstring);
    if (!data)
        goto ERROR;

    // Allocate a new SigMatch structure
    match = SigMatchAlloc();
    if (!match)
        goto ERROR;

    match->type = DETECT_GEOIP;
    match->ctx = (SigMatchCtx*)data;

    SigMatchAppendSMToList(signature, match, DETECT_SM_LIST_MATCH);

    // We require the packet in order to perform any checks
    signature->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

ERROR:
    if (data)
        DetectLocationFree(ctx, data);
    if (match)
        SCFree(match);

    return -1;
}

/**
 * \internal
 * \brief This function determines the location of the sender/recipient IP address
 *
 * \param ctx points to the pattern matcher thread
 * \param packet points to the current packet
 * \param ptr points to DetectLocationData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectLocationMatch(DetectEngineThreadCtx* ctx, Packet* packet,
        const Signature* signature, const SigMatchCtx* ptr) {
    struct DetectLocationData* data = (struct DetectLocationData*)ptr;

    return 1;
}

#else /* HAVE_LIBLOC */

static int DetectLocationSetup(DetectEngineCtx* ctx, Signature* signature, const char* optstring) {
    SCLogError(SC_ERR_NO_LOCATION_SUPPORT,
        "Support for IPFire Location is not built in (needed for geoip keyword)");
    return -1;
}

#endif /* HAVE_LIBLOC */

/**
 * \brief Registers support for IPFire Location (geoip keyword)
 */
void DetectLocationRegister(void) {
    sigmatch_table[DETECT_GEOIP].name = "geoip";
    sigmatch_table[DETECT_GEOIP].desc = "match on the source, destination or source and destination IP addresses of network traffic, and to see to which country it belongs";
    sigmatch_table[DETECT_GEOIP].url = "/rules/header-keywords.html#geoip";
    sigmatch_table[DETECT_GEOIP].Setup = DetectLocationSetup;
#ifdef HAVE_LIBLOC
    sigmatch_table[DETECT_GEOIP].Match = DetectLocationMatch;
    sigmatch_table[DETECT_GEOIP].Free = DetectLocationFree;
#endif /* HAVE_LIBLOC */
}
