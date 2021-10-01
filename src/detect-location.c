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

#include <arpa/inet.h>

#include <libloc/libloc.h>
#include <libloc/country.h>
#include <libloc/database.h>
#include <libloc/network.h>

enum location_flags {
    LOCATION_FLAG_SRC     = (1 << 0),
    LOCATION_FLAG_DST     = (1 << 1),
    LOCATION_FLAG_BOTH    = (1 << 2),
    LOCATION_FLAG_NEGATED = (1 << 3),
};

struct DetectLocationData {
    struct loc_ctx* ctx;
    struct loc_database* db;
    char** countries;
    int anycast:1;
    int flags;
};

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
    if (data->db)
        loc_database_unref(data->db);

    // Free libloc context
    if (data->ctx)
        loc_unref(data->ctx);

    SCFree(data);
}

static int DetectLocationOpenDatabase(struct DetectLocationData* data) {
    const char* filename = NULL;
    int r = 0;

    // Fetch location database path from configuration file
    ConfGet("location-database", &filename);

    // Use the default database path if nothing was set
    if (!filename)
        filename = "/var/lib/location/database.db";

    // Open database file
    FILE* f = fopen(filename, "r");
    if (!f) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
            "Could not open location database at %s: %m", filename);
        return 1;
    }

    // Create libloc context
    r = loc_new(&data->ctx);
    if (r)
        return r;

    // Open database
    r = loc_database_new(data->ctx, &data->db, f);
    fclose(f);

    if (r)
        return r;

    SCLogDebug("Opened location database from %s", filename);
    SCLogDebug("  Vendor  : %s", loc_database_get_vendor(data->db));
    SCLogDebug("  License : %s", loc_database_get_license(data->db));

    return r;
}

static const struct keyword {
    const char* keyword;
    int flags;
} keywords[] = {
    { "src,",  LOCATION_FLAG_SRC, },
    { "dst,",  LOCATION_FLAG_DST, },
    { "both,", LOCATION_FLAG_BOTH|LOCATION_FLAG_SRC|LOCATION_FLAG_DST, },
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

static struct DetectLocationData* DetectLocationParseGeoIP(DetectEngineCtx* ctx,
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

    // Open location database
    int r = DetectLocationOpenDatabase(data);
    if (r)
        goto ERROR;

    return data;

ERROR:
    DetectLocationFree(ctx, data);

    return NULL;
}

static const struct direction {
    const char* keyword;
    int flags;
} directions[] = {
    { "src", LOCATION_FLAG_SRC },
    { "dst", LOCATION_FLAG_DST },
    { "both", LOCATION_FLAG_SRC|LOCATION_FLAG_DST },
    { NULL, 0 },
};

static int DetectLocationParseDirection(const char* string) {
    for (const struct direction* direction = directions; direction->keyword; direction++) {
        if (strcmp(direction->keyword, string) == 0)
            return direction->flags;
    }

    SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid direction: %s", string);

    return 0;
}

static struct DetectLocationData* DetectLocationParseAnycast(DetectEngineCtx* ctx,
        const char* string) {
    // Check for valid input
    if (!string || !*string)
        return NULL;

    // Allocate DetectLocationData
    struct DetectLocationData* data = SCCalloc(1, sizeof(*data));
    if (!data)
        return NULL;

    // Match anycast
    data->anycast = 1;

    // Which direction?
    data->flags = DetectLocationParseDirection(string);
    if (!data->flags)
        goto ERROR;

    // Open location database
    int r = DetectLocationOpenDatabase(data);
    if (r)
        goto ERROR;

    return data;

ERROR:
    DetectLocationFree(ctx, data);

    return NULL;
}

static int DetectLocationCreateMatch(Signature* signature, const enum DetectKeywordId type,
        SigMatchCtx* ctx) {
    // Allocate a new SigMatch structure
     SigMatch* match = SigMatchAlloc();
    if (!match)
        return -1;

    // Store type and context
    match->type = type;
    match->ctx = ctx;

    SigMatchAppendSMToList(signature, match, DETECT_SM_LIST_MATCH);

    // We require the packet in order to perform any checks
    signature->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
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
static int DetectLocationSetupGeoIP(DetectEngineCtx* ctx, Signature* signature,
        const char* optstring) {
    int r;

    // Parse the option string
    struct DetectLocationData* data = DetectLocationParseGeoIP(ctx, optstring);
    if (!data)
        return -1;

    // Create a match
    r = DetectLocationCreateMatch(signature, DETECT_GEOIP, (SigMatchCtx*)data);
    if (r) {
        DetectLocationFree(ctx, data);
        return r;
    }

    return 0;
}

static int DetectLocationSetupAnycast(DetectEngineCtx* ctx, Signature* signature,
        const char* optstring) {
    int r;

    // Parse the option string
    struct DetectLocationData* data = DetectLocationParseAnycast(ctx, optstring);
    if (!data)
        return -1;

    // Create a match
    r = DetectLocationCreateMatch(signature, DETECT_ANYCAST, (SigMatchCtx*)data);
    if (r) {
        DetectLocationFree(ctx, data);
        return r;
    }

    return 0;
}

static int DetectLocationMatchCountryCode(const struct DetectLocationData* data, struct loc_network* network) {
    int found = 0;

    for (char** country = data->countries; *country; country++) {
        if (loc_network_matches_country_code(network, *country)) {
            found = 1;
            break;
        }
    }

    if (data->flags & LOCATION_FLAG_NEGATED)
        return !found;

    return found;
}

static int DetectLocationMatchAddress(const struct DetectLocationData* data, const struct in6_addr* address) {
    struct loc_network* network = NULL;

    int r = loc_database_lookup(data->db, address, &network);
    if (r)
        return -1;

    // If we found a network, let's check whether the country matches
    if (network) {
        if (data->countries) {
            if (DetectLocationMatchCountryCode(data, network))
                r = 1;

        } else if (data->anycast)
            r = loc_network_has_flag(network, LOC_NETWORK_FLAG_ANYCAST);

        loc_network_unref(network);
    }

    return r;
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

    struct in6_addr src_addr;
    struct in6_addr dst_addr;

    // Skip any pseudo packets
    if (PKT_IS_PSEUDOPKT(packet)) {
        return 0;

    // Handle IPv6
    } else if (PKT_IS_IPV6(packet)) {
        if (data->flags & LOCATION_FLAG_SRC)
            src_addr = GET_IPV6_SRC_IN6ADDR(packet);

        if (data->flags & LOCATION_FLAG_DST)
            dst_addr = GET_IPV6_DST_IN6ADDR(packet);

    // Handle IPv4
    } else if (PKT_IS_IPV4(packet)) {
        // Convert to IPv6-mapped address
        if (data->flags & LOCATION_FLAG_SRC) {
            src_addr.s6_addr32[0] = htonl(0x0000);
            src_addr.s6_addr32[1] = htonl(0x0000);
            src_addr.s6_addr32[2] = htonl(0xffff);
            src_addr.s6_addr32[3] = GET_IPV4_SRC_ADDR_U32(packet);
        }

        if (data->flags & LOCATION_FLAG_DST) {
            dst_addr.s6_addr32[0] = htonl(0x0000);
            dst_addr.s6_addr32[1] = htonl(0x0000);
            dst_addr.s6_addr32[2] = htonl(0xffff);
            dst_addr.s6_addr32[3] = GET_IPV4_DST_ADDR_U32(packet);
        }
    }

    int matches = 0;
    int r;

    // Check source address
    if (data->flags & LOCATION_FLAG_SRC) {
        r = DetectLocationMatchAddress(data, &src_addr);
        switch (r) {
            // No match
            case 0:
                break;

            // Match
            case 1:
                matches++;
                break;

            // Error
            default:
                return r;
        }
    }

    // Check destination address
    if (data->flags & LOCATION_FLAG_DST) {
        r = DetectLocationMatchAddress(data, &dst_addr);
        switch (r) {
            // No match
            case 0:
                break;

            // Match
            case 1:
                matches++;
                break;

            // Error
            default:
                return r;
        }
    }

    // If BOTH is set, matches must at least be two
    if (data->flags & LOCATION_FLAG_BOTH) {
        if (matches < 2)
            matches = 0;
    }

    return (matches > 0);
}

#else /* HAVE_LIBLOC */

static int DetectLocationSetupGeoIP(DetectEngineCtx* ctx, Signature* signature, const char* optstring) {
    SCLogError(SC_ERR_NO_LOCATION_SUPPORT,
        "Support for IPFire Location is not built in (needed for geoip keyword)");
    return -1;
}

static int DetectLocationSetupAnycast(DetectEngineCtx* ctx, Signature* signature, const char* optstring) {
    SCLogError(SC_ERR_NO_LOCATION_SUPPORT,
        "Support for IPFire Location is not built in (needed for anycast keyword)");
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
    sigmatch_table[DETECT_GEOIP].Setup = DetectLocationSetupGeoIP;
#ifdef HAVE_LIBLOC
    sigmatch_table[DETECT_GEOIP].Match = DetectLocationMatch;
    sigmatch_table[DETECT_GEOIP].Free = DetectLocationFree;
#endif /* HAVE_LIBLOC */

    sigmatch_table[DETECT_ANYCAST].name = "anycast";
    sigmatch_table[DETECT_ANYCAST].desc = "match on the source, destination or source and destination IP addresses and check if they belong to an anycast network";
    sigmatch_table[DETECT_ANYCAST].url = "/rules/header-keywords.html#anycast";
    sigmatch_table[DETECT_ANYCAST].Setup = DetectLocationSetupAnycast;
#ifdef HAVE_LIBLOC
    sigmatch_table[DETECT_ANYCAST].Match = DetectLocationMatch;
    sigmatch_table[DETECT_ANYCAST].Free = DetectLocationFree;
#endif /* HAVE_LIBLOC */
}
