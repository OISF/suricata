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

#include "detect-location.h"

#ifdef HAVE_LIBLOC

#include <libloc/libloc.h>

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

	return -1;
}

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

	// Free database
	if (data->ctx)
		loc_unref(data->ctx);

	SCFree(data);
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
