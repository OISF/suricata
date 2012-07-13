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
 * \author Eric Leblond <eric@regit.org>
 *
 *
 * Implements the l3_proto keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-ipproto.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "util-debug.h"

static int DetectL3ProtoSetup(DetectEngineCtx *, Signature *, char *);

void DetectL3ProtoRegister(void)
{
    sigmatch_table[DETECT_L3PROTO].name = "l3_proto";
    sigmatch_table[DETECT_L3PROTO].Match = NULL;
    sigmatch_table[DETECT_L3PROTO].Setup = DetectL3ProtoSetup;
    sigmatch_table[DETECT_L3PROTO].Free  = NULL;
    sigmatch_table[DETECT_L3PROTO].RegisterTests = NULL;

    return;
}
/**
 * \internal
 * \brief Setup l3_proto keyword.
 *
 * \param de_ctx Detection engine context
 * \param s Signature
 * \param optstr Options string
 *
 * \return Non-zero on error
 */
static int DetectL3ProtoSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    char *str = optstr;
    char dubbed = 0;

    /* strip "'s */
    if (optstr[0] == '\"' && optstr[strlen(optstr) - 1] == '\"') {
        str = SCStrdup(optstr + 1);
        if (str == NULL)
            goto error;
        str[strlen(optstr) - 2] = '\0';
        dubbed = 1;
    }

    /* reset possible any value */
    if (s->proto.flags & DETECT_PROTO_ANY) {
        s->proto.flags &= ~DETECT_PROTO_ANY;
    }

    /* authorized value, ip, any, ip4, ipv4, ip6, ipv6 */
    if (strcasecmp(str,"ipv4") == 0 ||
            strcasecmp(str,"ip4") == 0 ) {
        if (s->proto.flags & DETECT_PROTO_IPV6) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Conflicting l3 proto specified");
            goto error;
        }
        s->proto.flags |= DETECT_PROTO_IPV4;
        SCLogDebug("IPv4 protocol detected");
    } else if (strcasecmp(str,"ipv6") == 0 ||
            strcasecmp(str,"ip6") == 0 ) {
        if (s->proto.flags & DETECT_PROTO_IPV6) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Conflicting l3 proto specified");
            goto error;
        }
        s->proto.flags |= DETECT_PROTO_IPV6;
        SCLogDebug("IPv6 protocol detected");
    } else {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid l3 proto: \"%s\"", str);
        goto error;
    }

    if (dubbed)
        SCFree(str);
    return 0;
error:
    if (dubbed)
        SCFree(str);
    return -1;
}
