/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "rust.h"

AppProto g_alproto_max = ALPROTO_MAX_STATIC;
#define ARRAY_CAP_STEP 16
AppProto g_alproto_strings_cap = ALPROTO_MAX_STATIC;

typedef struct AppProtoStringTuple {
    AppProto alproto;
    const char *str;
} AppProtoStringTuple;

AppProtoStringTuple *g_alproto_strings = NULL;

const char *AppProtoToString(AppProto alproto)
{
    const char *proto_name = NULL;
    switch (alproto) {
        // special cases
        case ALPROTO_HTTP1:
            proto_name = "http";
            break;
        case ALPROTO_HTTP:
            proto_name = "http_any";
            break;
        default:
            if (alproto < g_alproto_max) {
                DEBUG_VALIDATE_BUG_ON(g_alproto_strings[alproto].alproto != alproto);
                proto_name = g_alproto_strings[alproto].str;
            }
    }
    return proto_name;
}

AppProto StringToAppProto(const char *proto_name)
{
    if (proto_name == NULL)
        return ALPROTO_UNKNOWN;

    // We could use a Multi Pattern Matcher
    for (size_t i = 0; i < g_alproto_max; i++) {
        if (strcmp(proto_name, g_alproto_strings[i].str) == 0)
            return g_alproto_strings[i].alproto;
    }

    return ALPROTO_UNKNOWN;
}

AppProto AppProtoNewProtoFromString(const char *proto_name)
{
    AppProtoRegisterProtoString(g_alproto_max, proto_name);
    return g_alproto_max - 1;
}

void AppProtoRegisterProtoString(AppProto alproto, const char *proto_name)
{
    if (alproto < ALPROTO_MAX_STATIC) {
        if (g_alproto_strings == NULL) {
            g_alproto_strings = SCCalloc(g_alproto_strings_cap, sizeof(AppProtoStringTuple));
            if (g_alproto_strings == NULL) {
                FatalError("Unable to allocate g_alproto_strings");
            }
        }
    } else if (alproto == g_alproto_max) {
        if (g_alproto_max == g_alproto_strings_cap) {
            void *tmp = SCRealloc(g_alproto_strings,
                    sizeof(AppProtoStringTuple) * (g_alproto_strings_cap + ARRAY_CAP_STEP));
            if (tmp == NULL) {
                FatalError("Unable to reallocate g_alproto_strings");
            }
            g_alproto_strings_cap += ARRAY_CAP_STEP;
            g_alproto_strings = tmp;
        }
        g_alproto_max++;
        SCAppLayerParserReallocCtx(alproto);
    }
    g_alproto_strings[alproto].str = proto_name;
    g_alproto_strings[alproto].alproto = alproto;
}
