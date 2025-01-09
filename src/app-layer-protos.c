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
#include "rust.h"

AppProto AlprotoMax = ALPROTO_MAX_STATIC + 1;
#define ARRAY_CAP_STEP 16
AppProto AppProtoStringsCap = ALPROTO_MAX_STATIC + 1;

typedef struct AppProtoStringTuple {
    AppProto alproto;
    const char *str;
} AppProtoStringTuple;

AppProtoStringTuple *AppProtoStrings = NULL;

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
            if (alproto < AlprotoMax) {
                BUG_ON(AppProtoStrings[alproto].alproto != alproto);
                proto_name = AppProtoStrings[alproto].str;
            }
    }
    return proto_name;
}

AppProto StringToAppProto(const char *proto_name)
{
    if (proto_name == NULL)
        return ALPROTO_UNKNOWN;

    // We could use a Multi Pattern Matcher
    for (size_t i = 0; i < AlprotoMax; i++) {
        if (strcmp(proto_name, AppProtoStrings[i].str) == 0)
            return AppProtoStrings[i].alproto;
    }

    return ALPROTO_UNKNOWN;
}

void AppProtoRegisterProtoString(AppProto alproto, const char *proto_name)
{
    if (alproto < ALPROTO_MAX_STATIC) {
        if (AppProtoStrings == NULL) {
            AppProtoStrings = SCCalloc(AppProtoStringsCap, sizeof(AppProtoStringTuple));
            if (AppProtoStrings == NULL) {
                FatalError("Unable to allocate AppProtoStrings");
            }
        }
    } else if (alproto + 1 == AlprotoMax) {
        if (AlprotoMax == AppProtoStringsCap) {
            void *tmp = SCRealloc(AppProtoStrings,
                    sizeof(AppProtoStringTuple) * (AppProtoStringsCap + ARRAY_CAP_STEP));
            if (tmp == NULL) {
                FatalError("Unable to reallocate AppProtoStrings");
            }
            AppProtoStringsCap += ARRAY_CAP_STEP;
            AppProtoStrings = tmp;
        }
        AlprotoMax++;
    }
    AppProtoStrings[alproto].str = proto_name;
    AppProtoStrings[alproto].alproto = alproto;
}
