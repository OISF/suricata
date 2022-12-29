/* Copyright (C) 2007-2021 Open Information Security Foundation
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

#ifndef __APP_LAYER_PROTOS_H__
#define __APP_LAYER_PROTOS_H__

#include "rust-app-layer-protos.h"

static inline bool AppProtoIsValid(AppProto a)
{
    return ((a > ALPROTO_UNKNOWN && a < ALPROTO_FAILED));
}

// wether a signature AppProto matches a flow (or signature) AppProto
static inline bool AppProtoEquals(AppProto sigproto, AppProto alproto)
{
    switch (sigproto) {
        case ALPROTO_HTTP:
            return (alproto == ALPROTO_HTTP1) || (alproto == ALPROTO_HTTP2) ||
                   (alproto == ALPROTO_HTTP);
        case ALPROTO_DCERPC:
            return (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB);
    }
    return (sigproto == alproto);
}

/**
 * \brief Maps the ALPROTO_*, to its string equivalent.
 *
 * \param alproto App layer protocol id.
 *
 * \retval String equivalent for the alproto.
 */
const char *AppProtoToString(AppProto alproto);

/**
 * \brief Maps a string to its ALPROTO_* equivalent.
 *
 * \param String equivalent for the alproto.
 *
 * \retval alproto App layer protocol id, or ALPROTO_UNKNOWN.
 */
AppProto StringToAppProto(const char *proto_name);

#endif /* __APP_LAYER_PROTOS_H__ */
