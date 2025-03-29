/* Copyright (C) 2025 Open Information Security Foundation
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
 * This file contains definitions that should be made available
 * to rust via bindgen.
 *
 */

#ifndef SURICATA_OUTPUT_PUBLIC_H
#define SURICATA_OUTPUT_PUBLIC_H

#include "app-layer-protos.h"

typedef enum SCOutputJsonLogDirection {
    LOG_DIR_PACKET = 0,
    LOG_DIR_FLOW,
    LOG_DIR_FLOW_TOCLIENT,
    LOG_DIR_FLOW_TOSERVER,
} SCOutputJsonLogDirection;

typedef bool (*EveJsonSimpleTxLogFunc)(const void *, void *);

typedef struct EveJsonSimpleAppLayerLogger {
    EveJsonSimpleTxLogFunc LogTx;
    const char *name;
} EveJsonSimpleAppLayerLogger;

EveJsonSimpleAppLayerLogger *SCEveJsonSimpleGetLogger(AppProto alproto);

typedef struct EveJsonTxLoggerRegistrationData {
    const char *confname;
    const char *logname;
    AppProto alproto;
    uint8_t dir;
    EveJsonSimpleTxLogFunc LogTx;
} EveJsonTxLoggerRegistrationData;

int SCOutputEvePreRegisterLogger(EveJsonTxLoggerRegistrationData reg_data);

#endif /* ! SURICATA_OUTPUT_PUBLIC_H */
