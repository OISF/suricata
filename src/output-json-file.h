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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef SURICATA_OUTPUT_JSON_FILE_H
#define SURICATA_OUTPUT_JSON_FILE_H

#include "app-layer-htp-xff.h"

typedef struct OutputJsonCtx_ OutputJsonCtx;

void JsonFileLogRegister(void);
SCJsonBuilder *JsonBuildFileInfoRecord(const Packet *p, const File *ff, void *tx,
        const uint64_t tx_id, const bool stored, uint8_t dir, HttpXFFCfg *xff_cfg,
        OutputJsonCtx *eve_ctx);

#endif /* SURICATA_OUTPUT_JSON_FILE_H */
