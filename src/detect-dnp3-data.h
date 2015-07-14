/* Copyright (C) 2015 Open Information Security Foundation
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

#ifndef __DETECT_DNP3_DATA_H__
#define __DETECT_DNP3_DATA_H__

#include "app-layer-dnp3.h"

void DetectDNP3DataRegister(void);

uint32_t DetectDNP3DataInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
    DNP3State *dnp3_state, uint8_t flags, void *txv, uint64_t tx_id);

#endif /* !__DETECT_DNP3_DATA_H__ */
