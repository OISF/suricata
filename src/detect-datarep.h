/* Copyright (C) 2022 Open Information Security Foundation
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
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_DATAREP_H__
#define __DETECT_DATAREP_H__

#include "datasets.h"
#include "datasets-reputation.h"

enum DetectDatarepOp {
    DATAREP_OP_GT,  /* rep is greater than requested */
    DATAREP_OP_LT,  /* rep is smaller than requested */
    DATAREP_OP_EQ,  /* rep is smaller than requested */
};

typedef struct DetectDatarepData_ {
    Dataset *set;
    uint8_t cmd;
    enum DetectDatarepOp op;
    DataRepType rep;
} DetectDatarepData;

int DetectDatarepBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectDatarepData *sd,
    const uint8_t *data, const uint32_t data_len);

/* prototypes */
void DetectDatarepRegister (void);

#endif /* __DETECT_DATAREP_H__ */
