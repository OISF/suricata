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
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_IPREP_H__
#define __DETECT_IPREP_H__

#define DETECT_IPREP_CMD_ANY      0
#define DETECT_IPREP_CMD_BOTH     1
#define DETECT_IPREP_CMD_SRC      2
#define DETECT_IPREP_CMD_DST      3

#define DETECT_IPREP_OP_LT        0
#define DETECT_IPREP_OP_GT        1
#define DETECT_IPREP_OP_EQ        2

typedef struct DetectIPRepData_ {
    uint8_t cmd;
    int8_t cat;
    int8_t op;
    uint8_t val;
} DetectIPRepData;

/* prototypes */
void DetectIPRepRegister (void);

#endif /* __DETECT_IPREP_H__ */
