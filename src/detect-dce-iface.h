/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_DCE_IFACE_H__
#define __DETECT_DCE_IFACE_H__

typedef enum DetectDceIfaceOperators_ {
    DETECT_DCE_IFACE_OP_NONE = 0,
    DETECT_DCE_IFACE_OP_LT,
    DETECT_DCE_IFACE_OP_GT,
    DETECT_DCE_IFACE_OP_EQ,
    DETECT_DCE_IFACE_OP_NE,
} DetectDceIfaceOperators;

typedef struct DetectDceIfaceData_ {
    uint8_t uuid[16];
    uint8_t op;
    uint16_t version;
    uint8_t any_frag;
} DetectDceIfaceData;

void DetectDceIfaceRegister(void);
void DetectDceIfaceRegisterTests(void);

#endif /* __DETECT_DCE_IFACE_H__ */
