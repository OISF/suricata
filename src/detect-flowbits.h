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
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FLOWBITS_H__
#define __DETECT_FLOWBITS_H__

#define DETECT_FLOWBITS_CMD_SET      0
#define DETECT_FLOWBITS_CMD_TOGGLE   1
#define DETECT_FLOWBITS_CMD_UNSET    2
#define DETECT_FLOWBITS_CMD_ISNOTSET 3
#define DETECT_FLOWBITS_CMD_ISSET    4
#define DETECT_FLOWBITS_CMD_NOALERT  5
#define DETECT_FLOWBITS_CMD_MAX      6

typedef struct DetectFlowbitsData_ {
    uint32_t idx;
    uint8_t cmd;
} DetectFlowbitsData;

/* prototypes */
void DetectFlowbitsRegister (void);

#endif /* __DETECT_FLOWBITS_H__ */

