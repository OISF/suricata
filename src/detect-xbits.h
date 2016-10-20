/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __DETECT_XBITS_H__
#define __DETECT_XBITS_H__

#define DETECT_XBITS_CMD_SET      0
#define DETECT_XBITS_CMD_TOGGLE   1
#define DETECT_XBITS_CMD_UNSET    2
#define DETECT_XBITS_CMD_ISNOTSET 3
#define DETECT_XBITS_CMD_ISSET    4
#define DETECT_XBITS_CMD_NOALERT  5
#define DETECT_XBITS_CMD_MAX      6

#define DETECT_XBITS_TRACK_IPSRC  0
#define DETECT_XBITS_TRACK_IPDST  1
#define DETECT_XBITS_TRACK_IPPAIR 2
#define DETECT_XBITS_TRACK_FLOW   3

#define DETECT_XBITS_EXPIRE_DEFAULT 30

typedef struct DetectXbitsData_ {
    uint32_t idx;
    uint8_t cmd;
    uint8_t tracker;
    uint32_t expire;
    /** data type: host/ippair/flow used for sig sorting in sigorder */
    enum VarTypes type;
} DetectXbitsData;

/* prototypes */
void DetectXbitsRegister (void);

#endif /* __DETECT_XBITS_H__ */
