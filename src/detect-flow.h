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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_FLOW_H__
#define __DETECT_FLOW_H__

#define DETECT_FLOW_FLAG_TOSERVER        BIT_U16(0)
#define DETECT_FLOW_FLAG_TOCLIENT        BIT_U16(1)
#define DETECT_FLOW_FLAG_ESTABLISHED     BIT_U16(2)
#define DETECT_FLOW_FLAG_NOT_ESTABLISHED BIT_U16(3)
#define DETECT_FLOW_FLAG_STATELESS       BIT_U16(4)
#define DETECT_FLOW_FLAG_ONLYSTREAM      BIT_U16(5)
#define DETECT_FLOW_FLAG_NOSTREAM        BIT_U16(6)
#define DETECT_FLOW_FLAG_NO_FRAG         BIT_U16(7)
#define DETECT_FLOW_FLAG_ONLY_FRAG       BIT_U16(8)

typedef struct DetectFlowData_ {
    uint16_t flags;     /* flags to match */
    uint8_t match_cnt;  /* number of matches we need */
} DetectFlowData;

/* prototypes */
void DetectFlowRegister (void);

#endif /* __DETECT_FLOW_H__ */

