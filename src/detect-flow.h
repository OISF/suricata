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

#define DETECT_FLOW_FLAG_TOSERVER       0x01
#define DETECT_FLOW_FLAG_TOCLIENT       0x02
#define DETECT_FLOW_FLAG_ESTABLISHED    0x04
#define DETECT_FLOW_FLAG_STATELESS      0x08
#define DETECT_FLOW_FLAG_ONLYSTREAM     0x10
#define DETECT_FLOW_FLAG_NOSTREAM       0x20

typedef struct DetectFlowData_ {
    uint8_t flags;     /* flags to match */
    uint8_t match_cnt; /* number of matches we need */
} DetectFlowData;

/* prototypes */
void DetectFlowRegister (void);

#endif /* __DETECT_FLOW_H__ */

