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

#ifndef __FLOW_ALERT_SID_H__
#define __FLOW_ALERT_SID_H__

#include "flow.h"
#include "util-var.h"

typedef struct FlowAlertSid_ {
    uint8_t type; /* type, DETECT_FLOWALERTSID in this case */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
    uint32_t sid; /* sid */
} FlowAlertSid;

void FlowAlertSidFree(FlowAlertSid *);
void FlowAlertSidRegisterTests(void);

void FlowAlertSidSet(Flow *, uint32_t);
void FlowAlertSidUnset(Flow *, uint32_t);
void FlowAlertSidToggle(Flow *, uint32_t);
int FlowAlertSidIsset(Flow *, uint32_t);
int FlowAlertSidIsnotset(Flow *, uint32_t);

#endif /* __FLOW_ALERT_SID_H__ */

