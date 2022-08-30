/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __TMQH_FLOW_H__
#define __TMQH_FLOW_H__

typedef struct TmqhFlowMode_ {
    PacketQueue *q;
} TmqhFlowMode;

/** \brief Ctx for the flow queue handler
 *  \param size number of queues to output to
 *  \param queues array of queue id's this flow handler outputs to */
typedef struct TmqhFlowCtx_ {
    uint16_t size;
    uint16_t last;

    TmqhFlowMode *queues;
} TmqhFlowCtx;

void TmqhFlowRegister (void);
void TmqhFlowRegisterTests(void);

void TmqhFlowPrintAutofpHandler(void);

#endif /* __TMQH_FLOW_H__ */
