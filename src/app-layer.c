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
 *
 * Generic App-layer functions
 */

#include "suricata-common.h"
#include "app-layer.h"
#include "stream-tcp-private.h"
#include "util-debug.h"

/** \brief Get the active app layer proto from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval proto (ALPROTO_UNKNOWN if no proto yet) */
uint16_t AppLayerGetProtoFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    SCReturnUInt(ssn->alproto);
}

/** \brief Get the active app layer state from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnPtr(NULL, "void");
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL || ssn->aldata == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];

    SCLogDebug("p->flow %p", p->flow);
    SCReturnPtr(alstate, "void");
}

/** \brief Get the active app layer state from the flow
 *  \param f flow pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    SCEnter();

    if (f == NULL)
        SCReturnPtr(NULL, "void");

    TcpSession *ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL || ssn->aldata == NULL)
        SCReturnPtr(NULL, "void");

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];
    SCReturnPtr(alstate, "void");
}

