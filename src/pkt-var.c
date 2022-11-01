/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * Implements per packet vars
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 * \todo have more than one instance of the same var, and be able to match on a
 *   specific one, or one all at a time. So if a certain capture matches
 *   multiple times, we can operate on all of them.
 */

#include "suricata-common.h"
#include "decode.h"
#include "pkt-var.h"

/* get the pktvar with name 'name' from the pkt
 *
 * name is a normal string*/
PktVar *PktVarGet(Packet *p, uint32_t id)
{
    PktVar *pv = p->pktvar;

    for (;pv != NULL; pv = pv->next) {
        if (pv->id == id)
            return pv;
    }

    return NULL;
}

/**
 *  \brief add a key-value pktvar to the pkt
 *  \retval r 0 ok, -1 error
 */
int PktVarAddKeyValue(Packet *p, uint8_t *key, uint16_t ksize, uint8_t *value, uint16_t size)
{
    PktVar *pv = SCCalloc(1, sizeof(PktVar));
    if (unlikely(pv == NULL))
        return -1;

    pv->key = key;
    pv->key_len = ksize;
    pv->value = value;
    pv->value_len = size;

    PktVar *tpv = p->pktvar;
    if (p->pktvar == NULL)
        p->pktvar = pv;
    else {
        while(tpv) {
            if (tpv->next == NULL) {
                tpv->next = pv;
                return 0;
            }
            tpv = tpv->next;
        }
    }
    return 0;
}

/**
 *  \brief add a key-value pktvar to the pkt
 *  \retval r 0 ok, -1 error
 */
int PktVarAdd(Packet *p, uint32_t id, uint8_t *value, uint16_t size)
{
    PktVar *pv = SCCalloc(1, sizeof(PktVar));
    if (unlikely(pv == NULL))
        return -1;

    pv->id = id;
    pv->value = value;
    pv->value_len = size;

    PktVar *tpv = p->pktvar;
    if (p->pktvar == NULL)
        p->pktvar = pv;
    else {
        while(tpv) {
            if (tpv->next == NULL) {
                tpv->next = pv;
                return 0;
            }
            tpv = tpv->next;
        }
    }
    return 0;
}

void PktVarFree(PktVar *pv)
{
    if (pv == NULL)
        return;

    if (pv->key != NULL)
        SCFree(pv->key);
    if (pv->value != NULL)
        SCFree(pv->value);
    PktVar *pv_next = pv->next;

    SCFree(pv);

    if (pv_next != NULL)
        PktVarFree(pv_next);
}
