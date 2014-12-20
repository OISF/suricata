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

#ifndef __UTIL_VAR_H__
#define __UTIL_VAR_H__

enum VarTypes {
    VAR_TYPE_NOT_SET,

    VAR_TYPE_PKT_BIT,
    VAR_TYPE_PKT_INT,
    VAR_TYPE_PKT_VAR,

    VAR_TYPE_FLOW_BIT,
    VAR_TYPE_FLOW_INT,
    VAR_TYPE_FLOW_VAR,

    VAR_TYPE_HOST_BIT,
    VAR_TYPE_HOST_INT,
    VAR_TYPE_HOST_VAR,

    VAR_TYPE_IPPAIR_BIT,
    VAR_TYPE_IPPAIR_INT,
    VAR_TYPE_IPPAIR_VAR,
};

typedef struct GenericVar_ {
    uint8_t type;
    uint16_t idx;
    struct GenericVar_ *next;
} GenericVar;

typedef struct XBit_ {
    uint8_t type;       /* type, DETECT_XBITS in this case */
    uint16_t idx;       /* name idx */
    GenericVar *next;
    uint32_t expire;
} XBit;

void GenericVarFree(GenericVar *);
void GenericVarAppend(GenericVar **, GenericVar *);
void GenericVarRemove(GenericVar **, GenericVar *);

#endif /* __UTIL_VAR_H__ */

