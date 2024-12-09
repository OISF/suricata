/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_VAR_H
#define SURICATA_UTIL_VAR_H

/** variable types: these are used to track variable names */
enum VarTypes {
    VAR_TYPE_NOT_SET,

    VAR_TYPE_PKT_BIT,
    VAR_TYPE_PKT_INT,
    VAR_TYPE_PKT_VAR,
    VAR_TYPE_PKT_VAR_KV, // key-value

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
    uint16_t type; /**< variable type, uses detection sm_type */
    uint8_t pad[2];
    uint32_t idx;
    struct GenericVar_ *next;
} GenericVar;

typedef struct XBit_ {
    uint16_t type; /* type, DETECT_XBITS in this case */
    uint8_t pad[2];
    uint32_t idx;       /* name idx */
    GenericVar *next;
    uint32_t expire;
} XBit;

void XBitFree(XBit *);

// A list of variables we try to resolve while parsing configuration file.
// Helps to detect recursive declarations.
typedef struct ResolvedVariable_ {
    char var_name[256];
    TAILQ_ENTRY(ResolvedVariable_) next;
} ResolvedVariable;

typedef TAILQ_HEAD(, ResolvedVariable_) ResolvedVariablesList;

void GenericVarFree(GenericVar *);
void GenericVarAppend(GenericVar **, GenericVar *);
void GenericVarRemove(GenericVar **, GenericVar *);

int AddVariableToResolveList(ResolvedVariablesList *list, const char *var);
void CleanVariableResolveList(ResolvedVariablesList *var_list);

#endif /* SURICATA_UTIL_VAR_H */
