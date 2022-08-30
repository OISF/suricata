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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 */

#ifndef __CONF_H__
#define __CONF_H__

#include "queue.h"

/**
 * Structure of a configuration parameter.
 */
typedef struct ConfNode_ {
    char *name;
    char *val;

    int is_seq;

    /**< Flag that sets this nodes value as final. */
    int final;

    struct ConfNode_ *parent;
    TAILQ_HEAD(, ConfNode_) head;
    TAILQ_ENTRY(ConfNode_) next;
} ConfNode;


/**
 * The default log directory.
 */
#ifdef OS_WIN32
#define DEFAULT_LOG_DIR "C:\\WINDOWS\\Temp"
#define DEFAULT_DATA_DIR "C:\\WINDOWS\\Temp"
#else
#define DEFAULT_LOG_DIR "/var/log/suricata"
#define DEFAULT_DATA_DIR DATA_DIR
#endif /* OS_WIN32 */

void ConfInit(void);
void ConfDeInit(void);
ConfNode *ConfGetRootNode(void);
int ConfGet(const char *name, const char **vptr);
int ConfGetInt(const char *name, intmax_t *val);
int ConfGetBool(const char *name, int *val);
int ConfGetDouble(const char *name, double *val);
int ConfGetFloat(const char *name, float *val);
int ConfSet(const char *name, const char *val);
int ConfSetFromString(const char *input, int final);
int ConfSetFinal(const char *name, const char *val);
void ConfDump(void);
void ConfNodeDump(const ConfNode *node, const char *prefix);
ConfNode *ConfNodeNew(void);
void ConfNodeFree(ConfNode *);
ConfNode *ConfGetNode(const char *key);
void ConfCreateContextBackup(void);
void ConfRestoreContextBackup(void);
ConfNode *ConfNodeLookupChild(const ConfNode *node, const char *key);
const char *ConfNodeLookupChildValue(const ConfNode *node, const char *key);
void ConfNodeRemove(ConfNode *);
void ConfRegisterTests(void);
int ConfNodeChildValueIsTrue(const ConfNode *node, const char *key);
int ConfValIsTrue(const char *val);
int ConfValIsFalse(const char *val);
void ConfNodePrune(ConfNode *node);
int ConfRemove(const char *name);
bool ConfNodeHasChildren(const ConfNode *node);

ConfNode *ConfGetChildWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name);
ConfNode *ConfNodeLookupKeyValue(const ConfNode *base, const char *key, const char *value);
int ConfGetChildValue(const ConfNode *base, const char *name, const char **vptr);
int ConfGetChildValueInt(const ConfNode *base, const char *name, intmax_t *val);
int ConfGetChildValueBool(const ConfNode *base, const char *name, int *val);
int ConfGetChildValueWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, const char **vptr);
int ConfGetChildValueIntWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, intmax_t *val);
int ConfGetChildValueBoolWithDefault(const ConfNode *base, const ConfNode *dflt, const char *name, int *val);
char *ConfLoadCompleteIncludePath(const char *);
int ConfNodeIsSequence(const ConfNode *node);
ConfNode *ConfSetIfaceNode(const char *ifaces_node_name, const char *iface);
int ConfSetRootAndDefaultNodes(
        const char *ifaces_node_name, const char *iface, ConfNode **if_root, ConfNode **if_default);

#endif /* ! __CONF_H__ */
