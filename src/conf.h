/* Copyright (C) 2007-2023 Open Information Security Foundation
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

#ifndef SURICATA_CONF_H
#define SURICATA_CONF_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "queue.h"

/**
 * Structure of a configuration parameter.
 */
typedef struct SCConfNode_ {
    char *name;
    char *val;

    int is_seq;

    /**< Flag that sets this nodes value as final. */
    int final;

    struct SCConfNode_ *parent;
    TAILQ_HEAD(, SCConfNode_) head;
    TAILQ_ENTRY(SCConfNode_) next;
} SCConfNode;

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

void SCConfInit(void);
void SCConfDeInit(void);
SCConfNode *SCConfGetRootNode(void);
int SCConfGet(const char *name, const char **vptr);
int SCConfGetInt(const char *name, intmax_t *val);
int SCConfGetBool(const char *name, int *val);
int SCConfGetDouble(const char *name, double *val);
int SCConfGetFloat(const char *name, float *val);
int SCConfSet(const char *name, const char *val);
int SCConfSetFromString(const char *input, int final);
int SCConfSetFinal(const char *name, const char *val);
void SCConfDump(void);
void SCConfNodeDump(const SCConfNode *node, const char *prefix);
SCConfNode *SCConfNodeNew(void);
void SCConfNodeFree(SCConfNode *);
SCConfNode *SCConfGetNode(const char *key);
void SCConfCreateContextBackup(void);
void SCConfRestoreContextBackup(void);
SCConfNode *SCConfNodeLookupChild(const SCConfNode *node, const char *key);
const char *SCConfNodeLookupChildValue(const SCConfNode *node, const char *key);
void SCConfNodeRemove(SCConfNode *);
void SCConfRegisterTests(void);
int SCConfNodeChildValueIsTrue(const SCConfNode *node, const char *key);
int SCConfValIsTrue(const char *val);
int SCConfValIsFalse(const char *val);
void SCConfNodePrune(SCConfNode *node);
int SCConfRemove(const char *name);
bool SCConfNodeHasChildren(const SCConfNode *node);

SCConfNode *SCConfGetChildWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name);
SCConfNode *SCConfNodeLookupKeyValue(const SCConfNode *base, const char *key, const char *value);
int SCConfGetChildValue(const SCConfNode *base, const char *name, const char **vptr);
int SCConfGetChildValueInt(const SCConfNode *base, const char *name, intmax_t *val);
int SCConfGetChildValueBool(const SCConfNode *base, const char *name, int *val);
int SCConfGetChildValueWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, const char **vptr);
int SCConfGetChildValueIntWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, intmax_t *val);
int SCConfGetChildValueBoolWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, int *val);
int SCConfNodeIsSequence(const SCConfNode *node);
SCConfNode *SCConfSetIfaceNode(const char *ifaces_node_name, const char *iface);
int SCConfSetRootAndDefaultNodes(const char *ifaces_node_name, const char *iface,
        SCConfNode **if_root, SCConfNode **if_default);
SCConfNode *SCConfNodeGetNodeOrCreate(SCConfNode *parent, const char *name, int final);

SCConfNode *SCConfGetFirstNode(const SCConfNode *parent);
SCConfNode *SCConfGetNextNode(const SCConfNode *node);
const char *SCConfGetValueNode(const SCConfNode *node);

#ifdef __cplusplus
}
#endif

#endif /* ! SURICATA_CONF_H */
