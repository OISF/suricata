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
#else
#define DEFAULT_LOG_DIR "/var/log/suricata"
#endif /* OS_WIN32 */

void ConfInit(void);
void ConfDeInit(void);
ConfNode *ConfGetRootNode(void);
int ConfGet(char *name, char **vptr);
int ConfGetInt(char *name, intmax_t *val);
int ConfGetBool(char *name, int *val);
int ConfGetDouble(char *name, double *val);
int ConfGetFloat(char *name, float *val);
int ConfSet(char *name, char *val);
int ConfSetFinal(char *name, char *val);
void ConfDump(void);
void ConfNodeDump(ConfNode *node, const char *prefix);
ConfNode *ConfNodeNew(void);
void ConfNodeFree(ConfNode *);
ConfNode *ConfGetNode(char *key);
void ConfCreateContextBackup(void);
void ConfRestoreContextBackup(void);
ConfNode *ConfNodeLookupChild(ConfNode *node, const char *key);
const char *ConfNodeLookupChildValue(ConfNode *node, const char *key);
void ConfNodeRemove(ConfNode *);
void ConfRegisterTests();
int ConfNodeChildValueIsTrue(ConfNode *node, const char *key);
int ConfValIsTrue(const char *val);
int ConfValIsFalse(const char *val);
void ConfNodePrune(ConfNode *node);

ConfNode *ConfNodeLookupKeyValue(ConfNode *base, const char *key, const char *value);
int ConfGetChildValue(ConfNode *base, char *name, char **vptr);
int ConfGetChildValueInt(ConfNode *base, char *name, intmax_t *val);
int ConfGetChildValueBool(ConfNode *base, char *name, int *val);
int ConfGetChildValueWithDefault(ConfNode *base, ConfNode *dflt, char *name, char **vptr);
int ConfGetChildValueIntWithDefault(ConfNode *base, ConfNode *dflt, char *name, intmax_t *val);
int ConfGetChildValueBoolWithDefault(ConfNode *base, ConfNode *dflt, char *name, int *val);
char *ConfLoadCompleteIncludePath(char *);

#endif /* ! __CONF_H__ */
