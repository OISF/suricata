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
 * \author Paulo Pacheco <fooinha@gmail.com>
 */

#ifndef __DETECT_YARA_RULE_H__
#define __DETECT_YARA_RULE_H__

#include "queue.h"

#ifdef HAVE_LIBYARA
#include <yara.h>

typedef struct DetectYaraRuleThreadData {
} DetectYaraRuleThreadData;

typedef struct YaraRuleEntry_ {
    TAILQ_ENTRY(YaraRuleEntry_) next;
    char *name;
} YaraRuleEntry;

typedef struct YaraRuleTagEntry_ {
    TAILQ_ENTRY(YaraRuleTagEntry_) next;
    char *name;
} YaraRuleTagEntry;

typedef struct DetectYaraRulesData_ {
    int thread_ctx_id;
    char *filename;
    char *rules_to_match;
    char *tags_to_match;
    YR_RULES  *rules;
    uint32_t flags;
    TAILQ_HEAD(, YaraRuleEntry_) rules_list;        /**< list for rules */
    TAILQ_HEAD(, YaraRuleTagEntry_) tags_list;      /**< list for tags */
} DetectYaraRulesData;

typedef struct DetectYaraRulesDataMatchInfo_ {
 DetectYaraRulesData *data;
 int matched;  /* used to stop match check */
} DetectYaraRulesDataMatchInfo;

#endif /* HAVE_LIBYARA */

/* prototypes */
void DetectYaraRulesRegister(void);
int YaraLoadRules(DetectEngineCtx *);
void YaraRulesClean();

#endif /* __DETECT_YARA_RULE_H__ */
