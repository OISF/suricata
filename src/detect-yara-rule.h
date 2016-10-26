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


#ifdef HAVE_LIBYARA
#include <yara.h>

typedef struct DetectYaraRuleThreadData {
} DetectYaraRuleThreadData;

typedef struct DetectYaraRulesData_ {
    int thread_ctx_id;
    uint8_t *rule;  /* The yara rule to match ... not working yet*/
    uint32_t flags;
} DetectYaraRulesData;

#endif /* HAVE_LIBYARA */

/* prototypes */
void DetectYaraRulesRegister(void);
int YaraLoadRules(DetectEngineCtx *);
void YaraRulesClean();

#endif /* __DETECT_YARA_RULE_H__ */
