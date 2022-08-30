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
 * \author Eileen Donlon <emdonlo@gmail.com>
 */

#ifndef __DETECT_ENGINE_ANALYZER_H__
#define __DETECT_ENGINE_ANALYZER_H__

#include <stdint.h>

int SetupFPAnalyzer(void);
void CleanupFPAnalyzer(void);

int SetupRuleAnalyzer(void);
void CleanupRuleAnalyzer (void);

int PerCentEncodingSetup (void);

void EngineAnalysisFP(const DetectEngineCtx *de_ctx,
        const Signature *s, char *line);
void EngineAnalysisRules(const DetectEngineCtx *de_ctx,
        const Signature *s, const char *line);
void EngineAnalysisRulesFailure(char *line, char *file, int lineno);

void EngineAnalysisRules2(const DetectEngineCtx *de_ctx, const Signature *s);

#endif /* __DETECT_ENGINE_ANALYZER_H__ */
