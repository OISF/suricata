/* Copyright (C) 2015 Open Information Security Foundation
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
 * \file Set up of the "template_buffer" keyword to allow content inspections
 *    on the decoded template application layer buffers.
 */

#include "suricata-common.h"
#include "detect.h"
#include "app-layer-template.h"

static int DetectTemplateBufferSetup(DetectEngineCtx *, Signature *, char *);
static void DetectTemplateBufferRegisterTests(void);

void DetectTemplateBufferRegister(void)
{
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].name = "template_buffer";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].desc =
        "Template content modififier to match on the template buffers";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].alproto = ALPROTO_TEMPLATE;
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].Setup = DetectTemplateBufferSetup;
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].RegisterTests =
        DetectTemplateBufferRegisterTests;

    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].flags |= SIGMATCH_PAYLOAD;

    SCLogNotice("Template application layer detect registered.");
}

static int DetectTemplateBufferSetup(DetectEngineCtx *de_ctx, Signature *s,
    char *str)
{
    s->list = DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH;
    s->alproto = ALPROTO_TEMPLATE;
    return 0;
}

static void DetectTemplateBufferRegisterTests(void)
{
#ifdef UNITTESTS
#endif /* UNITTESTS */
}
