/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __DETECT_FLOWVAR_H__
#define __DETECT_FLOWVAR_H__

typedef struct DetectFlowvarData_ {
    char *name;
    uint32_t idx;
    uint8_t *content;
    uint16_t content_len;
    uint32_t flags;
} DetectFlowvarData;

/* prototypes */
void DetectFlowvarRegister (void);

int DetectFlowvarPostMatchSetup(DetectEngineCtx *de_ctx, Signature *s, uint32_t idx);
int DetectVarStoreMatch(DetectEngineThreadCtx *,
        uint32_t, uint8_t *, uint16_t, int);
int DetectVarStoreMatchKeyValue(DetectEngineThreadCtx *,
        uint8_t *, uint16_t, uint8_t *, uint16_t, int);

/* For use only by DetectFlowvarProcessList() */
void DetectVarProcessListInternal(DetectVarList *fs, Flow *f, Packet *p);
static inline void DetectVarProcessList(DetectEngineThreadCtx *det_ctx, Flow *f, Packet *p)
{
    DetectVarList *fs = det_ctx->varlist;

    SCLogDebug("flow %p det_ctx->varlist %p", f, fs);
    if ((f || p) && fs != NULL) {
        det_ctx->varlist = NULL;
        DetectVarProcessListInternal(fs, f, p);
    }
}

#endif /* __DETECT_FLOWVAR_H__ */
