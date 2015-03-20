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
    uint16_t idx;
    uint8_t *content;
    uint8_t content_len;
    uint8_t flags;
} DetectFlowvarData;

/* prototypes */
void DetectFlowvarRegister (void);

int DetectFlowvarPostMatchSetup(Signature *s, uint16_t idx);
int DetectFlowvarStoreMatch(DetectEngineThreadCtx *, uint16_t, uint8_t *, uint16_t, int);

/* For use only by DetectFlowvarProcessList() */
void DetectFlowvarProcessListInternal(DetectFlowvarList *fs, Flow *f, const int flow_locked);
static inline void DetectFlowvarProcessList(DetectEngineThreadCtx *det_ctx, Flow *f)
{
    DetectFlowvarList *fs = det_ctx->flowvarlist;
    const int flow_locked = det_ctx->flow_locked;

    SCLogDebug("det_ctx->flowvarlist %p", fs);

    if (fs != NULL) {
        det_ctx->flowvarlist = NULL;
        DetectFlowvarProcessListInternal(fs, f, flow_locked);
    }
}

#endif /* __DETECT_FLOWVAR_H__ */
