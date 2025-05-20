/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#ifndef SURICATA_DETECT_FILEDATA_H
#define SURICATA_DETECT_FILEDATA_H

/* prototypes */
void DetectFiledataRegister (void);

/* File handler registration */
#define MAX_DETECT_ALPROTO_CNT 10
typedef struct DetectFileHandlerTableElmt_ {
    const char *name;
    int priority;
    PrefilterRegisterFunc PrefilterFn;
    InspectEngineFuncPtr Callback;
    InspectionBufferGetDataPtr GetData;
    int al_protocols[MAX_DETECT_ALPROTO_CNT];
    int tx_progress;
    int progress;
} DetectFileHandlerTableElmt;
void DetectFileRegisterFileProtocols(DetectFileHandlerTableElmt *entry);

/* File registration table */
extern DetectFileHandlerTableElmt filehandler_table[DETECT_TBLSIZE_STATIC];

typedef struct PrefilterMpmFiledata {
    int list_id;
    int base_list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFiledata;

uint8_t DetectEngineInspectFiledata(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);
int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

#endif /* SURICATA_DETECT_FILEDATA_H */
