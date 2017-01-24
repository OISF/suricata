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

/** \file
 *
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 */

#ifndef __DETECT_ENGINE_FILEDATA_SMTP_H__
#define __DETECT_ENGINE_FILEDATA_SMTP_H__

#include "app-layer-smtp.h"

int PrefilterTxSmtpFiledataRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);

int DetectEngineInspectSMTPFiledata(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id);

void DetectEngineCleanSMTPBuffers(DetectEngineThreadCtx *det_ctx);

void DetectEngineSMTPFiledataRegisterTests(void);

#endif /* __DETECT_ENGINE_FILEDATA_SMTP_H__ */
