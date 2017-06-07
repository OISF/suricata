/* Copyright (C) 2016 Open Information Security Foundation
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
 *  \author Mats Klepsland <mats.klepsland@gmail.com>
 */

#ifndef __DETECT_ENGINE_TLS_H__
#define __DETECT_ENGINE_TLS_H__

int PrefilterTxTlsSniRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);
int PrefilterTxTlsIssuerRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);
int PrefilterTxTlsSubjectRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);
int PrefilterTxTlsSerialRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);

int DetectEngineInspectTlsSni(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

int DetectEngineInspectTlsIssuer(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

int DetectEngineInspectTlsSubject(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

int DetectEngineInspectTlsSerial(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

int DetectEngineInspectTlsValidity(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

#endif /* __DETECT_ENGINE_TLS_H__ */
