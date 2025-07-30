/* Copyright (C) 2007-2017 Open Information Security Foundation
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

#ifndef SURICATA_DETECT_ENGINE_BUILD_H
#define SURICATA_DETECT_ENGINE_BUILD_H

void PacketCreateMask(Packet *p, SignatureMask *mask, AppProto alproto,
        bool app_decoder_events);

int SignatureIsFilestoring(const Signature *);
int SignatureIsFilemagicInspecting(const Signature *);
int SignatureIsFileMd5Inspecting(const Signature *);
int SignatureIsFileSha1Inspecting(const Signature *s);
int SignatureIsFileSha256Inspecting(const Signature *s);
void SignatureSetType(DetectEngineCtx *de_ctx, Signature *s);

int SigPrepareStage1(DetectEngineCtx *de_ctx);
int SigPrepareStage2(DetectEngineCtx *de_ctx);
int SigPrepareStage3(DetectEngineCtx *de_ctx);
int SigPrepareStage4(DetectEngineCtx *de_ctx);
int SigAddressCleanupStage1(DetectEngineCtx *de_ctx);

void SigCleanSignatures(DetectEngineCtx *);

int SigGroupBuild(DetectEngineCtx *);
int SigGroupCleanup (DetectEngineCtx *de_ctx);

#endif /* SURICATA_DETECT_ENGINE_BUILD_H */
