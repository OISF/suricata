/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#ifndef __UTIL_JA4_H__
#define __UTIL_JA4_H__

typedef struct JA4_ JA4;

JA4 *Ja4Init(void);
void Ja4SetQUIC(JA4 *);
void Ja4SetTLSVersion(JA4 *, const uint16_t);
void Ja4SetALPN(JA4 *, const uint8_t *, uint8_t);
void Ja4AddCipher(JA4 *, const uint16_t);
void Ja4AddExtension(JA4 *, const uint16_t);
void Ja4AddSigAlgo(JA4 *, const uint16_t);
const char *Ja4GetHash(JA4 *);
void Ja4Reset(JA4 *);
void Ja4Free(JA4 **);
/* TODO */
void Ja4RegisterTests(void);

InspectionBuffer *Ja4DetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

#endif /* __UTIL_JA4_H__ */
