/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_ENGINE_HHHD_H__
#define __DETECT_ENGINE_HHHD_H__

#include "app-layer-htp.h"

int DetectEngineInspectHttpHH(ThreadVars *tv,
                              DetectEngineCtx *, DetectEngineThreadCtx *,
                              Signature *, Flow *, uint8_t, void *, int);
int DetectEngineRunHttpHHMpm(DetectEngineThreadCtx *, Flow *, HtpState *, uint8_t);
void DetectEngineHttpHHRegisterTests(void);

#endif /* __DETECT_ENGINE_HHHD_H__ */
