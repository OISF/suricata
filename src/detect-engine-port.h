/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __DETECT_PORT_H__
#define __DETECT_PORT_H__

/* prototypes */
int DetectPortParse(const DetectEngineCtx *, DetectPort **head, const char *str);

DetectPort *DetectPortCopy(DetectEngineCtx *, DetectPort *);
DetectPort *DetectPortCopySingle(DetectEngineCtx *, DetectPort *);
int DetectPortInsertCopy(DetectEngineCtx *,DetectPort **, DetectPort *);
int DetectPortInsert(DetectEngineCtx *,DetectPort **, DetectPort *);
void DetectPortCleanupList (DetectPort *head);

DetectPort *DetectPortLookupGroup(DetectPort *dp, uint16_t port);

int DetectPortJoin(DetectEngineCtx *,DetectPort *target, DetectPort *source);

void DetectPortPrint(DetectPort *);
void DetectPortPrintList(DetectPort *head);
int DetectPortCmp(DetectPort *, DetectPort *);
void DetectPortFree(DetectPort *);

int DetectPortTestConfVars(void);

DetectPort *DetectPortHashLookup(DetectEngineCtx *de_ctx, DetectPort *dp);
void DetectPortHashFree(DetectEngineCtx *de_ctx);
int DetectPortHashAdd(DetectEngineCtx *de_ctx, DetectPort *dp);
int DetectPortHashInit(DetectEngineCtx *de_ctx);

void DetectPortTests(void);

#endif /* __DETECT_PORT_H__ */

