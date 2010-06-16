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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __RUNMODES_H__
#define __RUNMODES_H__

void RunModeInitializeOutputs(void);

int RunModeIdsPcap(DetectEngineCtx *, char *);
int RunModeIdsPcap2(DetectEngineCtx *, char *);
int RunModeIdsPcap3(DetectEngineCtx *, char *);
int RunModeIdsPcapAuto(DetectEngineCtx *, char *);

int RunModeIpsNFQ(DetectEngineCtx *, char *);
int RunModeIpsNFQAuto(DetectEngineCtx *, char *);

int RunModeFilePcap(DetectEngineCtx *, char *);
int RunModeFilePcap2(DetectEngineCtx *, char *);
int RunModeFilePcapAuto(DetectEngineCtx *, char *);
int RunModeFilePcapAuto2(DetectEngineCtx *, char *);

int RunModeIdsPfring(DetectEngineCtx *, char *);
int RunModeIdsPfring2(DetectEngineCtx *, char *);
int RunModeIdsPfring3(DetectEngineCtx *, char *);
int RunModeIdsPfring4(DetectEngineCtx *, char *);
int RunModeIdsPfringAuto(DetectEngineCtx *, char *);

int RunModeIpsIPFW(DetectEngineCtx *);
int RunModeIpsIPFWAuto(DetectEngineCtx *);

int RunModeErfFileAuto(DetectEngineCtx *, char *);
int RunModeErfDagAuto(DetectEngineCtx *, char *);

void RunModeShutDown(void);

#endif /* __RUNMODES_H__ */

