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
 * \file detect-engine-tag.h
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements a global context to store data related to hosts flagged
 * tag keyword
 */

#ifndef __DETECT_ENGINE_TAG_H__
#define __DETECT_ENGINE_TAG_H__

#include "host.h"
#include "detect.h"
#include "detect-tag.h"

/* This limit should be overwriten/predefined at the config file
 * to limit the options to prevent possible DOS situations. We should also
 * create a limit for bytes and a limit for number of packets */
#define TAG_MAX_LAST_TIME_SEEN 600

#define TAG_TIMEOUT_CHECK_INTERVAL 60

/* Used for tagged data (sid and gid of the packets that
 * follow the one that triggered the rule with tag option) */
#define TAG_SIG_GEN           2
#define TAG_SIG_ID            1

int TagHashAddTag(DetectTagDataEntry *, Packet *);
int TagFlowAdd(Packet *, DetectTagDataEntry *);

void TagContextDestroy(void);
void TagHandlePacket(DetectEngineCtx *, DetectEngineThreadCtx *, Packet *);

void TagInitCtx(void);
void TagDestroyCtx(void);
void TagRestartCtx(void);

int TagTimeoutCheck(Host *, struct timeval *);

int TagHostHasTag(Host *host);

void DetectEngineTagRegisterTests(void);

#endif /* __DETECT_ENGINE_TAG_H__ */


