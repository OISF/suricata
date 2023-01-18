/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *         Original Idea by Matt Jonkman
 */

#ifndef __REPUTATION_H__
#define __REPUTATION_H__

#include "host.h"
#include "util-radix-tree.h"

#define SREP_MAX_CATS 60
#define SREP_MAX_VAL 127

typedef struct SRepCIDRTree_ {
    SCRadixTree *srepIPV4_tree[SREP_MAX_CATS];
    SCRadixTree *srepIPV6_tree[SREP_MAX_CATS];
} SRepCIDRTree;

typedef struct SReputation_ {
    uint32_t version;
    uint8_t rep[SREP_MAX_CATS];
} SReputation;

void SRepFreeHostData(Host *h);
uint8_t SRepCatGetByShortname(char *shortname);
int SRepInit(struct DetectEngineCtx_ *de_ctx);
void SRepDestroy(struct DetectEngineCtx_ *de_ctx);
void SRepReloadComplete(void);
int SRepHostTimedOut(Host *);

uint8_t SRepCIDRGetIPRepSrc(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version);
uint8_t SRepCIDRGetIPRepDst(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version);
void SRepResetVersion(void);
int SRepLoadCatFileFromFD(FILE *fp);
int SRepLoadFileFromFD(SRepCIDRTree *cidr_ctx, FILE *fp);

void SCReputationRegisterTests(void);

#endif /* __REPUTATION_H__ */
