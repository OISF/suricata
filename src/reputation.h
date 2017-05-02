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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *         Original Idea by Matt Jonkman
 */

#ifndef __REPUTATION_H__
#define __REPUTATION_H__

#include "host.h"

#define SREP_MAX_CATS 60

typedef struct SRepCIDRTree_ {
    SCRadixTree *srepIPV4_tree[SREP_MAX_CATS];
    SCRadixTree *srepIPV6_tree[SREP_MAX_CATS];
} SRepCIDRTree;

typedef struct SReputation_ {
    uint32_t version;
    uint8_t rep[SREP_MAX_CATS];
} SReputation;

uint8_t SRepCatGetByShortname(char *shortname);
int SRepInit(struct DetectEngineCtx_ *de_ctx);
void SRepDestroy(struct DetectEngineCtx_ *de_ctx);
void SRepReloadComplete(void);
int SRepHostTimedOut(Host *);

/** Reputation numbers (types) that we can use to lookup/update, etc
 *  Please, dont convert this to a enum since we want the same reputation
 *  codes always. */
#define REPUTATION_SPAM             0   /**< spammer */
#define REPUTATION_CNC              1   /**< CnC server */
#define REPUTATION_SCAN             2   /**< scanner */
#define REPUTATION_HOSTILE          3   /**< hijacked nets, RBN nets, etc */
#define REPUTATION_DYNAMIC          4   /**< Known dial up, residential, user networks */
#define REPUTATION_PUBLICACCESS     5   /**< known internet cafe's open access points */
#define REPUTATION_PROXY            6   /**< known tor out nodes, proxy servers, etc */
#define REPUTATION_P2P              7   /**< Heavy p2p node, torrent server, other sharing services */
#define REPUTATION_UTILITY          8   /**< known good places like google, yahoo, msn.com, etc */
#define REPUTATION_DDOS             9   /**< Known ddos participant */
#define REPUTATION_PHISH            10  /**< Known Phishing site */
#define REPUTATION_MALWARE          11  /**< Known Malware distribution site. Hacked web server, etc */
#define REPUTATION_ZOMBIE           12  /**< Known Zombie (botnet member) They typically are Scanner or Hostile,
                                             but if collaboration with botnet snooping, like we did back in
                                             2005 or so, can proactively identify online zombies that joined a
                                             botnet, you may want to break those out separately */
#define REPUTATION_NUMBER           13  /**< number of rep types we have for data structure size (be careful with this) */


/* Flags for reputation */
#define REPUTATION_FLAG_NEEDSYNC    0x01 /**< rep was changed by engine, needs sync with external hub */

/** Reputation Context for IPV4 IPV6 */
typedef struct IPReputationCtx_ {
    /** Radix trees that holds the host reputation information */
    SCRadixTree *reputationIPV4_tree;
    SCRadixTree *reputationIPV6_tree;

    /** Mutex to support concurrent access */
    SCMutex reputationIPV4_lock;
    SCMutex reputationIPV6_lock;
}IPReputationCtx;

uint8_t SRepCIDRGetIPRepSrc(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version);
uint8_t SRepCIDRGetIPRepDst(SRepCIDRTree *cidr_ctx, Packet *p, uint8_t cat, uint32_t version);
void SRepResetVersion(void);
int SRepLoadCatFileFromFD(FILE *fp);
int SRepLoadFileFromFD(SRepCIDRTree *cidr_ctx, FILE *fp);

#if 0
/** Reputation Data */
//TODO: Add a timestamp here to know the last update of this reputation.
typedef struct Reputation_ {
    uint8_t reps[REPUTATION_NUMBER]; /**< array of 8 bit reputations */
    uint8_t flags; /**< reputation flags */
    time_t ctime; /**< creation time (epoch) */
    time_t mtime; /**< modification time (epoch) */
} Reputation;

/* flags for transactions */
#define TRANSACTION_FLAG_NEEDSYNC 0x01 /**< We will apply the transaction only if necesary */
#define TRANSACTION_FLAG_INCS     0x02 /**< We will increment only if necesary */
#define TRANSACTION_FLAG_DECS     0x04 /**< We will decrement only if necesary */

/* transaction for feedback */
typedef struct ReputationTransaction_ {
    uint16_t inc[REPUTATION_NUMBER];
    uint16_t dec[REPUTATION_NUMBER];
    uint8_t flags;
} ReputationTransaction;

/* API */
Reputation *SCReputationAllocData();
Reputation *SCReputationClone(Reputation *);
void SCReputationFreeData(void *);

IPReputationCtx *SCReputationInitCtx(void);
void SCReputationFreeCtx(IPReputationCtx *);

void SCReputationPrint(Reputation *);
#endif
void SCReputationRegisterTests(void);

#endif /* __REPUTATION_H__ */
