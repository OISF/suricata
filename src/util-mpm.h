/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __UTIL_MPM_H__
#define __UTIL_MPM_H__

#include "util-prefilter.h"

#define MPM_INIT_HASH_SIZE 65536

enum {
    MPM_NOTSET = 0,

    /* aho-corasick */
    MPM_AC,
    MPM_AC_BS,
    MPM_AC_KS,
    MPM_HS,
    /* table size */
    MPM_TABLE_SIZE,
};

/* Internal Pattern Index: 0 to pattern_cnt-1 */
typedef uint32_t MpmPatternIndex;

typedef struct MpmThreadCtx_ {
    void *ctx;

    uint32_t memory_cnt;
    uint32_t memory_size;

} MpmThreadCtx;

typedef struct MpmPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags decribing the pattern */
    uint8_t flags;

    /* offset into the buffer where match may start */
    uint16_t offset;

    /* offset into the buffer before which match much complete */
    uint16_t depth;

    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* case sensitive */
    uint8_t *cs;
    /* case INsensitive */
    uint8_t *ci;
    /* pattern id */
    uint32_t id;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    struct MpmPattern_ *next;
} MpmPattern;

/* Indicates if this a global mpm_ctx.  Global mpm_ctx is the one that
 * is instantiated when we use "single".  Non-global is "full", i.e.
 * one per sgh. */
#define MPMCTX_FLAGS_GLOBAL     BIT_U8(0)
#define MPMCTX_FLAGS_NODEPTH    BIT_U8(1)

typedef struct MpmCtx_ {
    void *ctx;
    uint8_t mpm_type;

    uint8_t flags;

    uint16_t maxdepth;

    /* unique patterns */
    uint32_t pattern_cnt;

    uint16_t minlen;
    uint16_t maxlen;

    uint32_t memory_cnt;
    uint32_t memory_size;

    uint32_t max_pat_id;

    /* hash used during ctx initialization */
    MpmPattern **init_hash;
} MpmCtx;

/* if we want to retrieve an unique mpm context from the mpm context factory
 * we should supply this as the key */
#define MPM_CTX_FACTORY_UNIQUE_CONTEXT -1

typedef struct MpmCtxFactoryItem {
    const char *name;
    MpmCtx *mpm_ctx_ts;
    MpmCtx *mpm_ctx_tc;
    int32_t id;
    int32_t sm_list;
    struct MpmCtxFactoryItem *next;
} MpmCtxFactoryItem;

typedef struct MpmCtxFactoryContainer_ {
    MpmCtxFactoryItem *items;
    int32_t no_of_items;
    int32_t max_id;
} MpmCtxFactoryContainer;

/** pattern is case insensitive */
#define MPM_PATTERN_FLAG_NOCASE     0x01
/** pattern is negated */
#define MPM_PATTERN_FLAG_NEGATED    0x02
/** pattern has a depth setting */
#define MPM_PATTERN_FLAG_DEPTH      0x04
/** pattern has an offset setting */
#define MPM_PATTERN_FLAG_OFFSET     0x08
/** one byte pattern (used in b2g) */
#define MPM_PATTERN_ONE_BYTE        0x10
/** the ctx uses it's own internal id instead of
 *  what is passed through the API */
#define MPM_PATTERN_CTX_OWNS_ID     0x20

typedef struct MpmTableElmt_ {
    const char *name;
    void (*InitCtx)(struct MpmCtx_ *);
    void (*InitThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *);
    void (*DestroyCtx)(struct MpmCtx_ *);
    void (*DestroyThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *);

    /** function pointers for adding patterns to the mpm ctx.
     *
     *  \param mpm_ctx Mpm context to add the pattern to
     *  \param pattern pointer to the pattern
     *  \param pattern_len length of the pattern in bytes
     *  \param offset pattern offset setting
     *  \param depth pattern depth setting
     *  \param pid pattern id
     *  \param sid signature _internal_ id
     *  \param flags pattern flags
     */
    int  (*AddPattern)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int  (*AddPatternNocase)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int  (*Prepare)(struct MpmCtx_ *);
    uint32_t (*Search)(const struct MpmCtx_ *, struct MpmThreadCtx_ *, PrefilterRuleStore *, const uint8_t *, uint32_t);
    void (*PrintCtx)(struct MpmCtx_ *);
    void (*PrintThreadCtx)(struct MpmThreadCtx_ *);
    void (*RegisterUnittests)(void);
    uint8_t flags;
} MpmTableElmt;

extern MpmTableElmt mpm_table[MPM_TABLE_SIZE];
extern uint8_t mpm_default_matcher;

struct DetectEngineCtx_;

int32_t MpmFactoryRegisterMpmCtxProfile(struct DetectEngineCtx_ *, const char *, const int);
void MpmFactoryReClaimMpmCtx(const struct DetectEngineCtx_ *, MpmCtx *);
MpmCtx *MpmFactoryGetMpmCtxForProfile(const struct DetectEngineCtx_ *, int32_t, int);
void MpmFactoryDeRegisterAllMpmCtxProfiles(struct DetectEngineCtx_ *);
int32_t MpmFactoryIsMpmCtxAvailable(const struct DetectEngineCtx_ *, const MpmCtx *);

void MpmTableSetup(void);
void MpmRegisterTests(void);

void MpmInitCtx(MpmCtx *mpm_ctx, uint8_t matcher);
void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t);

int MpmAddPatternCS(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags);
int MpmAddPatternCI(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags);

void MpmFreePattern(MpmCtx *mpm_ctx, MpmPattern *p);

int MpmAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                            uint16_t offset, uint16_t depth, uint32_t pid,
                            SigIntId sid, uint8_t flags);

#endif /* __UTIL_MPM_H__ */
