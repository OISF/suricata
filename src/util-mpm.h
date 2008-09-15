/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_H__
#define __UTIL_MPM_H__

#define MPM_ENDMATCH_SINGLE 0x01 /* A single match is sufficient */
#define MPM_ENDMATCH_OFFSET 0x02 /* has offset setting */
#define MPM_ENDMATCH_DEPTH  0x04 /* has depth setting */

enum {
    MPM_TRIE,
    MPM_WUMANBER,

    /* table size */
    MPM_TABLE_SIZE,
};

/* Data structures */
typedef struct _MpmEndMatch {
    u_int32_t id;
    u_int16_t depth;
    u_int16_t offset;
    u_int8_t flags;
    struct _MpmEndMatch *next;
} MpmEndMatch;

typedef struct _MpmMatch {
    u_int16_t offset; /* offset of this match in the search buffer */
    struct _MpmMatch *next; /* match list -- used to connect a match to a
                             * pattern id. */
    struct _MpmMatch *qnext; /* queue list -- used to cleanup all matches after
                              * the inspection. */
    struct _MpmMatchBucket *mb; /* pointer back to the bucket */
} MpmMatch;

typedef struct _MpmMatchBucket {
    MpmMatch *top;
    MpmMatch *bot;
    u_int32_t len;
} MpmMatchBucket;

typedef struct _MpmThreadCtx {
    void *ctx;

    u_int32_t memory_cnt;
    u_int32_t memory_size;

    MpmMatchBucket *match;
    /* list of all matches */
    MpmMatch *qlist;
    /* spare list */
    MpmMatch *sparelist;

    u_int32_t matches;

} MpmThreadCtx;

typedef struct _MpmCtx {
    void *ctx;

    void (*InitCtx)(struct _MpmCtx *);
    void (*InitThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int32_t);
    void (*DestroyCtx)(struct _MpmCtx *);
    void (*DestroyThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *);
    int  (*AddPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int32_t);
    int  (*AddPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int32_t);
    int  (*Prepare)(struct _MpmCtx *);
    u_int32_t (*Search)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int8_t *, u_int16_t);
    void (*Cleanup)(struct _MpmThreadCtx *);
    void (*PrintCtx)(struct _MpmCtx *);
    void (*PrintThreadCtx)(struct _MpmThreadCtx *);

    u_int32_t memory_cnt;
    u_int32_t memory_size;

    u_int32_t endmatches;

    u_int32_t pattern_cnt;       /* unique patterns */
    u_int32_t total_pattern_cnt; /* total patterns added */

    u_int16_t minlen;
    u_int16_t maxlen;

    /* this is used to determine the size of the match
     * loopup table */
    u_int32_t max_pattern_id;

} MpmCtx;

typedef struct MpmTableElmt {
    char *name;
    void (*InitCtx)(struct _MpmCtx *);
    void (*InitThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int32_t);
    void (*DestroyCtx)(struct _MpmCtx *);
    void (*DestroyThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *);
    int  (*AddPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int32_t);
    int  (*AddPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int32_t);
    int  (*Prepare)(struct _MpmCtx *);
    u_int32_t (*Search)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int8_t *, u_int16_t);
    void (*Cleanup)(struct _MpmThreadCtx *);
    void (*PrintCtx)(struct _MpmCtx *);
    void (*PrintThreadCtx)(struct _MpmThreadCtx *);
    void (*RegisterUnittests)(void);
    u_int8_t flags;
} MpmTableElmt;

void MpmMatchCleanup(MpmThreadCtx *);
MpmMatch *MpmMatchAlloc(MpmThreadCtx *);
void MpmMatchAppend(MpmThreadCtx *, MpmEndMatch *, MpmMatchBucket *, u_int16_t);
MpmEndMatch *MpmAllocEndMatch (MpmCtx *);
void MpmEndMatchFreeAll(MpmCtx *mpm_ctx, MpmEndMatch *em);
void MpmMatchFreeSpares(MpmThreadCtx *mpm_ctx, MpmMatch *m);

MpmTableElmt mpm_table[MPM_TABLE_SIZE];
void MpmTableSetup(void);
void MpmRegisterTests(void);

void MpmInitCtx (MpmCtx *mpm_ctx, u_int16_t matcher);

#endif /* __UTIL_MPM_H__ */

