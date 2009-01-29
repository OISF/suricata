/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_H__
#define __UTIL_MPM_H__

#define MPM_ENDMATCH_SINGLE 0x01 /* A single match is sufficient */
#define MPM_ENDMATCH_OFFSET 0x02 /* has offset setting */
#define MPM_ENDMATCH_DEPTH  0x04 /* has depth setting */

enum {
    MPM_TRIE,
    MPM_WUMANBER,
    MPM_B2G,
    MPM_B3G,

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
    u_int32_t sig_id; /* sig callback stuff -- internal id */
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

#define PMQ_MODE_SCAN   0
#define PMQ_MODE_SEARCH 1

/* helper structure for the detection engine. The Pattern Matcher thread
 * has this and passes a pointer to it to the pattern matcher. The actual
 * pattern matcher will fill the structure. */
typedef struct _PatternMatcherQueue {
    /* sig callback stuff XXX consider a separate struct for this*/
    u_int32_t *sig_id_array; /* array with internal sig id's that had a
                                pattern match. These will be inspected
                                futher by the detection engine. */
    u_int32_t sig_id_array_cnt;
    u_int8_t *sig_bitarray;
    char mode; /* 0: scan, 1: search */
} PatternMatcherQueue;

typedef struct _MpmCtx {
    void *ctx;

    void (*InitCtx)(struct _MpmCtx *);
    void (*InitThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int32_t);
    void (*DestroyCtx)(struct _MpmCtx *);
    void (*DestroyThreadCtx)(struct _MpmCtx *, struct _MpmThreadCtx *);
    int  (*AddScanPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddScanPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*Prepare)(struct _MpmCtx *);
    u_int32_t (*Scan)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    u_int32_t (*Search)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    void (*Cleanup)(struct _MpmThreadCtx *);
    void (*PrintCtx)(struct _MpmCtx *);
    void (*PrintThreadCtx)(struct _MpmThreadCtx *);

    u_int32_t memory_cnt;
    u_int32_t memory_size;

    u_int32_t endmatches;

    u_int32_t scan_pattern_cnt;  /* scan patterns */
    u_int32_t pattern_cnt;       /* unique patterns */
    u_int32_t total_pattern_cnt; /* total patterns added */

    u_int16_t scan_minlen;
    u_int16_t scan_maxlen;
    u_int16_t search_minlen;
    u_int16_t search_maxlen;

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
    int  (*AddScanPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddScanPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddPattern)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*AddPatternNocase)(struct _MpmCtx *, u_int8_t *, u_int16_t, u_int16_t, u_int16_t, u_int32_t, u_int32_t);
    int  (*Prepare)(struct _MpmCtx *);
    u_int32_t (*Scan)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    u_int32_t (*Search)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    void (*Cleanup)(struct _MpmThreadCtx *);
    void (*PrintCtx)(struct _MpmCtx *);
    void (*PrintThreadCtx)(struct _MpmThreadCtx *);
    void (*RegisterUnittests)(void);
    u_int8_t flags;
} MpmTableElmt;

void MpmMatchCleanup(MpmThreadCtx *);
MpmMatch *MpmMatchAlloc(MpmThreadCtx *);
int MpmMatchAppend(MpmThreadCtx *, PatternMatcherQueue *, MpmEndMatch *, MpmMatchBucket *, u_int16_t, u_int16_t);
MpmEndMatch *MpmAllocEndMatch (MpmCtx *);
void MpmEndMatchFreeAll(MpmCtx *mpm_ctx, MpmEndMatch *em);
void MpmMatchFreeSpares(MpmThreadCtx *mpm_ctx, MpmMatch *m);

MpmTableElmt mpm_table[MPM_TABLE_SIZE];
void MpmTableSetup(void);
void MpmRegisterTests(void);

void MpmInitCtx (MpmCtx *mpm_ctx, u_int16_t matcher);

#endif /* __UTIL_MPM_H__ */

