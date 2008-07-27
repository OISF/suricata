/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_TRIE_H__
#define __UTIL_MPM_TRIE_H__

//#define MPM_DBG_PERF

#define MPM_ENDMATCH_SINGLE 0x01 /* A single match is sufficient */
#define MPM_ENDMATCH_OFFSET 0x02 /* has offset setting */
#define MPM_ENDMATCH_DEPTH  0x04 /* has depth setting */

typedef struct _TrieCharacter {
    u_int16_t min_matchlen_left; /* minimum match length left from this
                                  * character. Used for determining if this
                                  * leaf can match at all */
    struct _TrieCharacter *nc[256];
    MpmEndMatch *em;
} TrieCharacter;

typedef struct _TriePartialMatch {
    struct _TriePartialMatch *prev;
    struct _TriePartialMatch *next;
    TrieCharacter *c;
} TriePartialMatch;

typedef struct _TriePartialMatchList {
    TriePartialMatch *top;
} TriePartialMatchList;

/* global ctx */
typedef struct _TrieCtx {
    u_int32_t queuelen;
    u_int32_t max_queuelen;

    u_int32_t keywords;
    u_int32_t nocase_keywords;
    u_int32_t characters;

    TrieCharacter root;
    TrieCharacter nocase_root;
} TrieCtx;

/* thread ctx */
typedef struct _TrieThreadCtx {
#ifdef MPM_DBG_PERF
    /* debug/performance counters */
    u_int64_t mpmsearch;
    u_int64_t mpmsearchoffsetdepth;

    u_int64_t searchchar_cnt;
    u_int64_t searchchar_pmloop_cnt;
    u_int64_t searchchar_nocase_cnt;
    u_int64_t searchchar_nocase_pmloop_cnt;

    u_int64_t searchchar_nocase_matchroot_cnt;
    u_int64_t searchchar_nocase_prepeek_cnt;
    u_int64_t searchchar_nocase_prepeekmatch_cnt;
    u_int64_t searchchar_nocase_prepeek_nomatchnobuf_cnt;
    u_int64_t searchchar_nocase_prepeek_nomatchbuflen_cnt;
    u_int64_t searchchar_nocase_pmcreate_cnt;

    u_int64_t searchchar_matchroot_cnt;
    u_int64_t searchchar_prepeek_cnt;
    u_int64_t searchchar_prepeekmatch_cnt;
    u_int64_t searchchar_prepeek_nomatchnobuf_cnt;
    u_int64_t searchchar_prepeek_nomatchbuflen_cnt;
    u_int64_t searchchar_pmcreate_cnt;
#endif /* MPM_DBG_PERF */

    /* workspace for partial matches in TrieSearch */
    TriePartialMatchList spare_queue;
    TriePartialMatch *pmqueue;
    TriePartialMatch *nocase_pmqueue;

    u_int8_t *buf;
    u_int8_t *bufmin;
    u_int8_t *bufmax;
    u_int8_t *buflast;

} TrieThreadCtx;

/* prototypes */
void MpmTrieRegister(void);

#endif /* __UTIL_MPM_TRIE_H__ */

