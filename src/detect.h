#ifndef __DETECT_H__
#define __DETECT_H__

#define SIG_FLAG_RECURSIVE 0x01
#define SIG_FLAG_SP_ANY    0x02
#define SIG_FLAG_DP_ANY    0x04

typedef struct _PatternMatcherThread {
    /* detection engine variables */
    u_int8_t *pkt_ptr; /* ptr to the current position in the pkt */
    u_int16_t pkt_off;
    u_int8_t pkt_cnt;

    /* multipattern matcher ctx */
    MpmThreadCtx mpm_ctx[MPM_INSTANCE_MAX];
    char de_checking_distancewithin;

    /* http_uri stuff for uricontent */
    char de_have_httpuri;
    char de_scanned_httpuri;

    /* instance of the mpm */
    u_int8_t mpm_instance;
} PatternMatcherThread;

/* for now typedef them to known types, we will implement
 * our types later... */
typedef Port SigPort;
typedef Address SigAddress;

typedef struct _Signature {
    u_int32_t id;
    u_int8_t rev;
    char *msg;
    u_int8_t flags;

    SigAddress src, dst;
    SigPort sp, dp;

    struct _SigMatch *match;
    struct _Signature *next;
} Signature;

typedef struct _SigMatch {
    u_int8_t type;
    void *ctx;
    struct _SigMatch *prev;
    struct _SigMatch *next;
} SigMatch;

typedef struct SigTableElmt {
    char *name;
    u_int8_t cost; /* 0 hardly any, 255 very expensive */
    int (*Match)(ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
    int (*Setup)(Signature *, SigMatch *, char *);
    int (*Free)(SigMatch *);
    void (*RegisterTests)(void);
    u_int8_t flags;
} SigTableElmt;

#define SIGMATCH_NOOPT  0x01

void SigLoadSignatures (void);
void SigTableSetup(void);

enum {
    DETECT_SID,
    DETECT_REV,
    DETECT_CLASSTYPE,
    DETECT_THRESHOLD,
    DETECT_METADATA,
    DETECT_REFERENCE,
    DETECT_MSG,
    DETECT_CONTENT,
    DETECT_URICONTENT,
    DETECT_PCRE,
    DETECT_DEPTH,
    DETECT_DISTANCE,
    DETECT_WITHIN,
    DETECT_OFFSET,
    DETECT_NOCASE,
    DETECT_RECURSIVE,
    DETECT_RAWBYTES,
    DETECT_FLOW,
    DETECT_DSIZE,
    DETECT_FLOWVAR,
    DETECT_ADDRESS,

    /* make sure this stays last */
    DETECT_TBLSIZE,
};

/* Table with all SigMatch registrations */
SigTableElmt sigmatch_table[DETECT_TBLSIZE];

/* detection api */
SigMatch *SigMatchAlloc(void);
void SigMatchAppend(Signature *, SigMatch *, SigMatch *);
void SigCleanSignatures(void);

void SigTableRegisterTests(void);
void SigRegisterTests(void);
void TmModuleDetectRegister (void);

#endif /* __DETECT_H__ */

