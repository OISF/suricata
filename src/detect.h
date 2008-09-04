#ifndef __DETECT_H__
#define __DETECT_H__

#include "detect-engine-proto.h"
#include "detect-address.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#define SIG_FLAG_RECURSIVE 0x01
#define SIG_FLAG_SP_ANY    0x02
#define SIG_FLAG_DP_ANY    0x04
#define SIG_FLAG_NOALERT   0x08
#define SIG_FLAG_IPONLY    0x10 /* ip only signature */

typedef struct _PatternMatcherThread {
    /* detection engine variables */
    u_int8_t *pkt_ptr; /* ptr to the current position in the pkt */
    u_int16_t pkt_off;
    u_int8_t pkt_cnt;

    char de_checking_distancewithin;

    /* http_uri stuff for uricontent */
    char de_have_httpuri;
    char de_scanned_httpuri;

    /* pointer to the current mpm ctx that is stored
     * in a rule group head -- can be either a content
     * or uricontent ctx.
     *
     * XXX rename to mpm_ctx as soon as the threading
     * thing above is renamed as well  */
    MpmCtx *mc;
    MpmCtx *mcu;
    MpmThreadCtx mtc;
    MpmThreadCtx mtcu;
} PatternMatcherThread;

/* for now typedef them to known types, we will implement
 * our types later... */
typedef Port SigPort;
typedef Address SigAddress;

typedef struct _Signature {
    u_int32_t id;
    u_int8_t rev;
    u_int8_t prio;
    char *msg;
    u_int8_t flags;
    u_int8_t action; 
    DetectAddressGroupsHead src, dst;
    SigPort sp, dp;
    DetectProto proto;
    u_int32_t rulegroup_refcnt;
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

typedef struct DetectEngineCtx_ {
    Signature *sig_list;
    u_int32_t sig_cnt;

    /* ip only sigs: we only add 'alert ip' without
     * an ip_proto setting here, so no need to look
     * at the proto */
    DetectAddressGroupsHead *io_src_gh;
    DetectAddressGroupsHead *io_tmp_gh;

    /* main sigs */
    DetectAddressGroupsHead *src_gh[256];
    DetectAddressGroupsHead *tmp_gh[256];

    u_int32_t mpm_unique, mpm_reuse, mpm_none,
              mpm_uri_unique, mpm_uri_reuse, mpm_uri_none;
    u_int32_t gh_unique, gh_reuse;

} DetectEngineCtx;

#define SIGGROUP_PROTO 1
#define SIGGROUP_SP    2
#define SIGGROUP_DP    3
#define SIGGROUP_SRC   4
#define SIGGROUP_DST   5
#define SIGGROUP_FLOW  6
#define SIGGROUP_DSIZE 7
/* XXX more? */

/* list container for signatures in the rule groups */
typedef struct _SigGroupContainer {
    /* ptr to the signature */
    Signature *s;

    /* list */
    struct _SigGroupContainer *next;
} SigGroupContainer;

/* container for content matches... we use this to compare
 * group heads for contents
 * XXX name */
typedef struct _SigGroupContent {
    DetectContentData *content;
    struct _SigGroupContent *next;
} SigGroupContent;

/* container for content matches... we use this to compare
 * group heads for contents
 * XXX name */
typedef struct _SigGroupUricontent {
    DetectUricontentData *content;
    struct _SigGroupUricontent *next;
} SigGroupUricontent;

#define SIG_GROUP_HAVECONTENT    0x1
#define SIG_GROUP_HAVEURICONTENT 0x2

/* XXX rename */
#define SIG_GROUP_INITIALIZED    0x4
#define SIG_GROUP_COPY           0x8

#define SIG_GROUP_HEAD_MPM_COPY      0x4
#define SIG_GROUP_HEAD_MPM_URI_COPY  0x8

/* head of the list of containers. */
typedef struct _SigGroupHead {
    u_int8_t flags;

    /* pattern matcher instance */
    MpmCtx *mpm_ctx;
    MpmCtx *mpm_uri_ctx;

    /* list of content containers
     * XXX move into a separate data struct
     * with only a ptr to it. Saves some memory
     * after initialization
     * XXX use a bitarray to save 7/8 of the mem*/
    u_int32_t *content_array;
    u_int32_t content_size;
    u_int32_t *uri_content_array;
    u_int32_t uri_content_size;

    /* list of signature containers */
    SigGroupContainer *head;
    SigGroupContainer *tail;
    u_int32_t sig_cnt;

    struct _SigGroupHead *next;
} SigGroupHead;

#define SIGMATCH_NOOPT  0x01

void SigLoadSignatures (void);
void SigTableSetup(void);

enum {
    DETECT_SID,
    DETECT_PRIORITY,
    DETECT_REV,
    DETECT_CLASSTYPE,
    DETECT_THRESHOLD,
    DETECT_METADATA,
    DETECT_REFERENCE,
    DETECT_MSG,
    DETECT_CONTENT,    /* 8 */
    DETECT_URICONTENT, /* 9 */
    DETECT_PCRE,       /* 10 */
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
    DETECT_PROTO,
    DETECT_NOALERT,

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

int SigGroupBuild(DetectEngineCtx *);
int SigGroupCleanup();

#endif /* __DETECT_H__ */

