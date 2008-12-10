#ifndef __DETECT_H__
#define __DETECT_H__

#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-address.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#define SIG_FLAG_RECURSIVE 0x01
#define SIG_FLAG_SRC_ANY   0x02
#define SIG_FLAG_DST_ANY   0x04
#define SIG_FLAG_SP_ANY    0x08
#define SIG_FLAG_DP_ANY    0x10
#define SIG_FLAG_NOALERT   0x20
#define SIG_FLAG_IPONLY    0x40 /* ip only signature */

#define DE_QUIET           0x01

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
    MpmCtx *mc;       /* search ctx */
    MpmCtx *mc_scan;  /* scan ctx */
    MpmCtx *mcu;
    //MpmCtx *mcu_scan;
    MpmThreadCtx mtc;
    MpmThreadCtx mtcu;

    u_int32_t pkts;
    u_int32_t pkts_scanned;
    u_int32_t pkts_searched;
} PatternMatcherThread;

typedef struct _Signature {
    u_int8_t flags;

    u_int32_t num; /* signature number */
    u_int32_t id;
    u_int8_t rev;
    u_int8_t prio;
    char *msg;
    u_int8_t action; 

    DetectAddressGroupsHead src, dst;
    DetectProto proto;
    DetectPort *sp, *dp;

    //u_int32_t rulegroup_refcnt;
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
    u_int8_t flags;

    Signature *sig_list;
    u_int32_t sig_cnt;

    Signature **sig_array;
    u_int32_t sig_array_size; /* size in bytes */
    u_int32_t sig_array_len;  /* size in array members */

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

    u_int32_t mpm_max_patcnt,
              mpm_min_patcnt,
              mpm_tot_patcnt,
              mpm_uri_max_patcnt,
              mpm_uri_min_patcnt,
              mpm_uri_tot_patcnt;

} DetectEngineCtx;

typedef struct SignatureTuple_ {
    DetectAddressGroup *src;
    DetectAddressGroup *dst;
    DetectPort *sp;
    DetectPort *dp;
    u_int8_t proto;

    struct _SigGroupHead *sgh;

    struct SignatureTuple_ *hnext;
    struct SignatureTuple_ *next;

    u_int32_t cnt;
} SignatureTuple;

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
//#define SIG_GROUP_INITIALIZED    0x4
//#define SIG_GROUP_COPY           0x8

#define SIG_GROUP_HEAD_MPM_COPY      0x4
#define SIG_GROUP_HEAD_MPM_URI_COPY  0x8
#define SIG_GROUP_HEAD_FREE          0x10

/* head of the list of containers. */
typedef struct _SigGroupHead {
    u_int8_t flags;

    /* pattern matcher instance */
    MpmCtx *mpm_ctx;      /* search */
    MpmCtx *mpm_scan_ctx; /* scan */
    u_int16_t mpm_content_minlen;
    MpmCtx *mpm_uri_ctx;
    u_int16_t mpm_uricontent_minlen;

    /* number of sigs in this head */
    u_int32_t sig_cnt;

    u_int8_t *sig_array; /* bit array of sig nums */
    u_int32_t sig_size; /* size in bytes */

    /* array with sig nums... size is sig_cnt * sizeof(u_int32_t) */
    u_int32_t *match_array;

    /* list of content containers
     * XXX move into a separate data struct
     * with only a ptr to it. Saves some memory
     * after initialization
     */
    u_int32_t *content_array;
    u_int32_t content_size;
    u_int32_t *uri_content_array;
    u_int32_t uri_content_size;

    /* port ptr */
    struct DetectPort_ *port;

    struct _SigGroupHead *mpm_next; /* mpm and mpm_uri hash */
    struct _SigGroupHead *mpm_uri_next; /* mpm and mpm_uri hash */
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
    DETECT_PKTVAR,
    DETECT_NOALERT,

    DETECT_ADDRESS,
    DETECT_PROTO,
    DETECT_PORT,

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

