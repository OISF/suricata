#ifndef __DETECT_H__
#define __DETECT_H__

#include "detect-engine-proto.h"

#include "util-hash.h"
#include "util-hashlist.h"

#define COUNTER_DETECT_ALERTS 1

/*
 * DETECT ADDRESS
 */

/* a is ... than b */
enum {
    ADDRESS_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /* smaller              [aaa] [bbb] */
    ADDRESS_LE,      /* smaller with overlap [aa[bab]bb] */
    ADDRESS_EQ,      /* exactly equal        [abababab]  */
    ADDRESS_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GE,      /* bigger with overlap  [bb[aba]aa] */
    ADDRESS_GT,      /* bigger               [bbb] [aaa] */
};

#define ADDRESS_FLAG_ANY 0x1
#define ADDRESS_FLAG_NOT 0x2

#define ADDRESS_GROUP_SIGGROUPHEAD_COPY  0x01
#define ADDRESS_GROUP_PORTS_COPY         0x02
#define ADDRESS_GROUP_PORTS_NOTUNIQ      0x04
#define ADDRESS_GROUP_HAVEPORT           0x08

typedef struct DetectAddressData_ {
    /* XXX convert to use a Address datatype to replace family, ip,ip2*/
    u_int8_t family;
    u_int32_t ip[4];
    u_int32_t ip2[4];
    u_int8_t flags;
} DetectAddressData;

typedef struct DetectAddressGroup_ {
    /* address data for this group */
    DetectAddressData *ad;

    /* XXX ptr to rules, or PortGroup or whatever */
    union {
        struct DetectAddressGroupsHead_ *dst_gh;
        struct DetectPort_ *port;
    };
    /* signatures that belong in this group */
    struct SigGroupHead_ *sh;
    u_int8_t flags;

    /* double linked list */
    struct DetectAddressGroup_ *prev;
    struct DetectAddressGroup_ *next;

    u_int32_t cnt;
} DetectAddressGroup;

typedef struct DetectAddressGroupsHead_ {
    DetectAddressGroup *any_head;
    DetectAddressGroup *ipv4_head;
    DetectAddressGroup *ipv6_head;
} DetectAddressGroupsHead;

/*
 * DETECT PORT
 */

/* a is ... than b */
enum {
    PORT_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    PORT_LT,      /* smaller              [aaa] [bbb] */
    PORT_LE,      /* smaller with overlap [aa[bab]bb] */
    PORT_EQ,      /* exactly equal        [abababab]  */
    PORT_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    PORT_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    PORT_GE,      /* bigger with overlap  [bb[aba]aa] */
    PORT_GT,      /* bigger               [bbb] [aaa] */
};

#define PORT_FLAG_ANY 0x1
#define PORT_FLAG_NOT 0x2

#define PORT_SIGGROUPHEAD_COPY 0x04
#define PORT_GROUP_PORTS_COPY  0x08

typedef struct DetectPort_ {
    u_int8_t flags;

    u_int16_t port;
    u_int16_t port2;

    /* signatures that belong in this group */
    struct SigGroupHead_ *sh;

    struct DetectPort_ *dst_ph;

    /* double linked list */
    union {
        struct DetectPort_ *prev;
        struct DetectPort_ *hnext; /* hash next */
    };
    struct DetectPort_ *next;

    u_int32_t cnt;
} DetectPort;

/* Signature flags */
#define SIG_FLAG_RECURSIVE 0x0001 /* recurive capturing enabled */
#define SIG_FLAG_SRC_ANY   0x0002 /* source is any */
#define SIG_FLAG_DST_ANY   0x0004 /* destination is any */
#define SIG_FLAG_SP_ANY    0x0008 /* source port is any */
#define SIG_FLAG_DP_ANY    0x0010 /* destination port is any */
#define SIG_FLAG_NOALERT   0x0020 /* no alert flag is set */
#define SIG_FLAG_IPONLY    0x0040 /* ip only signature */
#define SIG_FLAG_MPM       0x0080 /* sig has mpm portion (content, uricontent, etc) */

/* Detection Engine flags */
#define DE_QUIET           0x01   /* DE is quiet (esp for unittests) */

typedef struct DetectEngineIPOnlyThreadCtx_ {
    DetectAddressGroup *src, *dst;
    u_int8_t *sig_match_array; /* bit array of sig nums */
    u_int32_t sig_match_size;  /* size in bytes of the array */
} DetectEngineIPOnlyThreadCtx;

/**
  * Detection engine thread data.
  * XXX: we should rename this
  */
typedef struct PatternMatcherThread_ {
    /* detection engine variables */
    u_int8_t *pkt_ptr; /* ptr to the current position in the pkt */
    u_int16_t pkt_off;
    u_int8_t pkt_cnt;

    char de_checking_distancewithin;

    /* http_uri stuff for uricontent */
    char de_have_httpuri;

    /* pointer to the current mpm ctx that is stored
     * in a rule group head -- can be either a content
     * or uricontent ctx. */
    MpmThreadCtx mtc; /* thread ctx for the mpm */
    MpmThreadCtx mtcu;
    struct SigGroupHead_ *sgh;
    PatternMatcherQueue pmq;

    /* counters */
    u_int32_t pkts;
    u_int32_t pkts_scanned;
    u_int32_t pkts_searched;
    u_int32_t pkts_scanned1;
    u_int32_t pkts_searched1;
    u_int32_t pkts_scanned2;
    u_int32_t pkts_searched2;
    u_int32_t pkts_scanned3;
    u_int32_t pkts_searched3;
    u_int32_t pkts_scanned4;
    u_int32_t pkts_searched4;

    u_int32_t uris;
    u_int32_t pkts_uri_scanned;
    u_int32_t pkts_uri_searched;
    u_int32_t pkts_uri_scanned1;
    u_int32_t pkts_uri_searched1;
    u_int32_t pkts_uri_scanned2;
    u_int32_t pkts_uri_searched2;
    u_int32_t pkts_uri_scanned3;
    u_int32_t pkts_uri_searched3;
    u_int32_t pkts_uri_scanned4;
    u_int32_t pkts_uri_searched4;

    DetectEngineIPOnlyThreadCtx io_ctx;

} PatternMatcherThread;

typedef struct Signature_ {
    u_int16_t flags;

    u_int32_t num; /* signature number, internal id */
    u_int32_t id;
    u_int8_t rev;
    u_int8_t prio;
    char *msg;
    u_int8_t action; 

    DetectAddressGroupsHead src, dst;
    DetectProto proto;
    DetectPort *sp, *dp;

    struct SigMatch_ *match;
    struct Signature_ *next;
} Signature;

typedef struct DetectEngineIPOnlyCtx_ {
    /* lookup hashes */
    HashListTable *ht16_src, *ht16_dst;
    HashListTable *ht24_src, *ht24_dst;

    /* counters */
    u_int32_t a_src_uniq16, a_src_total16;
    u_int32_t a_dst_uniq16, a_dst_total16;
    u_int32_t a_src_uniq24, a_src_total24;
    u_int32_t a_dst_uniq24, a_dst_total24;

    u_int32_t max_idx;

    u_int8_t *sig_init_array; /* bit array of sig nums */
    u_int32_t sig_init_size;  /* size in bytes of the array */

    /* number of sigs in this head */
    u_int32_t sig_cnt;
    u_int32_t *match_array; 
} DetectEngineIPOnlyCtx;

typedef struct DetectEngineLookupFlow_ {
    DetectAddressGroupsHead *src_gh[256]; /* a head for each protocol */
    DetectAddressGroupsHead *tmp_gh[256];
} DetectEngineLookupFlow;

/* Flow status
 *
 * to server
 * to client
 */
#define FLOW_STATES 2
typedef struct DetectEngineLookupDsize_ {
    DetectEngineLookupFlow flow_gh[FLOW_STATES];
} DetectEngineLookupDsize;

/* Dsize states
 * <= 100
 * >100
 */
#define DSIZE_STATES 2

typedef struct DetectEngineCtx_ {
    u_int8_t flags;

    Signature *sig_list;
    u_int32_t sig_cnt;

    Signature **sig_array;
    u_int32_t sig_array_size; /* size in bytes */
    u_int32_t sig_array_len;  /* size in array members */

    u_int32_t signum;

    /* main sigs */
    DetectEngineLookupDsize dsize_gh[DSIZE_STATES];

    u_int32_t mpm_unique, mpm_reuse, mpm_none,
              mpm_uri_unique, mpm_uri_reuse, mpm_uri_none;
    u_int32_t gh_unique, gh_reuse;

    u_int32_t mpm_max_patcnt, mpm_min_patcnt, mpm_tot_patcnt,
              mpm_uri_max_patcnt, mpm_uri_min_patcnt, mpm_uri_tot_patcnt;

    /* content and uricontent vars */
    u_int32_t content_max_id;
    u_int32_t uricontent_max_id;

    /* init phase vars */
    HashListTable *sgh_hash_table;

    HashListTable *sgh_mpm_hash_table;
    HashListTable *sgh_mpm_uri_hash_table;

    HashListTable *sgh_sport_hash_table;
    HashListTable *sgh_dport_hash_table;

    HashListTable *sport_hash_table;
    HashListTable *dport_hash_table;

    HashListTable *variable_names;
    u_int16_t variable_names_idx;

    /* memory counters */
    u_int32_t mpm_memory_size;

    DetectEngineIPOnlyCtx io_ctx;
} DetectEngineCtx;

typedef struct SigMatch_ {
    u_int8_t type;
    void *ctx;
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

typedef struct SigTableElmt_ {
    int (*Match)(ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
    int (*Setup)(DetectEngineCtx *, Signature *, SigMatch *, char *);
    int (*Free)(SigMatch *);
    void (*RegisterTests)(void);

    u_int8_t flags;
    char *name;
} SigTableElmt;

#define SIG_GROUP_HAVECONTENT          0x1
#define SIG_GROUP_HAVEURICONTENT       0x2
#define SIG_GROUP_HEAD_MPM_COPY        0x4
#define SIG_GROUP_HEAD_MPM_URI_COPY    0x8
#define SIG_GROUP_HEAD_FREE            0x10
#define SIG_GROUP_HEAD_MPM_NOSCAN      0x20
#define SIG_GROUP_HEAD_MPM_URI_NOSCAN  0x40

/* head of the list of containers. */
typedef struct SigGroupHead_ {
    u_int8_t flags;

    /* pattern matcher instance */
    MpmCtx *mpm_ctx;      /* search */
    u_int16_t mpm_content_maxlen;
    MpmCtx *mpm_uri_ctx;
    u_int16_t mpm_uricontent_maxlen;

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

    u_int16_t mpm_len1;
    u_int16_t mpm_len2;
    u_int16_t mpm_len3;
    u_int16_t mpm_len4; /* 4+ */
} SigGroupHead;

#define SIGMATCH_NOOPT  0x01

void SigLoadSignatures (char *);
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
    DETECT_FLOWBITS,

    DETECT_ADDRESS,
    DETECT_PROTO,
    DETECT_PORT,
    DETECT_DECODE_EVENT,
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

int PacketAlertAppend(Packet *, u_int8_t, u_int32_t, u_int8_t, u_int8_t, char *);
/*
 * XXX globals, remove
 */

DetectEngineCtx *g_de_ctx;

#endif /* __DETECT_H__ */

