#ifndef __DETECT_H__
#define __DETECT_H__

#include <stdint.h>

#include "flow.h"

#include "detect-engine-proto.h"
#include "detect-reference.h"

#include "packet-queue.h"
#include "util-mpm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-radix-tree.h"

#include "detect-threshold.h"

#define COUNTER_DETECT_ALERTS 1

/* forward declarations for the structures from detect-engine-sigorder.h */
struct SCSigOrderFunc_;
struct SCSigSignatureWrapper_;

/*

  The detection engine groups similar signatures/rules together. Internally a
  tree of different types of data is created on initialization. This is it's
  global layout:

   For TCP/UDP

   Packet data size (dsize)
   - Flow direction
   -- Protocol
   -=- Src address
   -==- Dst address
   -===- Src port
   -====- Dst port

   For the other protocols

   Packet data size (dsize)
   - Flow direction
   -- Protocol
   -=- Src address
   -==- Dst address

*/

/*
 * DETECT ADDRESS
 */

/* a is ... than b */
enum {
    ADDRESS_ER = -1, /**< error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /**< smaller              [aaa] [bbb] */
    ADDRESS_LE,      /**< smaller with overlap [aa[bab]bb] */
    ADDRESS_EQ,      /**< exactly equal        [abababab]  */
    ADDRESS_ES,      /**< within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /**< completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GE,      /**< bigger with overlap  [bb[aba]aa] */
    ADDRESS_GT,      /**< bigger               [bbb] [aaa] */
};

#define ADDRESS_FLAG_ANY            0x01 /**< address is "any" */
#define ADDRESS_FLAG_NOT            0x02 /**< address is negated */

#define ADDRESS_SIGGROUPHEAD_COPY   0x04 /**< sgh is a ptr to another sgh */
#define ADDRESS_PORTS_COPY          0x08 /**< ports are a ptr to other ports */
#define ADDRESS_PORTS_NOTUNIQ       0x10
#define ADDRESS_HAVEPORT            0x20 /**< address has a ports ptr */

/** \brief address structure for use in the detection engine.
 *
 *  Contains the address information and matching information.
 */
typedef struct DetectAddress_ {
    /** address data for this group */
    uint8_t family; /**< address family, AF_INET (IPv4) or AF_INET6 (IPv6) */
    uint32_t ip[4]; /**< the address, or lower end of a range */
    uint32_t ip2[4]; /**< higher end of a range */

    /** ptr to the next address (dst addr in that case) or to the src port */
    union {
        struct DetectAddressHead_ *dst_gh; /**< destination address */
        struct DetectPort_ *port; /**< source port */
    };

    /** signatures that belong in this group */
    struct SigGroupHead_ *sh;

    /** flags affecting this address */
    uint8_t flags;

    /** ptr to the previous address in the list */
    struct DetectAddress_ *prev;
    /** ptr to the next address in the list */
    struct DetectAddress_ *next;

    uint32_t cnt;
} DetectAddress;

/** Signature grouping head. Here 'any', ipv4 and ipv6 are split out */
typedef struct DetectAddressHead_ {
    DetectAddress *any_head;
    DetectAddress *ipv4_head;
    DetectAddress *ipv6_head;
} DetectAddressHead;

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

#define PORT_FLAG_ANY           0x01 /**< 'any' special port */
#define PORT_FLAG_NOT           0x02 /**< negated port */
#define PORT_SIGGROUPHEAD_COPY  0x04 /**< sgh is a ptr copy */
#define PORT_GROUP_PORTS_COPY   0x08 /**< dst_ph is a ptr copy */

/** \brief Port structure for detection engine */
typedef struct DetectPort_ {
    uint16_t port;
    uint16_t port2;

    /* signatures that belong in this group */
    struct SigGroupHead_ *sh;

    struct DetectPort_ *dst_ph;

    /* double linked list */
    union {
        struct DetectPort_ *prev;
        struct DetectPort_ *hnext; /* hash next */
    };
    struct DetectPort_ *next;

    uint32_t cnt;
    uint8_t flags;  /**< flags for this port */
} DetectPort;

/* Signature flags */
#define SIG_FLAG_RECURSIVE 0x0001   /**< recursive capturing enabled */
#define SIG_FLAG_SRC_ANY   0x0002   /**< source is any */
#define SIG_FLAG_DST_ANY   0x0004   /**< destination is any */
#define SIG_FLAG_SP_ANY    0x0008   /**< source port is any */

#define SIG_FLAG_DP_ANY    0x0010   /**< destination port is any */
#define SIG_FLAG_NOALERT   0x0020   /**< no alert flag is set */
#define SIG_FLAG_IPONLY    0x0040   /**< ip only signature */
#define SIG_FLAG_MPM       0x0080   /**< sig has mpm portion (content, uricontent, etc) */

#define SIG_FLAG_DEONLY    0x0100   /**< decode event only signature */
#define SIG_FLAG_PAYLOAD   0x0200   /**< signature is inspecting the packet payload */
#define SIG_FLAG_DSIZE     0x0400   /**< signature has a dsize setting */
#define SIG_FLAG_FLOW      0x0800   /**< signature has a flow setting */

#define SIG_FLAG_MPM_NEGCONTENT 0x1000  /**< sig has negative mpm portion(!content) */
#define SIG_FLAG_APPLAYER  0x2000   /**< signature applies to app layer instead of packets */
#define SIG_FLAG_BIDIREC   0x4000   /**< signature has bidirectional operator */
#define SIG_FLAG_PACKET    0x8000   /**< signature has matches against a packet (as opposed to app layer) */

/* Detection Engine flags */
#define DE_QUIET           0x01     /**< DE is quiet (esp for unittests) */

typedef struct IPOnlyCIDRItem_ {
    /* address data for this item */
    uint8_t family;
    uint32_t ip[4];
    /* netmask in CIDR values (ex. /16 /18 /24..) */
    uint8_t netmask;

    /* If this host or net is negated for the signum */
    uint8_t negated;
    SigIntId signum; /**< our internal id */

    /* linked list, the header should be the biggest network */
    struct IPOnlyCIDRItem_ *next;

} IPOnlyCIDRItem;

/** \brief Signature container */
typedef struct Signature_ {
    uint16_t flags;

    uint8_t rev;
    int prio;

    uint32_t gid; /**< generator id */
    SigIntId num; /**< signature number, internal id */
    uint32_t id;  /**< sid, set by the 'sid' rule keyword */
    uint8_t nchunk_groups; /**< Internal chunk grp id (for splitted patterns) */
    char *msg;

    /** classification message */
    char *class_msg;

    /** Reference */
    Reference *references;

    /** addresses, ports and proto this sig matches on */
    DetectAddressHead src, dst;
    DetectProto proto;
    DetectPort *sp, *dp;

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *CidrSrc, *CidrDst;

    /** ptr to the SigMatch lists */
    struct SigMatch_ *match; /* non-payload matches */
    struct SigMatch_ *match_tail; /* non-payload matches, tail of the list */
    struct SigMatch_ *pmatch; /* payload matches */
    struct SigMatch_ *pmatch_tail; /* payload matches, tail of the list */
    struct SigMatch_ *umatch; /* uricontent payload matches */
    struct SigMatch_ *umatch_tail; /* uricontent payload matches, tail of the list */
    /** ptr to the next sig in the list */
    struct Signature_ *next;

    /** inline -- action */
    uint8_t action;

    /* helper for init phase */
    uint16_t mpm_content_maxlen;
    uint16_t mpm_uricontent_maxlen;

    /* app layer signature stuff */
    uint8_t alproto;

    /** number of sigmatches in the match and pmatch list */
    uint16_t sm_cnt;
} Signature;

typedef struct DetectEngineIPOnlyThreadCtx_ {
    uint8_t *sig_match_array; /* bit array of sig nums */
    uint32_t sig_match_size;  /* size in bytes of the array */
} DetectEngineIPOnlyThreadCtx;

/** \brief IP only rules matching ctx.
 *  \todo a radix tree would be great here */
typedef struct DetectEngineIPOnlyCtx_ {
    /* lookup hashes */
    HashListTable *ht16_src, *ht16_dst;
    HashListTable *ht24_src, *ht24_dst;

    /* Lookup trees */
    SCRadixTree *tree_ipv4src, *tree_ipv4dst;
    SCRadixTree *tree_ipv6src, *tree_ipv6dst;

    /* Used to build the radix trees */
    IPOnlyCIDRItem *ip_src, *ip_dst;

    /* counters */
    uint32_t a_src_uniq16, a_src_total16;
    uint32_t a_dst_uniq16, a_dst_total16;
    uint32_t a_src_uniq24, a_src_total24;
    uint32_t a_dst_uniq24, a_dst_total24;

    uint32_t max_idx;

    uint8_t *sig_init_array; /* bit array of sig nums */
    uint32_t sig_init_size;  /* size in bytes of the array */

    /* number of sigs in this head */
    uint32_t sig_cnt;
    uint32_t *match_array;
} DetectEngineIPOnlyCtx;

typedef struct DetectEngineLookupFlow_ {
    DetectAddressHead *src_gh[256]; /* a head for each protocol */
    DetectAddressHead *tmp_gh[256];
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

/** \brief threshold ctx */
typedef struct ThresholdCtx_    {
    HashListTable *threshold_hash_table_dst;        /**< Ipv4 dst hash table */
    HashListTable *threshold_hash_table_src;        /**< Ipv4 src hash table */
    HashListTable *threshold_hash_table_dst_ipv6;   /**< Ipv6 dst hash table */
    HashListTable *threshold_hash_table_src_ipv6;   /**< Ipv6 src hash table */
    SCMutex threshold_table_lock;                   /**< Mutex for hash table */
} ThresholdCtx;

/** \brief main detection engine ctx */
typedef struct DetectEngineCtx_ {
    uint8_t flags;
    uint8_t failure_fatal;

    Signature *sig_list;
    uint32_t sig_cnt;

    Signature **sig_array;
    uint32_t sig_array_size; /* size in bytes */
    uint32_t sig_array_len;  /* size in array members */

    uint32_t signum;

    /* used by the signature ordering module */
    struct SCSigOrderFunc_ *sc_sig_order_funcs;
    struct SCSigSignatureWrapper_ *sc_sig_sig_wrapper;

    /* hash table used for holding the classification config info */
    HashTable *class_conf_ht;

    /* main sigs */
    DetectEngineLookupDsize dsize_gh[DSIZE_STATES];

    uint32_t mpm_unique, mpm_reuse, mpm_none,
        mpm_uri_unique, mpm_uri_reuse, mpm_uri_none;
    uint32_t gh_unique, gh_reuse;

    uint32_t mpm_max_patcnt, mpm_min_patcnt, mpm_tot_patcnt,
        mpm_uri_max_patcnt, mpm_uri_min_patcnt, mpm_uri_tot_patcnt;

    /* content and uricontent vars */
    uint32_t content_max_id;
    uint32_t uricontent_max_id;

    /* init phase vars */
    HashListTable *sgh_hash_table;

    HashListTable *sgh_mpm_hash_table;
    HashListTable *sgh_mpm_uri_hash_table;

    HashListTable *sgh_sport_hash_table;
    HashListTable *sgh_dport_hash_table;

    HashListTable *sport_hash_table;
    HashListTable *dport_hash_table;

    HashListTable *variable_names;
    uint16_t variable_names_idx;

    /* memory counters */
    uint32_t mpm_memory_size;

    DetectEngineIPOnlyCtx io_ctx;
    ThresholdCtx ths_ctx;

    uint16_t mpm_matcher; /**< mpm matcher this ctx uses */

#ifdef __SC_CUDA_SUPPORT__
    /* cuda rules content module handle.  Holds the handler serivice's
     * (util-cuda-handler.c) handle for a module.  This module would
     * hold the cuda context for all the rules content */
    int cuda_rc_mod_handle;
#endif

    /* Config options */

    uint16_t max_uniq_toclient_src_groups;
    uint16_t max_uniq_toclient_dst_groups;
    uint16_t max_uniq_toclient_sp_groups;
    uint16_t max_uniq_toclient_dp_groups;

    uint16_t max_uniq_toserver_src_groups;
    uint16_t max_uniq_toserver_dst_groups;
    uint16_t max_uniq_toserver_sp_groups;
    uint16_t max_uniq_toserver_dp_groups;

    uint16_t max_uniq_small_toclient_src_groups;
    uint16_t max_uniq_small_toclient_dst_groups;
    uint16_t max_uniq_small_toclient_sp_groups;
    uint16_t max_uniq_small_toclient_dp_groups;

    uint16_t max_uniq_small_toserver_src_groups;
    uint16_t max_uniq_small_toserver_dst_groups;
    uint16_t max_uniq_small_toserver_sp_groups;
    uint16_t max_uniq_small_toserver_dp_groups;

    HashTable *content_hash;
    uint32_t content_hash_unique;
    uint32_t content_hash_shared;
} DetectEngineCtx;

/* Engine groups profiles (low, medium, high, custom) */
enum {
    ENGINE_PROFILE_UNKNOWN,
    ENGINE_PROFILE_LOW,
    ENGINE_PROFILE_MEDIUM,
    ENGINE_PROFILE_HIGH,
    ENGINE_PROFILE_CUSTOM,
    ENGINE_PROFILE_MAX
};

/**
  * Detection engine thread data.
  */
typedef struct DetectionEngineThreadCtx_ {
    /* the thread to which this detection engine thread belongs */
    ThreadVars *tv;

    /* detection engine variables */

    /** offset into the payload of the last match by:
     *  content, pcre, etc */
    uint32_t payload_offset;

    /** offset into the uri payload of the last match by
     *  uricontent */
    uint32_t uricontent_payload_offset;

    /** recursive counter */
    uint8_t pkt_cnt;

    char de_checking_distancewithin;
    char de_checking_uricontent_distancewithin;

    /* http_uri stuff for uricontent */
    char de_have_httpuri;

    /** pointer to the current mpm ctx that is stored
     *  in a rule group head -- can be either a content
     *  or uricontent ctx. */
    MpmThreadCtx mtc; /**< thread ctx for the mpm */
    MpmThreadCtx mtcu;
    struct SigGroupHead_ *sgh;
    PatternMatcherQueue pmq;

    /* counters */
    uint32_t pkts;
    uint32_t pkts_searched;
    uint32_t pkts_searched1;
    uint32_t pkts_searched2;
    uint32_t pkts_searched3;
    uint32_t pkts_searched4;

    uint32_t uris;
    uint32_t pkts_uri_searched;
    uint32_t pkts_uri_searched1;
    uint32_t pkts_uri_searched2;
    uint32_t pkts_uri_searched3;
    uint32_t pkts_uri_searched4;

    /** id for alert counter */
    uint16_t counter_alerts;

    /** ip only rules ctx */
    DetectEngineIPOnlyThreadCtx io_ctx;

    DetectEngineCtx *de_ctx;

#ifdef __SC_CUDA_SUPPORT__
    /* each detection thread would have it's own queue where the cuda dispatcher
     * thread can dump the packets once it has processed them */
    Tmq *cuda_mpm_rc_disp_outq;
#endif

    uint64_t mpm_match;
    uint64_t mpm_sigs;
    uint64_t mpm_sigsmin25;
    uint64_t mpm_sigsplus100;
    uint64_t mpm_sigsplus1000;
    uint64_t mpm_sigsmax;
} DetectEngineThreadCtx;

/** \brief a single match condition for a signature */
typedef struct SigMatch_ {
    uint16_t idx; /**< position in the signature */
    uint8_t type; /**< match type */
    void *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

/** \brief element in sigmatch type table. */
typedef struct SigTableElmt_ {
    /** Packet match function pointer */
    int (*Match)(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);

    /** AppLayer match function  pointer */
    int (*AppLayerMatch)(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t flags, void *alstate, Signature *, SigMatch *);
    /** app layer proto from app-layer-protos.h this match applies to */
    uint16_t alproto;

    /** keyword setup function pointer */
    int (*Setup)(DetectEngineCtx *, Signature *, char *);

    void (*Free)(void *);
    void (*RegisterTests)(void);

    uint8_t flags;
    char *name;
} SigTableElmt;

#define SIG_GROUP_HAVECONTENT       0x01
#define SIG_GROUP_HAVEURICONTENT    0x02
#define SIG_GROUP_HEAD_MPM_COPY     0x04
#define SIG_GROUP_HEAD_MPM_URI_COPY 0x08
#define SIG_GROUP_HEAD_FREE         0x10
#define SIG_GROUP_HEAD_REFERENCED   0x20 /**< sgh is being referenced by others, don't clear */

typedef struct SigGroupHeadInitData_ {
    /* list of content containers
     * XXX move into a separate data struct
     * with only a ptr to it. Saves some memory
     * after initialization
     */
    uint8_t *content_array;
    uint32_t content_size;
    uint8_t *uri_content_array;
    uint32_t uri_content_size;

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

/** \brief head of the list of containers. */
typedef struct SigGroupHead_ {
    uint8_t flags;

    /* pattern matcher instance */
    MpmCtx *mpm_ctx;
    uint16_t mpm_content_maxlen;
    MpmCtx *mpm_uri_ctx;
    uint16_t mpm_uricontent_maxlen;

    /* number of sigs in this head */
    uint32_t sig_cnt;

    /* "Normal" detection uses these only at init, but ip-only
     * uses it during runtime as well, thus not in init... */
    uint8_t *sig_array; /**< bit array of sig nums (internal id's) */
    uint32_t sig_size; /**< size in bytes */

    /* Array with sig nums... size is sig_cnt * sizeof(SigIntId) */
    SigIntId *match_array;

    /* ptr to our init data we only use at... init :) */
    SigGroupHeadInitData *init;
} SigGroupHead;

/** sigmatch has no options, so the parser shouldn't expect any */
#define SIGMATCH_NOOPT          0x01
/** sigmatch is compatible with a ip only rule */
#define SIGMATCH_IPONLY_COMPAT  0x02
/** sigmatch is compatible with a decode event only rule */
#define SIGMATCH_DEONLY_COMPAT  0x04
/**< Flag to indicate that the signature inspects the packet payload */
#define SIGMATCH_PAYLOAD        0x08

/** Remember to add the options in SignatureIsIPOnly() at detect.c otherwise it wont be part of a signature group */

enum {
    DETECT_SID,
    DETECT_PRIORITY,
    DETECT_REV,
    DETECT_CLASSTYPE,
    DETECT_THRESHOLD,
    DETECT_METADATA,
    DETECT_REFERENCE,
    DETECT_TAG,
    DETECT_MSG,
    DETECT_CONTENT,
    DETECT_URICONTENT,
    DETECT_PCRE,
    DETECT_PCRE_HTTPBODY,
    DETECT_ACK,
    DETECT_SEQ,
    DETECT_DEPTH,
    DETECT_DISTANCE,
    DETECT_WITHIN,
    DETECT_OFFSET,
    DETECT_NOCASE,
    DETECT_FAST_PATTERN,
    DETECT_RECURSIVE,
    DETECT_RAWBYTES,
    DETECT_BYTETEST,
    DETECT_BYTEJUMP,
    DETECT_SAMEIP,
    DETECT_IPPROTO,
    DETECT_FLOW,
    DETECT_WINDOW,
    DETECT_FTPBOUNCE,
    DETECT_ISDATAAT,
    DETECT_ID,
    DETECT_RPC,
    DETECT_DSIZE,
    DETECT_FLOWVAR,
    DETECT_FLOWINT,
    DETECT_PKTVAR,
    DETECT_NOALERT,
    DETECT_FLOWBITS,
    DETECT_FLOWALERTSID,
    DETECT_IPV4_CSUM,
    DETECT_TCPV4_CSUM,
    DETECT_TCPV6_CSUM,
    DETECT_UDPV4_CSUM,
    DETECT_UDPV6_CSUM,
    DETECT_ICMPV4_CSUM,
    DETECT_ICMPV6_CSUM,
    DETECT_STREAM_SIZE,
    DETECT_TTL,
    DETECT_ITYPE,
    DETECT_ICODE,
    DETECT_ICMP_ID,
    DETECT_ICMP_SEQ,
    DETECT_DETECTION_FILTER,

    DETECT_ADDRESS,
    DETECT_PROTO,
    DETECT_PORT,
    DETECT_DECODE_EVENT,
    DETECT_IPOPTS,
    DETECT_FLAGS,
    DETECT_FRAGBITS,
    DETECT_FRAGOFFSET,
    DETECT_GID,

    DETECT_AL_TLS_VERSION,
    DETECT_AL_HTTP_COOKIE,
    DETECT_AL_HTTP_METHOD,
    DETECT_AL_URILEN,
    DETECT_AL_HTTP_CLIENT_BODY,

    DETECT_DCE_IFACE,
    DETECT_DCE_OPNUM,
    DETECT_DCE_STUB_DATA,

    /* make sure this stays last */
    DETECT_TBLSIZE,
};

/* Table with all SigMatch registrations */
SigTableElmt sigmatch_table[DETECT_TBLSIZE];

/* detection api */
SigMatch *SigMatchAlloc(void);
Signature *SigFindSignatureBySidGid(DetectEngineCtx *, uint32_t, uint32_t);
void SigMatchFree(SigMatch *sm);
void SigCleanSignatures(DetectEngineCtx *);

void SigTableRegisterTests(void);
void SigRegisterTests(void);
void TmModuleDetectRegister (void);

int SigGroupBuild(DetectEngineCtx *);
int SigGroupCleanup();
void SigAddressPrepareBidirectionals (DetectEngineCtx *);

int PacketAlertAppend(DetectEngineThreadCtx *, Signature *s, Packet *);

int SigLoadSignatures (DetectEngineCtx *, char *);
void SigTableSetup(void);
int PacketAlertCheck(Packet *p, uint32_t sid);
int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);

int PacketAlertCheck(Packet *p, uint32_t sid);
int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);
int SignatureIsIPOnly(DetectEngineCtx *de_ctx, Signature *s);

#endif /* __DETECT_H__ */

