/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __DETECT_H__
#define __DETECT_H__

#include "suricata-common.h"

#include "flow.h"

#include "detect-engine-proto.h"
#include "detect-reference.h"
#include "detect-metadata.h"
#include "detect-engine-register.h"
#include "packet-queue.h"

#include "util-prefilter.h"
#include "util-mpm.h"
#include "util-spm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-radix-tree.h"
#include "util-file.h"
#include "reputation.h"

#include "detect-mark.h"

#include "stream.h"

#include "util-var-name.h"

#include "app-layer-events.h"

#define DETECT_MAX_RULE_SIZE 8192

#define DETECT_TRANSFORMS_MAX 16

/** default rule priority if not set through priority keyword or via
 *  classtype. */
#define DETECT_DEFAULT_PRIO 3

/* forward declarations for the structures from detect-engine-sigorder.h */
struct SCSigOrderFunc_;
struct SCSigSignatureWrapper_;

/*
  The detection engine groups similar signatures/rules together. Internally a
  tree of different types of data is created on initialization. This is it's
  global layout:

   For TCP/UDP

   - Flow direction
   -- Protocol
   -=- Dst port

   For the other protocols

   - Flow direction
   -- Protocol
*/

/* holds the values for different possible lists in struct Signature.
 * These codes are access points to particular lists in the array
 * Signature->sm_lists[DETECT_SM_LIST_MAX]. */
enum DetectSigmatchListEnum {
    DETECT_SM_LIST_MATCH = 0,
    DETECT_SM_LIST_PMATCH,

    /* base64_data keyword uses some hardcoded logic so consider
     * built-in
     * TODO convert to inspect engine */
    DETECT_SM_LIST_BASE64_DATA,

    /* list for post match actions: flowbit set, flowint increment, etc */
    DETECT_SM_LIST_POSTMATCH,

    DETECT_SM_LIST_TMATCH, /**< post-detection tagging */

    /* lists for alert thresholding and suppression */
    DETECT_SM_LIST_SUPPRESS,
    DETECT_SM_LIST_THRESHOLD,

    DETECT_SM_LIST_MAX,

    /* start of dynamically registered lists */
    DETECT_SM_LIST_DYNAMIC_START = DETECT_SM_LIST_MAX,
};

/* used for Signature->list, which indicates which list
 * we're adding keywords to in cases of sticky buffers like
 * file_data */
#define DETECT_SM_LIST_NOTSET INT_MAX

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

#define ADDRESS_FLAG_NOT            0x01 /**< address is negated */

/** \brief address structure for use in the detection engine.
 *
 *  Contains the address information and matching information.
 */
typedef struct DetectAddress_ {
    /** address data for this group */
    Address ip;
    Address ip2;

    /** flags affecting this address */
    uint8_t flags;

    /** ptr to the previous address in the list */
    struct DetectAddress_ *prev;
    /** ptr to the next address in the list */
    struct DetectAddress_ *next;
} DetectAddress;

/** Address grouping head. IPv4 and IPv6 are split out */
typedef struct DetectAddressHead_ {
    DetectAddress *ipv4_head;
    DetectAddress *ipv6_head;
} DetectAddressHead;


typedef struct DetectMatchAddressIPv4_ {
    uint32_t ip;    /**< address in host order, start of range */
    uint32_t ip2;   /**< address in host order, end of range */
} DetectMatchAddressIPv4;

typedef struct DetectMatchAddressIPv6_ {
    uint32_t ip[4];
    uint32_t ip2[4];
} DetectMatchAddressIPv6;

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

/** \brief Port structure for detection engine */
typedef struct DetectPort_ {
    uint16_t port;
    uint16_t port2;

    uint8_t flags;  /**< flags for this port */

    /* signatures that belong in this group
     *
     * If the PORT_SIGGROUPHEAD_COPY flag is set, we don't own this pointer
     * (memory is freed elsewhere).
     */
    struct SigGroupHead_ *sh;

    struct DetectPort_ *prev;
    struct DetectPort_ *next;
} DetectPort;

/* Signature flags */
/** \note: additions should be added to the rule analyzer as well */

#define SIG_FLAG_SRC_ANY                BIT_U32(0)  /**< source is any */
#define SIG_FLAG_DST_ANY                BIT_U32(1)  /**< destination is any */
#define SIG_FLAG_SP_ANY                 BIT_U32(2)  /**< source port is any */
#define SIG_FLAG_DP_ANY                 BIT_U32(3)  /**< destination port is any */

#define SIG_FLAG_NOALERT                BIT_U32(4)  /**< no alert flag is set */
#define SIG_FLAG_DSIZE                  BIT_U32(5)  /**< signature has a dsize setting */
#define SIG_FLAG_APPLAYER               BIT_U32(6)  /**< signature applies to app layer instead of packets */
#define SIG_FLAG_IPONLY                 BIT_U32(7)  /**< ip only signature */
#define SIG_FLAG_LIKE_IPONLY                                                                       \
    BIT_U32(8) /**< signature that is almost ip only, but contains negation prevening some iponly  \
                  optimizations */

// vacancy

#define SIG_FLAG_REQUIRE_PACKET         BIT_U32(9)  /**< signature is requiring packet match */
#define SIG_FLAG_REQUIRE_STREAM         BIT_U32(10) /**< signature is requiring stream match */

#define SIG_FLAG_MPM_NEG                BIT_U32(11)

#define SIG_FLAG_FLUSH                  BIT_U32(12) /**< detection logic needs stream flush notification */

// vacancies

#define SIG_FLAG_REQUIRE_FLOWVAR        BIT_U32(17) /**< signature can only match if a flowbit, flowvar or flowint is available. */

#define SIG_FLAG_FILESTORE              BIT_U32(18) /**< signature has filestore keyword */

#define SIG_FLAG_TOSERVER               BIT_U32(19)
#define SIG_FLAG_TOCLIENT               BIT_U32(20)

#define SIG_FLAG_TLSSTORE               BIT_U32(21)

#define SIG_FLAG_BYPASS                 BIT_U32(22)

#define SIG_FLAG_PREFILTER              BIT_U32(23) /**< sig is part of a prefilter engine */

/** Proto detect only signature.
 *  Inspected once per direction when protocol detection is done. */
#define SIG_FLAG_PDONLY                 BIT_U32(24)
/** Info for Source and Target identification */
#define SIG_FLAG_SRC_IS_TARGET          BIT_U32(25)
/** Info for Source and Target identification */
#define SIG_FLAG_DEST_IS_TARGET         BIT_U32(26)

#define SIG_FLAG_HAS_TARGET             (SIG_FLAG_DEST_IS_TARGET|SIG_FLAG_SRC_IS_TARGET)

/* signature init flags */
#define SIG_FLAG_INIT_DEONLY                BIT_U32(0)  /**< decode event only signature */
#define SIG_FLAG_INIT_PACKET                BIT_U32(1)  /**< signature has matches against a packet (as opposed to app layer) */
#define SIG_FLAG_INIT_FLOW                  BIT_U32(2)  /**< signature has a flow setting */
#define SIG_FLAG_INIT_BIDIREC               BIT_U32(3)  /**< signature has bidirectional operator */
#define SIG_FLAG_INIT_FIRST_IPPROTO_SEEN    BIT_U32(4)  /** < signature has seen the first ip_proto keyword */
#define SIG_FLAG_INIT_HAS_TRANSFORM         BIT_U32(5)
#define SIG_FLAG_INIT_STATE_MATCH           BIT_U32(6)  /**< signature has matches that require stateful inspection */
#define SIG_FLAG_INIT_NEED_FLUSH            BIT_U32(7)
#define SIG_FLAG_INIT_PRIO_EXPLICT          BIT_U32(8)  /**< priority is explicitly set by the priority keyword */
#define SIG_FLAG_INIT_FILEDATA              BIT_U32(9)  /**< signature has filedata keyword */

/* signature mask flags */
/** \note: additions should be added to the rule analyzer as well */
#define SIG_MASK_REQUIRE_PAYLOAD            BIT_U8(0)
#define SIG_MASK_REQUIRE_FLOW               BIT_U8(1)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   BIT_U8(2)    /* SYN, FIN, RST */
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      BIT_U8(3)    /* URG, ECN, CWR */
#define SIG_MASK_REQUIRE_NO_PAYLOAD         BIT_U8(4)
#define SIG_MASK_REQUIRE_DCERPC             BIT_U8(5)    /* require either SMB+DCE or raw DCE */
// vacancy
#define SIG_MASK_REQUIRE_ENGINE_EVENT       BIT_U8(7)

/* for now a uint8_t is enough */
#define SignatureMask uint8_t

#define DETECT_ENGINE_THREAD_CTX_FRAME_ID_SET         0x0001
#define DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH 0x0004

#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_MAGIC         0x04    /**< need the start of the file */
#define FILE_SIG_NEED_FILECONTENT   0x08
#define FILE_SIG_NEED_MD5           0x10
#define FILE_SIG_NEED_SHA1          0x20
#define FILE_SIG_NEED_SHA256        0x40
#define FILE_SIG_NEED_SIZE          0x80

/* Detection Engine flags */
#define DE_QUIET           0x01     /**< DE is quiet (esp for unittests) */

typedef struct IPOnlyCIDRItem_ {
    /* address data for this item */
    uint8_t family;
    /* netmask in CIDR values (ex. /16 /18 /24..) */
    uint8_t netmask;
    /* If this host or net is negated for the signum */
    uint8_t negated;

    uint32_t ip[4];
    SigIntId signum; /**< our internal id */

    /* linked list, the header should be the biggest network */
    struct IPOnlyCIDRItem_ *next;

} IPOnlyCIDRItem;

/** \brief Used to start a pointer to SigMatch context
 * Should never be dereferenced without casting to something else.
 */
typedef struct SigMatchCtx_ {
    int foo;
} SigMatchCtx;

/** \brief a single match condition for a signature */
typedef struct SigMatch_ {
    uint16_t type; /**< match type */
    uint16_t idx; /**< position in the signature */
    SigMatchCtx *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

/** \brief Data needed for Match() */
typedef struct SigMatchData_ {
    uint16_t type;   /**< match type */
    uint8_t is_last; /**< Last element of the list */
    SigMatchCtx *ctx; /**< plugin specific data */
} SigMatchData;

struct DetectEngineThreadCtx_;// DetectEngineThreadCtx;

/* inspection buffer is a simple structure that is passed between prefilter,
 * transformation functions and inspection functions.
 * Initially setup with 'orig' ptr and len, transformations can then take
 * then and fill the 'buf'. Multiple transformations can update the buffer,
 * both growing and shrinking it.
 * Prefilter and inspection will only deal with 'inspect'. */

typedef struct InspectionBuffer {
    const uint8_t *inspect; /**< active pointer, points either to ::buf or ::orig */
    uint64_t inspect_offset;
    uint32_t inspect_len;   /**< size of active data. See to ::len or ::orig_len */
    uint8_t flags;          /**< DETECT_CI_FLAGS_* for use with DetectEngineContentInspection */
#ifdef DEBUG_VALIDATION
    bool multi;
#endif
    uint32_t len;           /**< how much is in use */
    uint8_t *buf;
    uint32_t size;          /**< size of the memory allocation */

    uint32_t orig_len;
    const uint8_t *orig;
} InspectionBuffer;

/* inspection buffers are kept per tx (in det_ctx), but some protocols
 * need a bit more. A single TX might have multiple buffers, e.g. files in
 * SMTP or DNS queries. Since all prefilters+transforms run before the
 * individual rules need the same buffers, we need a place to store the
 * transformed data. This array of arrays is that place. */

typedef struct InspectionBufferMultipleForList {
    InspectionBuffer *inspection_buffers;
    uint32_t size;      /**< size in number of elements */
    uint32_t max:31;    /**< max id in use in this run */
    uint32_t init:1;    /**< first time used this run. Used for clean logic */
} InspectionBufferMultipleForList;

typedef struct TransformData_ {
    int transform;
    void *options;
} TransformData;

typedef struct DetectEngineTransforms {
    TransformData transforms[DETECT_TRANSFORMS_MAX];
    uint8_t cnt;
} DetectEngineTransforms;

/** callback for getting the buffer we need to prefilter/inspect */
typedef InspectionBuffer *(*InspectionBufferGetDataPtr)(
        struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);
struct DetectEngineAppInspectionEngine_;

typedef uint8_t (*InspectEngineFuncPtr2)(struct DetectEngineCtx_ *de_ctx,
        struct DetectEngineThreadCtx_ *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const struct Signature_ *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

typedef struct DetectEngineAppInspectionEngine_ {
    AppProto alproto;
    uint8_t dir;
    uint8_t id;     /**< per sig id used in state keeping */
    bool mpm;
    bool stream;
    uint16_t sm_list;
    uint16_t sm_list_base; /**< base buffer being transformed */
    int16_t progress;

    struct {
        InspectionBufferGetDataPtr GetData;
        InspectEngineFuncPtr2 Callback;
        /** pointer to the transforms in the 'DetectBuffer entry for this list */
        const DetectEngineTransforms *transforms;
    } v2;

    SigMatchData *smd;

    struct DetectEngineAppInspectionEngine_ *next;
} DetectEngineAppInspectionEngine;

typedef struct DetectBufferType_ {
    char name[32];
    char description[128];
    int id;
    int parent_id;
    bool mpm;
    bool packet; /**< compat to packet matches */
    bool frame;  /**< is about Frame inspection */
    bool supports_transforms;
    void (*SetupCallback)(const struct DetectEngineCtx_ *, struct Signature_ *);
    bool (*ValidateCallback)(const struct Signature_ *, const char **sigerror);
    DetectEngineTransforms transforms;
} DetectBufferType;

struct DetectEnginePktInspectionEngine;

/**
 *  \param alert_flags[out] for setting PACKET_ALERT_FLAG_*
 */
typedef int (*InspectionBufferPktInspectFunc)(
        struct DetectEngineThreadCtx_ *,
        const struct DetectEnginePktInspectionEngine *engine,
        const struct Signature_ *s,
        Packet *p, uint8_t *alert_flags);

/** callback for getting the buffer we need to prefilter/inspect */
typedef InspectionBuffer *(*InspectionBufferGetPktDataPtr)(
        struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms,
        Packet *p, const int list_id);

typedef struct DetectEnginePktInspectionEngine {
    SigMatchData *smd;
    bool mpm;
    uint16_t sm_list;
    uint16_t sm_list_base;
    struct {
        InspectionBufferGetPktDataPtr GetData;
        InspectionBufferPktInspectFunc Callback;
        /** pointer to the transforms in the 'DetectBuffer entry for this list */
        const DetectEngineTransforms *transforms;
    } v1;
    struct DetectEnginePktInspectionEngine *next;
} DetectEnginePktInspectionEngine;

struct Frame;
struct Frames;
struct DetectEngineFrameInspectionEngine;

/**
 *  \param alert_flags[out] for setting PACKET_ALERT_FLAG_*
 */
typedef int (*InspectionBufferFrameInspectFunc)(struct DetectEngineThreadCtx_ *,
        const struct DetectEngineFrameInspectionEngine *engine, const struct Signature_ *s,
        Packet *p, const struct Frames *frames, const struct Frame *frame, const uint32_t idx);

typedef struct DetectEngineFrameInspectionEngine {
    AppProto alproto;
    uint8_t dir;
    uint8_t type;
    bool mpm;
    uint16_t sm_list;
    uint16_t sm_list_base;
    struct {
        InspectionBufferFrameInspectFunc Callback;
        /** pointer to the transforms in the 'DetectBuffer entry for this list */
        const DetectEngineTransforms *transforms;
    } v1;
    SigMatchData *smd;
    struct DetectEngineFrameInspectionEngine *next;
} DetectEngineFrameInspectionEngine;

#ifdef UNITTESTS
#define sm_lists init_data->smlists
#define sm_lists_tail init_data->smlists_tail
#endif

typedef struct SignatureInitData_ {
    /** Number of sigmatches. Used for assigning SigMatch::idx */
    uint16_t sm_cnt;

    /** option was prefixed with '!'. Only set for sigmatches that
     *  have the SIGMATCH_HANDLE_NEGATION flag set. */
    bool negated;

    /* track if we saw any negation in the addresses. If so, we
     * skip it for ip-only */
    bool src_contains_negation;
    bool dst_contains_negation;

    /* used to hold flags that are used during init */
    uint32_t init_flags;
    /* coccinelle: SignatureInitData:init_flags:SIG_FLAG_INIT_ */

    /* used at init to determine max dsize */
    SigMatch *dsize_sm;

    /* list id for `mpm_sm`. Should always match `SigMatchListSMBelongsTo(s, mpm_sm)`. */
    int mpm_sm_list;
    /* the fast pattern added from this signature */
    SigMatch *mpm_sm;
    /* used to speed up init of prefilter */
    SigMatch *prefilter_sm;

    /* SigMatch list used for adding content and friends. E.g. file_data; */
    int list;
    bool list_set;

    DetectEngineTransforms transforms;

    /** score to influence rule grouping. A higher value leads to a higher
     *  likelihood of a rulegroup with this sig ending up as a contained
     *  group. */
    int whitelist;

    /** address settings for this signature */
    const DetectAddressHead *src, *dst;

    int prefilter_list;

    uint32_t smlists_array_size;
    /* holds all sm lists */
    struct SigMatch_ **smlists;
    /* holds all sm lists' tails */
    struct SigMatch_ **smlists_tail;
} SignatureInitData;

/** \brief Signature container */
typedef struct Signature_ {
    uint32_t flags;
    /* coccinelle: Signature:flags:SIG_FLAG_ */

    AppProto alproto;

    uint16_t dsize_low;
    uint16_t dsize_high;
    uint8_t dsize_mode;

    SignatureMask mask;
    SigIntId num; /**< signature number, internal id */

    /** inline -- action */
    uint8_t action;
    uint8_t file_flags;

    /** addresses, ports and proto this sig matches on */
    DetectProto proto;

    /** classification id **/
    uint16_t class_id;

    /** ipv4 match arrays */
    uint16_t addr_dst_match4_cnt;
    uint16_t addr_src_match4_cnt;
    uint16_t addr_dst_match6_cnt;
    uint16_t addr_src_match6_cnt;
    DetectMatchAddressIPv4 *addr_dst_match4;
    DetectMatchAddressIPv4 *addr_src_match4;
    /** ipv6 match arrays */
    DetectMatchAddressIPv6 *addr_dst_match6;
    DetectMatchAddressIPv6 *addr_src_match6;

    uint32_t id;  /**< sid, set by the 'sid' rule keyword */
    uint32_t gid; /**< generator id */
    uint32_t rev;
    int prio;

    /** port settings for this signature */
    DetectPort *sp, *dp;

#ifdef PROFILING
    uint16_t profiling_id;
#endif

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *cidr_src, *cidr_dst;

    DetectEngineAppInspectionEngine *app_inspect;
    DetectEnginePktInspectionEngine *pkt_inspect;
    DetectEngineFrameInspectionEngine *frame_inspect;

    /* Matching structures for the built-ins. The others are in
     * their inspect engines. */
    SigMatchData *sm_arrays[DETECT_SM_LIST_MAX];

    /* memory is still owned by the sm_lists/sm_arrays entry */
    const struct DetectFilestoreData_ *filestore_ctx;

    char *msg;

    /** classification message */
    char *class_msg;
    /** Reference */
    DetectReference *references;
    /** Metadata */
    DetectMetadataHead *metadata;

    char *sig_str;

    SignatureInitData *init_data;

    /** ptr to the next sig in the list */
    struct Signature_ *next;
} Signature;

enum DetectBufferMpmType {
    DETECT_BUFFER_MPM_TYPE_PKT,
    DETECT_BUFFER_MPM_TYPE_APP,
    DETECT_BUFFER_MPM_TYPE_FRAME,
    /* must be last */
    DETECT_BUFFER_MPM_TYPE_SIZE,
};

/** \brief one time registration of keywords at start up */
typedef struct DetectBufferMpmRegistery_ {
    const char *name;
    char pname[32];             /**< name used in profiling */
    int direction;              /**< SIG_FLAG_TOSERVER or SIG_FLAG_TOCLIENT */
    int16_t sm_list;
    int16_t sm_list_base;
    int priority;
    int id;                     /**< index into this array and result arrays */
    enum DetectBufferMpmType type;
    int sgh_mpm_context;

    int (*PrefilterRegisterWithListId)(struct DetectEngineCtx_ *de_ctx,
            struct SigGroupHead_ *sgh, MpmCtx *mpm_ctx,
            const struct DetectBufferMpmRegistery_ *mpm_reg, int list_id);
    DetectEngineTransforms transforms;

    union {
        /* app-layer matching: use if type == DETECT_BUFFER_MPM_TYPE_APP */
        struct {
            InspectionBufferGetDataPtr GetData;
            AppProto alproto;
            int tx_min_progress;
        } app_v2;

        /* pkt matching: use if type == DETECT_BUFFER_MPM_TYPE_PKT */
        struct {
            int (*PrefilterRegisterWithListId)(struct DetectEngineCtx_ *de_ctx,
                    struct SigGroupHead_ *sgh, MpmCtx *mpm_ctx,
                    const struct DetectBufferMpmRegistery_ *mpm_reg, int list_id);
            InspectionBufferGetPktDataPtr GetData;
        } pkt_v1;

        /* frame matching: use if type == DETECT_BUFFER_MPM_TYPE_FRAME */
        struct {
            AppProto alproto;
            uint8_t type;
        } frame_v1;
    };

    struct DetectBufferMpmRegistery_ *next;
} DetectBufferMpmRegistery;

/* helper structure to track pattern stats and assign pattern id's. */
typedef struct DetectPatternTracker {
    const struct DetectContentData_ *cd;
    int sm_list;
    uint32_t cnt;
    uint32_t mpm;
} DetectPatternTracker;

typedef struct DetectReplaceList_ {
    struct DetectContentData_ *cd;
    uint8_t *found;
    struct DetectReplaceList_ *next;
} DetectReplaceList;

/** only execute flowvar storage if rule matched */
#define DETECT_VAR_TYPE_FLOW_POSTMATCH      1
#define DETECT_VAR_TYPE_PKT_POSTMATCH       2

/** list for flowvar store candidates, to be stored from
 *  post-match function */
typedef struct DetectVarList_ {
    uint32_t idx;                       /**< flowvar name idx */
    uint16_t len;                       /**< data len */
    uint16_t key_len;
    int type;                           /**< type of store candidate POSTMATCH or ALWAYS */
    uint8_t *key;
    uint8_t *buffer;                    /**< alloc'd buffer, may be freed by
                                             post-match, post-non-match */
    struct DetectVarList_ *next;
} DetectVarList;

typedef struct SCFPSupportSMList_ {
    int list_id;
    int priority;
    struct SCFPSupportSMList_ *next;
} SCFPSupportSMList;

typedef struct DetectEngineIPOnlyThreadCtx_ {
    uint8_t *sig_match_array; /* bit array of sig nums */
    uint32_t sig_match_size;  /* size in bytes of the array */
} DetectEngineIPOnlyThreadCtx;

/** \brief IP only rules matching ctx. */
typedef struct DetectEngineIPOnlyCtx_ {
    /* Lookup trees */
    SCRadixTree *tree_ipv4src, *tree_ipv4dst;
    SCRadixTree *tree_ipv6src, *tree_ipv6dst;

    /* Used to build the radix trees */
    IPOnlyCIDRItem *ip_src, *ip_dst;
    uint32_t max_idx;
} DetectEngineIPOnlyCtx;

typedef struct DetectEngineLookupFlow_ {
    DetectPort *tcp;
    DetectPort *udp;
    struct SigGroupHead_ *sgh[256];
} DetectEngineLookupFlow;

#include "detect-threshold.h"

/** \brief threshold ctx */
typedef struct ThresholdCtx_    {
    SCMutex threshold_table_lock;                   /**< Mutex for hash table */

    /** to support rate_filter "by_rule" option */
    DetectThresholdEntry **th_entry;
    uint32_t th_size;
} ThresholdCtx;

typedef struct SigString_ {
    char *filename;
    char *sig_str;
    char *sig_error;
    int line;
    TAILQ_ENTRY(SigString_) next;
} SigString;

/** \brief Signature loader statistics */
typedef struct SigFileLoaderStat_ {
    TAILQ_HEAD(, SigString_) failed_sigs;
    int bad_files;
    int total_files;
    int good_sigs_total;
    int bad_sigs_total;
} SigFileLoaderStat;

typedef struct DetectEngineThreadKeywordCtxItem_ {
    void *(*InitFunc)(void *);
    void (*FreeFunc)(void *);
    void *data;
    struct DetectEngineThreadKeywordCtxItem_ *next;
    int id;
    const char *name; /* keyword name, for error printing */
} DetectEngineThreadKeywordCtxItem;

enum DetectEnginePrefilterSetting
{
    DETECT_PREFILTER_MPM = 0,   /**< use only mpm / fast_pattern */
    DETECT_PREFILTER_AUTO = 1,  /**< use mpm + keyword prefilters */
};

enum DetectEngineType
{
    DETECT_ENGINE_TYPE_NORMAL = 0,
    DETECT_ENGINE_TYPE_DD_STUB = 1, /* delayed detect stub: can be reloaded */
    DETECT_ENGINE_TYPE_MT_STUB = 2, /* multi-tenant stub: cannot be reloaded */
    DETECT_ENGINE_TYPE_TENANT = 3,
};

/* Flow states:
 *  toserver
 *  toclient
 */
#define FLOW_STATES 2

/** \brief main detection engine ctx */
typedef struct DetectEngineCtx_ {
    uint8_t flags;
    int failure_fatal;

    int tenant_id;

    Signature *sig_list;
    uint32_t sig_cnt;

    /* version of the srep data */
    uint32_t srep_version;

    /* reputation for netblocks */
    SRepCIDRTree *srepCIDR_ctx;

    Signature **sig_array;
    uint32_t sig_array_size; /* size in bytes */
    uint32_t sig_array_len;  /* size in array members */

    uint32_t signum;

    /** Maximum value of all our sgh's non_mpm_store_cnt setting,
     *  used to alloc det_ctx::non_mpm_id_array */
    uint32_t non_pf_store_cnt_max;

    /* used by the signature ordering module */
    struct SCSigOrderFunc_ *sc_sig_order_funcs;

    /* hash table used for holding the classification config info */
    HashTable *class_conf_ht;
    /* hash table used for holding the reference config info */
    HashTable *reference_conf_ht;

    /* main sigs */
    DetectEngineLookupFlow flow_gh[FLOW_STATES];

    uint32_t gh_unique, gh_reuse;

    /* init phase vars */
    HashListTable *sgh_hash_table;

    HashListTable *mpm_hash_table;
    HashListTable *pattern_hash_table;

    /* hash table used to cull out duplicate sigs */
    HashListTable *dup_sig_hash_table;

    DetectEngineIPOnlyCtx io_ctx;
    ThresholdCtx ths_ctx;

    uint8_t mpm_matcher;  /**< mpm matcher this ctx uses */
    uint16_t spm_matcher; /**< spm matcher this ctx uses */

    /* spm thread context prototype, built as spm matchers are constructed and
     * later used to construct thread context for each thread. */
    SpmGlobalThreadCtx *spm_global_thread_ctx;

    /* Config options */

    uint16_t max_uniq_toclient_groups;
    uint16_t max_uniq_toserver_groups;

    /* specify the configuration for mpm context factory */
    uint8_t sgh_mpm_ctx_cnf;

    /* max flowbit id that is used */
    uint32_t max_fb_id;

    uint32_t max_fp_id;

    MpmCtxFactoryContainer *mpm_ctx_factory_container;

    /* maximum recursion depth for content inspection */
    int inspection_recursion_limit;

    /* conf parameter that limits the length of the http request body inspected */
    int hcbd_buffer_limit;
    /* conf parameter that limits the length of the http response body inspected */
    int hsbd_buffer_limit;

    /* array containing all sgh's in use so we can loop
     * through it in Stage4. */
    struct SigGroupHead_ **sgh_array;
    uint32_t sgh_array_cnt;
    uint32_t sgh_array_size;

    int32_t sgh_mpm_context_proto_tcp_packet;
    int32_t sgh_mpm_context_proto_udp_packet;
    int32_t sgh_mpm_context_proto_other_packet;
    int32_t sgh_mpm_context_stream;

    /* the max local id used amongst all sigs */
    int32_t byte_extract_max_local_id;

    /** version of the detect engine. The version is incremented on reloads */
    uint32_t version;

    /** sgh for signatures that match against invalid packets. In those cases
     *  we can't lookup by proto, address, port as we don't have these */
    struct SigGroupHead_ *decoder_event_sgh;

    /* Maximum size of the buffer for decoded base64 data. */
    uint32_t base64_decode_max_len;

    /** Store rule file and line so that parsers can use them in errors. */
    char *rule_file;
    int rule_line;
    bool sigerror_silent;
    bool sigerror_ok;
    const char *sigerror;

    /** hash list of keywords that need thread local ctxs */
    HashListTable *keyword_hash;
    int keyword_id;

    struct {
        uint32_t content_limit;
        uint32_t content_inspect_min_size;
        uint32_t content_inspect_window;
    } filedata_config[ALPROTO_MAX];
    bool filedata_config_initialized;

#ifdef PROFILING
    struct SCProfileDetectCtx_ *profile_ctx;
    struct SCProfileKeywordDetectCtx_ *profile_keyword_ctx;
    struct SCProfilePrefilterDetectCtx_ *profile_prefilter_ctx;
    struct SCProfileKeywordDetectCtx_ **profile_keyword_ctx_per_list;
    struct SCProfileSghDetectCtx_ *profile_sgh_ctx;
    uint32_t profile_match_logging_threshold;
#endif
    uint32_t prefilter_maxid;

    char config_prefix[64];

    enum DetectEngineType type;

    /** how many de_ctx' are referencing this */
    uint32_t ref_cnt;
    /** list in master: either active or freelist */
    struct DetectEngineCtx_ *next;

    /** id of loader thread 'owning' this de_ctx */
    int loader_id;

    /** are we using just mpm or also other prefilters */
    enum DetectEnginePrefilterSetting prefilter_setting;

    HashListTable *dport_hash_table;

    DetectPort *tcp_whitelist;
    DetectPort *udp_whitelist;

    /** table for storing the string representation with the parsers result */
    HashListTable *address_table;

    /** table to store metadata keys and values */
    HashTable *metadata_table;

    /* hash tables with rule-time buffer registration. Start time registration
     * is in detect-engine.c::g_buffer_type_hash */
    HashListTable *buffer_type_hash_name;
    HashListTable *buffer_type_hash_id;
    uint32_t buffer_type_id;

    /* list with app inspect engines. Both the start-time registered ones and
     * the rule-time registered ones. */
    DetectEngineAppInspectionEngine *app_inspect_engines;
    DetectBufferMpmRegistery *app_mpms_list;
    uint32_t app_mpms_list_cnt;
    DetectEnginePktInspectionEngine *pkt_inspect_engines;
    DetectBufferMpmRegistery *pkt_mpms_list;
    uint32_t pkt_mpms_list_cnt;
    DetectEngineFrameInspectionEngine *frame_inspect_engines;
    DetectBufferMpmRegistery *frame_mpms_list;
    uint32_t frame_mpms_list_cnt;

    uint32_t prefilter_id;
    HashListTable *prefilter_hash_table;

    /** time of last ruleset reload */
    struct timeval last_reload;

    /** signatures stats */
    SigFileLoaderStat sig_stat;

    /** per keyword flag indicating if a prefilter has been
     *  set for it. If true, the setup function will have to
     *  run. */
    bool sm_types_prefilter[DETECT_TBLSIZE];
    bool sm_types_silent_error[DETECT_TBLSIZE];

    /* list of Fast Pattern registrations. Initially filled using a copy of
     * `g_fp_support_smlist_list`, then extended at rule loading time if needed */
    SCFPSupportSMList *fp_support_smlist_list;
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

/* Siggroup mpm context profile */
enum {
    ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL = 0,
    ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE,
    ENGINE_SGH_MPM_FACTORY_CONTEXT_AUTO,
#define ENGINE_SGH_MPM_FACTORY_CONTEXT_START_ID_RANGE (ENGINE_SGH_MPM_FACTORY_CONTEXT_AUTO + 1)
};

typedef struct HttpReassembledBody_ {
    const uint8_t *buffer;
    uint8_t *decompressed_buffer;
    uint32_t buffer_size;   /**< size of the buffer itself */
    uint32_t buffer_len;    /**< data len in the buffer */
    uint32_t decompressed_buffer_len;
    uint64_t offset;        /**< data offset */
} HttpReassembledBody;

#define DETECT_FILESTORE_MAX 15

typedef struct SignatureNonPrefilterStore_ {
    SigIntId id;
    SignatureMask mask;
    AppProto alproto;
} SignatureNonPrefilterStore;

/** array of TX inspect rule candidates */
typedef struct RuleMatchCandidateTx {
    SigIntId id;            /**< internal signature id */
    uint32_t *flags;        /**< inspect flags ptr */
    union {
        struct {
            bool stream_stored;
            uint8_t stream_result;
        };
        uint32_t stream_reset;
    };

    const Signature *s;     /**< ptr to sig */
} RuleMatchCandidateTx;

/**
  * Detection engine thread data.
  */
typedef struct DetectEngineThreadCtx_ {
    /** \note multi-tenant hash lookup code from Detect() *depends*
     *        on this being the first member */
    uint32_t tenant_id;

    /* the thread to which this detection engine thread belongs */
    ThreadVars *tv;

    /** Array of non-prefiltered sigs that need to be evaluated. Updated
     *  per packet based on the rule group and traffic properties. */
    SigIntId *non_pf_id_array;
    uint32_t non_pf_id_cnt; // size is cnt * sizeof(uint32_t)

    uint32_t mt_det_ctxs_cnt;
    struct DetectEngineThreadCtx_ **mt_det_ctxs;
    HashTable *mt_det_ctxs_hash;

    struct DetectEngineTenantMapping_ *tenant_array;
    uint32_t tenant_array_size;

    uint32_t (*TenantGetId)(const void *, const Packet *p);

    /* detection engine variables */

    uint64_t raw_stream_progress;

    /** offset into the payload of the last match by:
     *  content, pcre, etc */
    uint32_t buffer_offset;
    /* used by pcre match function alone */
    uint32_t pcre_match_start_offset;

    /* counter for the filestore array below -- up here for cache reasons. */
    uint16_t filestore_cnt;

    /** id for alert counter */
    uint16_t counter_alerts;
    /** id for discarded alerts counter */
    uint16_t counter_alerts_overflow;
    /** id for suppressed alerts counter */
    uint16_t counter_alerts_suppressed;
#ifdef PROFILING
    uint16_t counter_mpm_list;
    uint16_t counter_nonmpm_list;
    uint16_t counter_fnonmpm_list;
    uint16_t counter_match_list;
#endif

    int inspect_list; /**< list we're currently inspecting, DETECT_SM_LIST_* */

    struct {
        InspectionBuffer *buffers;
        uint32_t buffers_size;          /**< in number of elements */
        uint32_t to_clear_idx;
        uint32_t *to_clear_queue;
    } inspect;

    struct {
        /** inspection buffers for more complex case. As we can inspect multiple
         *  buffers in parallel, we need this extra wrapper struct */
        InspectionBufferMultipleForList *buffers;
        uint32_t buffers_size;                      /**< in number of elements */
        uint32_t to_clear_idx;
        uint32_t *to_clear_queue;
    } multi_inspect;

    /* used to discontinue any more matching */
    uint16_t discontinue_matching;
    uint16_t flags; /**< DETECT_ENGINE_THREAD_CTX_* flags */

    /* true if tx_id is set */
    bool tx_id_set;
    /** ID of the transaction currently being inspected. */
    uint64_t tx_id;
    int64_t frame_id;
    Packet *p;

    uint16_t alert_queue_size;
    uint16_t alert_queue_capacity;
    PacketAlert *alert_queue;

    SC_ATOMIC_DECLARE(int, so_far_used_by_detect);

    /* holds the current recursion depth on content inspection */
    int inspection_recursion_counter;

    /** array of signature pointers we're going to inspect in the detection
     *  loop. */
    Signature **match_array;
    /** size of the array in items (mem size if * sizeof(Signature *)
     *  Only used during initialization. */
    uint32_t match_array_len;
    /** size in use */
    SigIntId match_array_cnt;

    RuleMatchCandidateTx *tx_candidates;
    uint32_t tx_candidates_size;

    SignatureNonPrefilterStore *non_pf_store_ptr;
    uint32_t non_pf_store_cnt;

    /** pointer to the current mpm ctx that is stored
     *  in a rule group head -- can be either a content
     *  or uricontent ctx. */
    MpmThreadCtx mtc;   /**< thread ctx for the mpm */
    MpmThreadCtx mtcu;  /**< thread ctx for uricontent mpm */
    MpmThreadCtx mtcs;  /**< thread ctx for stream mpm */
    PrefilterRuleStore pmq;

    /** SPM thread context used for scanning. This has been cloned from the
     * prototype held by DetectEngineCtx. */
    SpmThreadCtx *spm_thread_ctx;

    /** ip only rules ctx */
    DetectEngineIPOnlyThreadCtx io_ctx;

    /* byte_* values */
    uint64_t *byte_values;

    /* string to replace */
    DetectReplaceList *replist;
    /* vars to store in post match function */
    DetectVarList *varlist;

    /* Array in which the filestore keyword stores file id and tx id. If the
     * full signature matches, these are processed by a post-match filestore
     * function to finalize the store. */
    struct {
        uint32_t file_id;
        uint64_t tx_id;
    } filestore[DETECT_FILESTORE_MAX];

    DetectEngineCtx *de_ctx;
    /** store for keyword contexts that need a per thread storage. Per de_ctx. */
    void **keyword_ctxs_array;
    int keyword_ctxs_size;
    /** store for keyword contexts that need a per thread storage. Global. */
    int global_keyword_ctxs_size;
    void **global_keyword_ctxs_array;

    uint8_t *base64_decoded;
    int base64_decoded_len;
    int base64_decoded_len_max;

    AppLayerDecoderEvents *decoder_events;
    uint16_t events;

#ifdef DEBUG
    uint64_t pkt_stream_add_cnt;
    uint64_t payload_mpm_cnt;
    uint64_t payload_mpm_size;
    uint64_t stream_mpm_cnt;
    uint64_t stream_mpm_size;
    uint64_t payload_persig_cnt;
    uint64_t payload_persig_size;
    uint64_t stream_persig_cnt;
    uint64_t stream_persig_size;
#endif
#ifdef PROFILING
    struct SCProfileData_ *rule_perf_data;
    int rule_perf_data_size;
    struct SCProfileKeywordData_ *keyword_perf_data;
    struct SCProfileKeywordData_ **keyword_perf_data_per_list;
    int keyword_perf_list; /**< list we're currently inspecting, DETECT_SM_LIST_* */
    struct SCProfileSghData_ *sgh_perf_data;

    struct SCProfilePrefilterData_ *prefilter_perf_data;
    int prefilter_perf_size;
#endif
} DetectEngineThreadCtx;

/** \brief element in sigmatch type table.
 */
typedef struct SigTableElmt_ {
    /** Packet match function pointer */
    int (*Match)(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);

    /** AppLayer TX match function pointer */
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *,
            uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);

    /** File match function  pointer */
    int (*FileMatch)(DetectEngineThreadCtx *,
        Flow *,                     /**< *LOCKED* flow */
        uint8_t flags, File *, const Signature *, const SigMatchCtx *);

    /** InspectionBuffer transformation callback */
    void (*Transform)(InspectionBuffer *, void *context);
    bool (*TransformValidate)(const uint8_t *content, uint16_t content_len, void *context);

    /** keyword setup function pointer */
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);

    bool (*SupportsPrefilter)(const Signature *s);
    int (*SetupPrefilter)(DetectEngineCtx *de_ctx, struct SigGroupHead_ *sgh);

    void (*Free)(DetectEngineCtx *, void *);
#ifdef UNITTESTS
    void (*RegisterTests)(void);
#endif
    uint16_t flags;
    /* coccinelle: SigTableElmt:flags:SIGMATCH_ */

    /** better keyword to replace the current one */
    uint16_t alternative;

    const char *name;     /**< keyword name alias */
    const char *alias;    /**< name alias */
    const char *desc;
    const char *url;

} SigTableElmt;

/* event code */
enum {
#ifdef UNITTESTS
    DET_CTX_EVENT_TEST,
#endif
    FILE_DECODER_EVENT_NO_MEM,
    FILE_DECODER_EVENT_INVALID_SWF_LENGTH,
    FILE_DECODER_EVENT_INVALID_SWF_VERSION,
    FILE_DECODER_EVENT_Z_DATA_ERROR,
    FILE_DECODER_EVENT_Z_STREAM_ERROR,
    FILE_DECODER_EVENT_Z_BUF_ERROR,
    FILE_DECODER_EVENT_Z_UNKNOWN_ERROR,
    FILE_DECODER_EVENT_LZMA_DECODER_ERROR,
    FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR,
    FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR,
    FILE_DECODER_EVENT_LZMA_FORMAT_ERROR,
    FILE_DECODER_EVENT_LZMA_DATA_ERROR,
    FILE_DECODER_EVENT_LZMA_BUF_ERROR,
    FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR,

    DETECT_EVENT_TOO_MANY_BUFFERS,
};

#define SIG_GROUP_HEAD_HAVERAWSTREAM    BIT_U32(0)
#ifdef HAVE_MAGIC
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    BIT_U32(20)
#endif
#define SIG_GROUP_HEAD_HAVEFILEMD5      BIT_U32(21)
#define SIG_GROUP_HEAD_HAVEFILESIZE     BIT_U32(22)
#define SIG_GROUP_HEAD_HAVEFILESHA1     BIT_U32(23)
#define SIG_GROUP_HEAD_HAVEFILESHA256   BIT_U32(24)

enum MpmBuiltinBuffers {
    MPMB_TCP_PKT_TS,
    MPMB_TCP_PKT_TC,
    MPMB_TCP_STREAM_TS,
    MPMB_TCP_STREAM_TC,
    MPMB_UDP_TS,
    MPMB_UDP_TC,
    MPMB_OTHERIP,
    MPMB_MAX,
};

typedef struct MpmStore_ {
    uint8_t *sid_array;
    uint32_t sid_array_size;

    int direction;
    enum MpmBuiltinBuffers buffer;
    int sm_list;
    int32_t sgh_mpm_context;

    MpmCtx *mpm_ctx;

} MpmStore;

typedef void (*PrefilterFrameFn)(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        const struct Frames *frames, const struct Frame *frame, const uint32_t idx);

typedef struct PrefilterEngineList_ {
    uint16_t id;

    /** App Proto this engine applies to: only used with Tx Engines */
    AppProto alproto;
    /** Minimal Tx progress we need before running the engine. Only used
     *  with Tx Engine */
    uint8_t tx_min_progress;

    uint8_t frame_type;

    /** Context for matching. Might be MpmCtx for MPM engines, other ctx'
     *  for other engines. */
    void *pectx;

    void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx);
    void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
            Packet *p, Flow *f, void *tx,
            const uint64_t idx, const uint8_t flags);
    PrefilterFrameFn PrefilterFrame;

    struct PrefilterEngineList_ *next;

    /** Free function for pectx data. If NULL the memory is not freed. */
    void (*Free)(void *pectx);

    const char *name;
    /* global id for this prefilter */
    uint32_t gid;
} PrefilterEngineList;

typedef struct PrefilterEngine_ {
    uint16_t local_id;

    /** App Proto this engine applies to: only used with Tx Engines */
    AppProto alproto;

    union {
        /** Minimal Tx progress we need before running the engine. Only used
         *  with Tx Engine */
        uint8_t tx_min_progress;
        uint8_t frame_type;
    } ctx;

    /** Context for matching. Might be MpmCtx for MPM engines, other ctx'
     *  for other engines. */
    void *pectx;

    union {
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx);
        void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
                Packet *p, Flow *f, void *tx,
                const uint64_t idx, const uint8_t flags);
        PrefilterFrameFn PrefilterFrame;
    } cb;

    /* global id for this prefilter */
    uint32_t gid;
    bool is_last;
    bool is_last_for_progress;
} PrefilterEngine;

typedef struct SigGroupHeadInitData_ {
    MpmStore mpm_store[MPMB_MAX];

    uint8_t *sig_array; /**< bit array of sig nums (internal id's) */
    uint32_t sig_size; /**< size in bytes */

    uint8_t protos[256];    /**< proto(s) this sgh is for */
    uint32_t direction;     /**< set to SIG_FLAG_TOSERVER, SIG_FLAG_TOCLIENT or both */
    int whitelist;          /**< try to make this group a unique one */

    MpmCtx **app_mpms;
    MpmCtx **pkt_mpms;
    MpmCtx **frame_mpms;

    PrefilterEngineList *pkt_engines;
    PrefilterEngineList *payload_engines;
    PrefilterEngineList *tx_engines;
    PrefilterEngineList *frame_engines;

    /** number of sigs in this group */
    SigIntId sig_cnt;

    /** Array with sig ptrs... size is sig_cnt * sizeof(Signature *) */
    Signature **match_array;

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

/** \brief Container for matching data for a signature group */
typedef struct SigGroupHead_ {
    uint32_t flags;
    /* coccinelle: SigGroupHead:flags:SIG_GROUP_HEAD_ */

    /* non prefilter list excluding SYN rules */
    uint32_t non_pf_other_store_cnt;
    uint32_t non_pf_syn_store_cnt;
    SignatureNonPrefilterStore *non_pf_other_store_array; // size is non_mpm_store_cnt * sizeof(SignatureNonPrefilterStore)
    /* non mpm list including SYN rules */
    SignatureNonPrefilterStore *non_pf_syn_store_array; // size is non_mpm_syn_store_cnt * sizeof(SignatureNonPrefilterStore)

    /** the number of signatures in this sgh that have the filestore keyword
     *  set. */
    uint16_t filestore_cnt;

    uint32_t id; /**< unique id used to index sgh_array for stats */

    PrefilterEngine *pkt_engines;
    PrefilterEngine *payload_engines;
    PrefilterEngine *tx_engines;
    PrefilterEngine *frame_engines;

    /* ptr to our init data we only use at... init :) */
    SigGroupHeadInitData *init;

} SigGroupHead;

/** sigmatch has no options, so the parser shouldn't expect any */
#define SIGMATCH_NOOPT                  BIT_U16(0)
/** sigmatch is compatible with a ip only rule */
#define SIGMATCH_IPONLY_COMPAT          BIT_U16(1)
/** sigmatch is compatible with a decode event only rule */
#define SIGMATCH_DEONLY_COMPAT          BIT_U16(2)
/**< Flag to indicate that the signature is not built-in */
#define SIGMATCH_NOT_BUILT              BIT_U16(3)
/** sigmatch may have options, so the parser should be ready to
 *  deal with both cases */
#define SIGMATCH_OPTIONAL_OPT           BIT_U16(4)
/** input may be wrapped in double quotes. They will be stripped before
 *  input data is passed to keyword parser */
#define SIGMATCH_QUOTES_OPTIONAL        BIT_U16(5)
/** input MUST be wrapped in double quotes. They will be stripped before
 *  input data is passed to keyword parser. Missing double quotes lead to
 *  error and signature invalidation. */
#define SIGMATCH_QUOTES_MANDATORY       BIT_U16(6)
/** negation parsing is handled by the rule parser. Signature::init_data::negated
 *  will be set to true or false prior to calling the keyword parser. Exclamation
 *  mark is stripped from the input to the keyword parser. */
#define SIGMATCH_HANDLE_NEGATION        BIT_U16(7)
/** keyword is a content modifier */
#define SIGMATCH_INFO_CONTENT_MODIFIER  BIT_U16(8)
/** keyword is a sticky buffer */
#define SIGMATCH_INFO_STICKY_BUFFER     BIT_U16(9)
/** keyword is deprecated: used to suggest an alternative */
#define SIGMATCH_INFO_DEPRECATED        BIT_U16(10)
/** strict parsing is enabled */
#define SIGMATCH_STRICT_PARSING         BIT_U16(11)

enum DetectEngineTenantSelectors
{
    TENANT_SELECTOR_UNKNOWN = 0,    /**< not set */
    TENANT_SELECTOR_DIRECT,         /**< method provides direct tenant id */
    TENANT_SELECTOR_VLAN,           /**< map vlan to tenant id */
    TENANT_SELECTOR_LIVEDEV,        /**< map livedev to tenant id */
};

typedef struct DetectEngineTenantMapping_ {
    uint32_t tenant_id;

    /* traffic id that maps to the tenant id */
    uint32_t traffic_id;

    struct DetectEngineTenantMapping_ *next;
} DetectEngineTenantMapping;

typedef struct DetectEngineMasterCtx_ {
    SCMutex lock;

    /** enable multi tenant mode */
    int multi_tenant_enabled;

    /** version, incremented after each 'apply to threads' */
    uint32_t version;

    /** list of active detection engines. This list is used to generate the
     *  threads det_ctx's */
    DetectEngineCtx *list;

    /** free list, containing detection engines that will be removed but may
     *  still be referenced by det_ctx's. Freed as soon as all references are
     *  gone. */
    DetectEngineCtx *free_list;

    enum DetectEngineTenantSelectors tenant_selector;

    /** list of tenant mappings. Updated under lock. Used to generate lookup
     *  structures. */
    DetectEngineTenantMapping *tenant_mapping_list;

    /** list of keywords that need thread local ctxs,
     *  only updated by keyword registration at start up. Not
     *  covered by the lock. */
    DetectEngineThreadKeywordCtxItem *keyword_list;
    int keyword_id;
} DetectEngineMasterCtx;

/* Table with all SigMatch registrations */
extern SigTableElmt sigmatch_table[DETECT_TBLSIZE];

/** Remember to add the options in SignatureIsIPOnly() at detect.c otherwise it wont be part of a signature group */

/* detection api */
TmEcode Detect(ThreadVars *tv, Packet *p, void *data);

SigMatch *SigMatchAlloc(void);
Signature *SigFindSignatureBySidGid(DetectEngineCtx *, uint32_t, uint32_t);
void SigMatchSignaturesBuildMatchArray(DetectEngineThreadCtx *,
                                       Packet *, SignatureMask,
                                       uint16_t);
void SigMatchFree(DetectEngineCtx *, SigMatch *sm);

void SigRegisterTests(void);
void TmModuleDetectRegister (void);

void SigAddressPrepareBidirectionals (DetectEngineCtx *);

void DisableDetectFlowFileFlags(Flow *f);
char *DetectLoadCompleteSigPath(const DetectEngineCtx *, const char *sig_file);
int SigLoadSignatures (DetectEngineCtx *, char *, int);
void SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);

int SignatureIsIPOnly(DetectEngineCtx *de_ctx, const Signature *s);
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx, const Packet *p);

Signature *DetectGetTagSignature(void);

int DetectUnregisterThreadCtxFuncs(DetectEngineCtx *, void *data, const char *name);
int DetectRegisterThreadCtxFuncs(DetectEngineCtx *, const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *), int);
void *DetectThreadCtxGetKeywordThreadCtx(DetectEngineThreadCtx *, int);

void RuleMatchCandidateTxArrayInit(DetectEngineThreadCtx *det_ctx, uint32_t size);
void RuleMatchCandidateTxArrayFree(DetectEngineThreadCtx *det_ctx);

void AlertQueueInit(DetectEngineThreadCtx *det_ctx);
void AlertQueueFree(DetectEngineThreadCtx *det_ctx);
void AlertQueueAppend(DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p, uint64_t tx_id,
        uint8_t alert_flags);

int DetectFlowbitsAnalyze(DetectEngineCtx *de_ctx);

int DetectMetadataHashInit(DetectEngineCtx *de_ctx);
void DetectMetadataHashFree(DetectEngineCtx *de_ctx);

/* events */
void DetectEngineSetEvent(DetectEngineThreadCtx *det_ctx, uint8_t e);
AppLayerDecoderEvents *DetectEngineGetEvents(DetectEngineThreadCtx *det_ctx);
int DetectEngineGetEventInfo(const char *event_name, int *event_id,
                             AppLayerEventType *event_type);

void DumpPatterns(DetectEngineCtx *de_ctx);

#include "detect-engine-build.h"
#include "detect-engine-register.h"

#endif /* __DETECT_H__ */

