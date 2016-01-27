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
#include "util-file.h"
#include "reputation.h"

#include "detect-mark.h"

#define DETECT_MAX_RULE_SIZE 8192

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
   -=- Src address
   -==- Dst address
   -===- Src port
   -====- Dst port

   For the other protocols

   - Flow direction
   -- Protocol
   -=- Src address
   -==- Dst address

*/

/*
 * DETECT ADDRESS
 */

/* holds the values for different possible lists in struct Signature.
 * These codes are access points to particular lists in the array
 * Signature->sm_lists[DETECT_SM_LIST_MAX]. */
enum DetectSigmatchListEnum {
    DETECT_SM_LIST_MATCH = 0,
    DETECT_SM_LIST_PMATCH,
    /* list for http_uri keyword and the ones relative to it */
    DETECT_SM_LIST_UMATCH,
    /* list for http_raw_uri keyword and the ones relative to it */
    DETECT_SM_LIST_HRUDMATCH,
    /* list for http_client_body keyword and the ones relative to it */
    DETECT_SM_LIST_HCBDMATCH,
    /* list for http_server_body keyword and the ones relative to it */
    DETECT_SM_LIST_FILEDATA,
    /* list for http_header keyword and the ones relative to it */
    DETECT_SM_LIST_HHDMATCH,
    /* list for http_raw_header keyword and the ones relative to it */
    DETECT_SM_LIST_HRHDMATCH,
    /* list for http_stat_msg keyword and the ones relative to it */
    DETECT_SM_LIST_HSMDMATCH,
    /* list for http_stat_code keyword and the ones relative to it */
    DETECT_SM_LIST_HSCDMATCH,
    /* list for http_host keyword and the ones relative to it */
    DETECT_SM_LIST_HHHDMATCH,
    /* list for http_raw_host keyword and the ones relative to it */
    DETECT_SM_LIST_HRHHDMATCH,
    /* list for http_method keyword and the ones relative to it */
    DETECT_SM_LIST_HMDMATCH,
    /* list for http_cookie keyword and the ones relative to it */
    DETECT_SM_LIST_HCDMATCH,
    /* list for http_user_agent keyword and the ones relative to it */
    DETECT_SM_LIST_HUADMATCH,
    /* list for http_request_line keyword and the ones relative to it */
    DETECT_SM_LIST_HRLMATCH,
    /* app event engine sm list */
    DETECT_SM_LIST_APP_EVENT,

    DETECT_SM_LIST_AMATCH,
    DETECT_SM_LIST_DMATCH,
    DETECT_SM_LIST_TMATCH,

    DETECT_SM_LIST_FILEMATCH,

    DETECT_SM_LIST_DNSREQUEST_MATCH,    /**< per DNS query tx match list */
    DETECT_SM_LIST_DNSRESPONSE_MATCH,   /**< per DNS response tx match list */
    DETECT_SM_LIST_DNSQUERYNAME_MATCH,  /**< per query in a tx list */

    DETECT_SM_LIST_MODBUS_MATCH,

    DETECT_SM_LIST_BASE64_DATA,

    DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH,

    /* list for post match actions: flowbit set, flowint increment, etc */
    DETECT_SM_LIST_POSTMATCH,

    /* lists for alert thresholding and suppression */
    DETECT_SM_LIST_SUPPRESS,
    DETECT_SM_LIST_THRESHOLD,
    DETECT_SM_LIST_MAX,

    /* used for Signature->list, which indicates which list
     * we're adding keywords to in cases of sticky buffers like
     * file_data */
    DETECT_SM_LIST_NOTSET,
};

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
    Address ip;
    Address ip2;

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


#include "detect-threshold.h"

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
#define SIG_FLAG_SRC_ANY                (1)  /**< source is any */
#define SIG_FLAG_DST_ANY                (1<<1)  /**< destination is any */
#define SIG_FLAG_SP_ANY                 (1<<2)  /**< source port is any */
#define SIG_FLAG_DP_ANY                 (1<<3)  /**< destination port is any */

#define SIG_FLAG_NOALERT                (1<<4)  /**< no alert flag is set */
#define SIG_FLAG_DSIZE                  (1<<5)  /**< signature has a dsize setting */
#define SIG_FLAG_APPLAYER               (1<<6)  /**< signature applies to app layer instead of packets */
#define SIG_FLAG_IPONLY                 (1<<7) /**< ip only signature */

#define SIG_FLAG_STATE_MATCH            (1<<8) /**< signature has matches that require stateful inspection */

#define SIG_FLAG_REQUIRE_PACKET         (1<<9) /**< signature is requiring packet match */
#define SIG_FLAG_REQUIRE_STREAM         (1<<10) /**< signature is requiring stream match */

#define SIG_FLAG_MPM_PACKET             (1<<11)
#define SIG_FLAG_MPM_PACKET_NEG         (1<<12)
#define SIG_FLAG_MPM_STREAM             (1<<13)
#define SIG_FLAG_MPM_STREAM_NEG         (1<<14)
#define SIG_FLAG_MPM_APPLAYER           (1<<15)
#define SIG_FLAG_MPM_APPLAYER_NEG       (1<<16)

#define SIG_FLAG_REQUIRE_FLOWVAR        (1<<17) /**< signature can only match if a flowbit, flowvar or flowint is available. */

#define SIG_FLAG_FILESTORE              (1<<18) /**< signature has filestore keyword */

#define SIG_FLAG_TOSERVER               (1<<19)
#define SIG_FLAG_TOCLIENT               (1<<20)

#define SIG_FLAG_TLSSTORE               (1<<21)

/* signature init flags */
#define SIG_FLAG_INIT_DEONLY         1  /**< decode event only signature */
#define SIG_FLAG_INIT_PACKET         (1<<1)  /**< signature has matches against a packet (as opposed to app layer) */
#define SIG_FLAG_INIT_FLOW           (1<<2)  /**< signature has a flow setting */
#define SIG_FLAG_INIT_BIDIREC        (1<<3)  /**< signature has bidirectional operator */
#define SIG_FLAG_INIT_PAYLOAD        (1<<4)  /**< signature is inspecting the packet payload */
#define SIG_FLAG_INIT_FIRST_IPPROTO_SEEN (1 << 5) /** < signature has seen the first ip_proto keyword */

/* signature mask flags */
#define SIG_MASK_REQUIRE_PAYLOAD            (1<<0)
#define SIG_MASK_REQUIRE_FLOW               (1<<1)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   (1<<2)    /* SYN, FIN, RST */
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      (1<<3)    /* URG, ECN, CWR */
#define SIG_MASK_REQUIRE_NO_PAYLOAD         (1<<4)
#define SIG_MASK_REQUIRE_HTTP_STATE         (1<<5)
#define SIG_MASK_REQUIRE_DCE_STATE          (1<<6)
#define SIG_MASK_REQUIRE_ENGINE_EVENT       (1<<7)
#define SIG_MASK_REQUIRE_SSH_STATE          (1<<8)
#define SIG_MASK_REQUIRE_TLS_STATE          (1<<9)
#define SIG_MASK_REQUIRE_DNS_STATE          (1<<10)
#define SIG_MASK_REQUIRE_FTP_STATE          (1<<11)
#define SIG_MASK_REQUIRE_SMTP_STATE         (1<<12)
#define SIG_MASK_REQUIRE_TEMPLATE_STATE     (1<<13)

/* for now a uint8_t is enough */
#define SignatureMask uint16_t

#define DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET 0x0001
#define DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM 0x0002
#define DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH 0x0004

#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_TYPE          0x04
#define FILE_SIG_NEED_MAGIC         0x08    /**< need the start of the file */
#define FILE_SIG_NEED_FILECONTENT   0x10
#define FILE_SIG_NEED_MD5           0x20
#define FILE_SIG_NEED_SIZE          0x40

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

/** \brief Used to start a pointer to SigMatch context
 * Should never be dereferenced without casting to something else.
 */
typedef struct SigMatchCtx_ {
    int foo;
} SigMatchCtx;

/** \brief a single match condition for a signature */
typedef struct SigMatch_ {
    uint8_t type; /**< match type */
    uint16_t idx; /**< position in the signature */
    SigMatchCtx *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

/** \brief Data needed for Match() */
typedef struct SigMatchData_ {
    uint8_t type; /**< match type */
    uint8_t is_last; /**< Last element of the list */
    SigMatchCtx *ctx; /**< plugin specific data */
} SigMatchData;


/** \brief Signature container */
typedef struct Signature_ {
    /* coccinelle: Signature:flags:SIG_FLAG */
    uint32_t flags;

    AppProto alproto;

    uint16_t dsize_low;
    uint16_t dsize_high;

    uint16_t mpm_pattern_id_div_8;
    uint8_t mpm_pattern_id_mod_8;

    SignatureMask mask;
    SigIntId num; /**< signature number, internal id */

    /** inline -- action */
    uint8_t action;
    uint8_t file_flags;

    /** addresses, ports and proto this sig matches on */
    DetectProto proto;

    /** classification id **/
    uint8_t class;

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
    /** number of sigmatches in the match and pmatch list */
    uint16_t sm_cnt;

    /* used to hold flags that are predominantly used during init */
    uint32_t init_flags;
    /* coccinelle: Signature:init_flags:SIG_FLAG_INIT_ */

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *CidrSrc, *CidrDst;

    /* Hold copies of the sm lists for Match() */
    SigMatchData *sm_arrays[DETECT_SM_LIST_MAX];

    /* holds all sm lists */
    struct SigMatch_ *sm_lists[DETECT_SM_LIST_MAX];
    /* holds all sm lists' tails */
    struct SigMatch_ *sm_lists_tail[DETECT_SM_LIST_MAX];

    SigMatch *filestore_sm;

    char *msg;

    /** classification message */
    char *class_msg;
    /** Reference */
    DetectReference *references;

    /** address settings for this signature */
    DetectAddressHead src, dst;

    /* used at init to determine max dsize */
    SigMatch *dsize_sm;
    /* the fast pattern added from this signature */
    SigMatch *mpm_sm;

    /* SigMatch list used for adding content and friends. E.g. file_data; */
    int list;

    /* Be careful, this pointer is only valid while parsing the sig,
     * to warn the user about any possible problem */
    char *sig_str;

    /** ptr to the next sig in the list */
    struct Signature_ *next;
} Signature;

typedef struct DetectReplaceList_ {
    struct DetectContentData_ *cd;
    uint8_t *found;
    struct DetectReplaceList_ *next;
} DetectReplaceList;

/** only execute flowvar storage if rule matched */
#define DETECT_FLOWVAR_TYPE_POSTMATCH   1
/** execute flowvar storage even if rule doesn't match (for luajit) */
#define DETECT_FLOWVAR_TYPE_ALWAYS      2

/** list for flowvar store candidates, to be stored from
 *  post-match function */
typedef struct DetectFlowvarList_ {
    uint16_t idx;                       /**< flowvar name idx */
    uint16_t len;                       /**< data len */
    uint8_t *buffer;                    /**< alloc'd buffer, may be freed by
                                             post-match, post-non-match */
    int type;                           /**< type of store candidate POSTMATCH or ALWAYS */
    struct DetectFlowvarList_ *next;
} DetectFlowvarList;

typedef struct DetectEngineIPOnlyThreadCtx_ {
    uint8_t *sig_match_array; /* bit array of sig nums */
    uint32_t sig_match_size;  /* size in bytes of the array */
} DetectEngineIPOnlyThreadCtx;

/** \brief IP only rules matching ctx. */
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

/* mpm pattern id api */
typedef struct MpmPatternIdStore_ {
    HashTable *hash;
    PatIntId max_id;

    uint32_t unique_patterns;
    uint32_t shared_patterns;
} MpmPatternIdStore;

/** \brief threshold ctx */
typedef struct ThresholdCtx_    {
    SCMutex threshold_table_lock;                   /**< Mutex for hash table */

    /** to support rate_filter "by_rule" option */
    DetectThresholdEntry **th_entry;
    uint32_t th_size;
} ThresholdCtx;

typedef struct DetectEngineThreadKeywordCtxItem_ {
    void *(*InitFunc)(void *);
    void (*FreeFunc)(void *);
    void *data;
    struct DetectEngineThreadKeywordCtxItem_ *next;
    int id;
    const char *name; /* keyword name, for error printing */
} DetectEngineThreadKeywordCtxItem;

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
    uint32_t non_mpm_store_cnt_max;

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

    HashListTable *sgh_mpm_hash_table;
    HashListTable *sgh_mpm_uri_hash_table;
    HashListTable *sgh_mpm_stream_hash_table;

    HashListTable *sgh_sport_hash_table;
    HashListTable *sgh_dport_hash_table;

    HashListTable *sport_hash_table;
    HashListTable *dport_hash_table;

    HashListTable *variable_names;
    HashListTable *variable_idxs;
    uint16_t variable_names_idx;

    /* hash table used to cull out duplicate sigs */
    HashListTable *dup_sig_hash_table;

    DetectEngineIPOnlyCtx io_ctx;
    ThresholdCtx ths_ctx;

    uint16_t mpm_matcher; /**< mpm matcher this ctx uses */

    /* Config options */

    uint16_t max_uniq_toclient_src_groups;
    uint16_t max_uniq_toclient_dst_groups;
    uint16_t max_uniq_toclient_sp_groups;
    uint16_t max_uniq_toclient_dp_groups;

    uint16_t max_uniq_toserver_src_groups;
    uint16_t max_uniq_toserver_dst_groups;
    uint16_t max_uniq_toserver_sp_groups;
    uint16_t max_uniq_toserver_dp_groups;

    /* specify the configuration for mpm context factory */
    uint8_t sgh_mpm_context;

    /** hash table for looking up patterns for
     *  id sharing and id tracking. */
    MpmPatternIdStore *mpm_pattern_id_store;
    uint16_t max_fp_id;

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
    int32_t sgh_mpm_context_uri;
    int32_t sgh_mpm_context_hcbd;
    int32_t sgh_mpm_context_hsbd;
    int32_t sgh_mpm_context_hhd;
    int32_t sgh_mpm_context_hrhd;
    int32_t sgh_mpm_context_hmd;
    int32_t sgh_mpm_context_hcd;
    int32_t sgh_mpm_context_hrud;
    int32_t sgh_mpm_context_hsmd;
    int32_t sgh_mpm_context_hscd;
    int32_t sgh_mpm_context_huad;
    int32_t sgh_mpm_context_hhhd;
    int32_t sgh_mpm_context_hrhhd;
    int32_t sgh_mpm_context_app_proto_detect;
    int32_t sgh_mpm_context_dnsquery;
    int32_t sgh_mpm_context_smtp;

    /* the max local id used amongst all sigs */
    int32_t byte_extract_max_local_id;

    /* id used by every detect engine ctx instance */
    uint32_t id;

    /** sgh for signatures that match against invalid packets. In those cases
     *  we can't lookup by proto, address, port as we don't have these */
    struct SigGroupHead_ *decoder_event_sgh;

    /* Maximum size of the buffer for decoded base64 data. */
    uint32_t base64_decode_max_len;

    /** Store rule file and line so that parsers can use them in errors. */
    char *rule_file;
    int rule_line;

    /** list of keywords that need thread local ctxs */
    DetectEngineThreadKeywordCtxItem *keyword_list;
    int keyword_id;

    int detect_luajit_instances;

#ifdef PROFILING
    struct SCProfileDetectCtx_ *profile_ctx;
    struct SCProfileKeywordDetectCtx_ *profile_keyword_ctx;
    struct SCProfileKeywordDetectCtx_ *profile_keyword_ctx_per_list[DETECT_SM_LIST_MAX];
#endif

    char config_prefix[64];

    /** minimal: essentially a stub */
    int minimal;

    /** how many de_ctx' are referencing this */
    uint32_t ref_cnt;
    /** list in master: either active or freelist */
    struct DetectEngineCtx_ *next;

    /** id of loader thread 'owning' this de_ctx */
    int loader_id;

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
    ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL,
    ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE,
    ENGINE_SGH_MPM_FACTORY_CONTEXT_AUTO
};

typedef struct HttpReassembledBody_ {
    uint8_t *buffer;
    uint32_t buffer_size;   /**< size of the buffer itself */
    uint32_t buffer_len;    /**< data len in the buffer */
    uint64_t offset;        /**< data offset */
} HttpReassembledBody;

typedef struct FiledataReassembledBody_ {
    uint8_t *buffer;
    uint32_t buffer_size;   /**< size of the buffer itself */
    uint32_t buffer_len;    /**< data len in the buffer */
    uint64_t offset;        /**< data offset */
} FiledataReassembledBody;

#define DETECT_FILESTORE_MAX 15
/** \todo review how many we actually need here */
#define DETECT_SMSG_PMQ_NUM 256

/**
  * Detection engine thread data.
  */
typedef struct DetectEngineThreadCtx_ {
    /** \note multi-tenant hash lookup code from Detect() *depends*
     *        on this beeing the first member */
    uint32_t tenant_id;

    /* the thread to which this detection engine thread belongs */
    ThreadVars *tv;

    SigIntId *non_mpm_id_array;
    uint32_t non_mpm_id_cnt; // size is cnt * sizeof(uint32_t)

    uint32_t mt_det_ctxs_cnt;
    struct DetectEngineThreadCtx_ **mt_det_ctxs;
    HashTable *mt_det_ctxs_hash;

    struct DetectEngineTenantMapping_ *tenant_array;
    uint32_t tenant_array_size;

    uint32_t (*TenantGetId)(const void *, const Packet *p);

    /* detection engine variables */

    /** offset into the payload of the last match by:
     *  content, pcre, etc */
    uint32_t buffer_offset;
    /* used by pcre match function alone */
    uint32_t pcre_match_start_offset;

    /* counter for the filestore array below -- up here for cache reasons. */
    uint16_t filestore_cnt;

    /* bool to hint the POSTMATCH list members about the lock status of the
     * flow. If locked this is TRUE, unlocked or no-flow: FALSE */
    uint8_t flow_locked;

    HttpReassembledBody *hsbd;
    uint64_t hsbd_start_tx_id;
    uint16_t hsbd_buffers_size;
    uint16_t hsbd_buffers_list_len;

    HttpReassembledBody *hcbd;
    uint64_t hcbd_start_tx_id;
    uint16_t hcbd_buffers_size;
    uint16_t hcbd_buffers_list_len;

    uint8_t **hhd_buffers;
    uint32_t *hhd_buffers_len;
    uint16_t hhd_buffers_size;
    uint16_t hhd_buffers_list_len;
    uint64_t hhd_start_tx_id;

    FiledataReassembledBody *smtp;
    uint64_t smtp_start_tx_id;
    uint16_t smtp_buffers_size;
    uint16_t smtp_buffers_list_len;

    /** id for alert counter */
    uint16_t counter_alerts;
#ifdef PROFILING
    uint16_t counter_mpm_list;
    uint16_t counter_nonmpm_list;
    uint16_t counter_fnonmpm_list;
    uint16_t counter_match_list;
#endif

    /* used to discontinue any more matching */
    uint16_t discontinue_matching;
    uint16_t flags;

    /* bool: if tx_id is set, this is 1, otherwise 0 */
    uint16_t tx_id_set;
    /** ID of the transaction currently being inspected. */
    uint64_t tx_id;

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

    /** Array of sigs that had a state change */
    SigIntId de_state_sig_array_len;
    uint8_t *de_state_sig_array;

    struct SigGroupHead_ *sgh;
    /** pointer to the current mpm ctx that is stored
     *  in a rule group head -- can be either a content
     *  or uricontent ctx. */
    MpmThreadCtx mtc;   /**< thread ctx for the mpm */
    MpmThreadCtx mtcu;  /**< thread ctx for uricontent mpm */
    MpmThreadCtx mtcs;  /**< thread ctx for stream mpm */
    PatternMatcherQueue pmq;
    PatternMatcherQueue smsg_pmq[DETECT_SMSG_PMQ_NUM];

    /** ip only rules ctx */
    DetectEngineIPOnlyThreadCtx io_ctx;

    /* byte jump values */
    uint64_t *bj_values;

    /* string to replace */
    DetectReplaceList *replist;
    /* flowvars to store in post match function */
    DetectFlowvarList *flowvarlist;

    /* Array in which the filestore keyword stores file id and tx id. If the
     * full signature matches, these are processed by a post-match filestore
     * function to finalize the store. */
    struct {
        uint16_t file_id;
        uint64_t tx_id;
    } filestore[DETECT_FILESTORE_MAX];

    DetectEngineCtx *de_ctx;
    /** store for keyword contexts that need a per thread storage because of
     *  thread safety issues */
    void **keyword_ctxs_array;
    int keyword_ctxs_size;

    uint8_t *base64_decoded;
    int base64_decoded_len;
    int base64_decoded_len_max;

#ifdef PROFILING
    struct SCProfileData_ *rule_perf_data;
    int rule_perf_data_size;
    struct SCProfileKeywordData_ *keyword_perf_data;
    struct SCProfileKeywordData_ *keyword_perf_data_per_list[DETECT_SM_LIST_MAX];
    int keyword_perf_list; /**< list we're currently inspecting, DETECT_SM_LIST_* */
#endif
} DetectEngineThreadCtx;

/** \brief element in sigmatch type table.
 *  \note FileMatch pointer below takes a locked flow, AppLayerMatch an unlocked flow
 */
typedef struct SigTableElmt_ {
    /** Packet match function pointer */
    int (*Match)(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);

    /** AppLayer match function  pointer */
    int (*AppLayerMatch)(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t flags, void *alstate, Signature *, SigMatch *);

    /** AppLayer TX match function pointer */
    int (*AppLayerTxMatch)(ThreadVars *, DetectEngineThreadCtx *, Flow *,
            uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);

    /** File match function  pointer */
    int (*FileMatch)(ThreadVars *,  /**< thread local vars */
        DetectEngineThreadCtx *,
        Flow *,                     /**< *LOCKED* flow */
        uint8_t flags, File *, Signature *, SigMatch *);

    /** app layer proto from app-layer-protos.h this match applies to */
    AppProto alproto;

    /** keyword setup function pointer */
    int (*Setup)(DetectEngineCtx *, Signature *, char *);

    void (*Free)(void *);
    void (*RegisterTests)(void);

    uint8_t flags;
    char *name;     /**< keyword name alias */
    char *alias;    /**< name alias */
    char *desc;
    char *url;

} SigTableElmt;

#define SIG_GROUP_HEAD_MPM_URI          (1)
#define SIG_GROUP_HEAD_MPM_HCBD         (1 << 1)
#define SIG_GROUP_HEAD_MPM_HHD          (1 << 2)
#define SIG_GROUP_HEAD_MPM_HRHD         (1 << 3)
#define SIG_GROUP_HEAD_MPM_HMD          (1 << 4)
#define SIG_GROUP_HEAD_MPM_HCD          (1 << 5)
#define SIG_GROUP_HEAD_MPM_HRUD         (1 << 6)
#define SIG_GROUP_HEAD_MPM_HSBD         (1 << 7)
#define SIG_GROUP_HEAD_MPM_HSMD         (1 << 8)
#define SIG_GROUP_HEAD_MPM_HSCD         (1 << 9)
#define SIG_GROUP_HEAD_MPM_HUAD         (1 << 10)
#define SIG_GROUP_HEAD_MPM_HHHD         (1 << 11)
#define SIG_GROUP_HEAD_MPM_HRHHD        (1 << 12)

#define SIG_GROUP_HEAD_MPM_COPY         (1 << 13)
#define SIG_GROUP_HEAD_MPM_URI_COPY     (1 << 14)
#define SIG_GROUP_HEAD_MPM_STREAM_COPY  (1 << 15)
#define SIG_GROUP_HEAD_FREE             (1 << 16)
#define SIG_GROUP_HEAD_MPM_PACKET       (1 << 17)
#define SIG_GROUP_HEAD_MPM_STREAM       (1 << 18)
#define SIG_GROUP_HEAD_REFERENCED       (1 << 19) /**< sgh is being referenced by others, don't clear */
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    (1 << 20)
#define SIG_GROUP_HEAD_HAVEFILEMD5      (1 << 21)
#define SIG_GROUP_HEAD_HAVEFILESIZE     (1 << 22)
#define SIG_GROUP_HEAD_MPM_DNSQUERY     (1 << 23)
#define SIG_GROUP_HEAD_MPM_FD_SMTP      (1 << 24)

typedef struct SigGroupHeadInitData_ {
    /* list of content containers */
    uint8_t *content_array;
    uint32_t content_size;
    uint8_t *uri_content_array;
    uint32_t uri_content_size;
    uint8_t *stream_content_array;
    uint32_t stream_content_size;

    uint8_t *sig_array; /**< bit array of sig nums (internal id's) */
    uint32_t sig_size; /**< size in bytes */

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

typedef struct SignatureNonMpmStore_ {
    SigIntId id;
    SignatureMask mask;
} SignatureNonMpmStore;

/** \brief Container for matching data for a signature group */
typedef struct SigGroupHead_ {
    uint32_t flags;
    /* number of sigs in this head */
    SigIntId sig_cnt;

    /* track min pattern length for content. Used in grouping */
    uint16_t mpm_content_minlen;

    /** array of masks, used to check multiple masks against
     *  a packet using SIMD. */
#if defined(__SSE3__) || defined(__tile__)
    SignatureMask *mask_array;
#endif

    SignatureNonMpmStore *non_mpm_store_array; // size is non_mpm_store_cnt * sizeof(SignatureNonMpmStore)
    uint32_t non_mpm_store_cnt;

    /* pattern matcher instances */
    MpmCtx *mpm_proto_other_ctx;

    MpmCtx *mpm_proto_tcp_ctx_ts;
    MpmCtx *mpm_proto_udp_ctx_ts;
    MpmCtx *mpm_stream_ctx_ts;
    MpmCtx *mpm_uri_ctx_ts;
    MpmCtx *mpm_hcbd_ctx_ts;
    MpmCtx *mpm_hhd_ctx_ts;
    MpmCtx *mpm_hrhd_ctx_ts;
    MpmCtx *mpm_hmd_ctx_ts;
    MpmCtx *mpm_hcd_ctx_ts;
    MpmCtx *mpm_hrud_ctx_ts;
    MpmCtx *mpm_huad_ctx_ts;
    MpmCtx *mpm_hhhd_ctx_ts;
    MpmCtx *mpm_hrhhd_ctx_ts;
    MpmCtx *mpm_dnsquery_ctx_ts;
    MpmCtx *mpm_smtp_filedata_ctx_ts;

    MpmCtx *mpm_proto_tcp_ctx_tc;
    MpmCtx *mpm_proto_udp_ctx_tc;
    MpmCtx *mpm_stream_ctx_tc;
    MpmCtx *mpm_hsbd_ctx_tc;
    MpmCtx *mpm_hhd_ctx_tc;
    MpmCtx *mpm_hrhd_ctx_tc;
    MpmCtx *mpm_hcd_ctx_tc;
    MpmCtx *mpm_hsmd_ctx_tc;
    MpmCtx *mpm_hscd_ctx_tc;

    uint16_t mpm_uricontent_minlen; /**< len of shortest mpm pattern in sgh */

    /** the number of signatures in this sgh that have the filestore keyword
     *  set. */
    uint16_t filestore_cnt;

    /** Array with sig ptrs... size is sig_cnt * sizeof(Signature *) */
    Signature **match_array;

    /* ptr to our init data we only use at... init :) */
    SigGroupHeadInitData *init;
} SigGroupHead;

/** sigmatch has no options, so the parser shouldn't expect any */
#define SIGMATCH_NOOPT          (1 << 0)
/** sigmatch is compatible with a ip only rule */
#define SIGMATCH_IPONLY_COMPAT  (1 << 1)
/** sigmatch is compatible with a decode event only rule */
#define SIGMATCH_DEONLY_COMPAT  (1 << 2)
/**< Flag to indicate that the signature inspects the packet payload */
#define SIGMATCH_PAYLOAD        (1 << 3)
/**< Flag to indicate that the signature is not built-in */
#define SIGMATCH_NOT_BUILT      (1 << 4)
/** sigmatch may have options, so the parser should be ready to
 *  deal with both cases */
#define SIGMATCH_OPTIONAL_OPT   (1 << 5)

enum DetectEngineTenantSelectors
{
    TENANT_SELECTOR_UNKNOWN = 0,    /**< not set */
    TENANT_SELECTOR_DIRECT,         /**< method provides direct tenant id */
    TENANT_SELECTOR_VLAN,           /**< map vlan to tenant id */
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

} DetectEngineMasterCtx;

/** \brief Signature loader statistics */
typedef struct SigFileLoaderStat_ {
    int bad_files;
    int total_files;
    int good_sigs_total;
    int bad_sigs_total;
} SigFileLoaderStat;

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
    DETECT_ACK,
    DETECT_SEQ,
    DETECT_DEPTH,
    DETECT_DISTANCE,
    DETECT_WITHIN,
    DETECT_OFFSET,
    DETECT_REPLACE,
    DETECT_NOCASE,
    DETECT_FAST_PATTERN,
    DETECT_RAWBYTES,
    DETECT_BYTETEST,
    DETECT_BYTEJUMP,
    DETECT_SAMEIP,
    DETECT_GEOIP,
    DETECT_IPPROTO,
    DETECT_FLOW,
    DETECT_WINDOW,
    DETECT_FTPBOUNCE,
    DETECT_ISDATAAT,
    DETECT_ID,
    DETECT_RPC,
    DETECT_DSIZE,
    DETECT_FLOWVAR,
    DETECT_FLOWVAR_POSTMATCH,
    DETECT_FLOWINT,
    DETECT_PKTVAR,
    DETECT_NOALERT,
    DETECT_FLOWBITS,
    DETECT_HOSTBITS,
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
    DETECT_TOS,
    DETECT_ICMP_ID,
    DETECT_ICMP_SEQ,
    DETECT_DETECTION_FILTER,

    DETECT_DECODE_EVENT,
    DETECT_IPOPTS,
    DETECT_FLAGS,
    DETECT_FRAGBITS,
    DETECT_FRAGOFFSET,
    DETECT_GID,
    DETECT_MARK,

    DETECT_AL_TLS_VERSION,
    DETECT_AL_TLS_SUBJECT,
    DETECT_AL_TLS_ISSUERDN,
    DETECT_AL_TLS_FINGERPRINT,
    DETECT_AL_TLS_STORE,

    DETECT_AL_HTTP_COOKIE,
    DETECT_AL_HTTP_METHOD,
    DETECT_AL_URILEN,
    DETECT_AL_HTTP_CLIENT_BODY,
    DETECT_AL_HTTP_SERVER_BODY,
    DETECT_AL_HTTP_HEADER,
    DETECT_AL_HTTP_RAW_HEADER,
    DETECT_AL_HTTP_URI,
    DETECT_AL_HTTP_RAW_URI,
    DETECT_AL_HTTP_STAT_MSG,
    DETECT_AL_HTTP_STAT_CODE,
    DETECT_AL_HTTP_USER_AGENT,
    DETECT_AL_HTTP_HOST,
    DETECT_AL_HTTP_RAW_HOST,
    DETECT_AL_SSH_PROTOVERSION,
    DETECT_AL_SSH_SOFTWAREVERSION,
    DETECT_AL_SSL_VERSION,
    DETECT_AL_SSL_STATE,
    DETECT_BYTE_EXTRACT,
    DETECT_FILE_DATA,
    DETECT_PKT_DATA,
    DETECT_AL_APP_LAYER_EVENT,
    DETECT_AL_APP_LAYER_PROTOCOL,

    DETECT_DCE_IFACE,
    DETECT_DCE_OPNUM,
    DETECT_DCE_STUB_DATA,

    DETECT_ASN1,

    DETECT_ENGINE_EVENT,
    DETECT_STREAM_EVENT,

    DETECT_FILENAME,
    DETECT_FILEEXT,
    DETECT_FILESTORE,
    DETECT_FILEMAGIC,
    DETECT_FILEMD5,
    DETECT_FILESIZE,

    DETECT_L3PROTO,
    DETECT_LUA,
    DETECT_IPREP,

    DETECT_AL_DNS_QUERY,
    DETECT_AL_MODBUS,

    DETECT_XBITS,
    DETECT_BASE64_DECODE,
    DETECT_BASE64_DATA,

    DETECT_TEMPLATE,
    DETECT_AL_TEMPLATE_BUFFER,

    /* make sure this stays last */
    DETECT_TBLSIZE,
};

/* Table with all SigMatch registrations */
SigTableElmt sigmatch_table[DETECT_TBLSIZE];

/* detection api */
SigMatch *SigMatchAlloc(void);
Signature *SigFindSignatureBySidGid(DetectEngineCtx *, uint32_t, uint32_t);
void SigMatchSignaturesBuildMatchArray(DetectEngineThreadCtx *,
                                       Packet *, SignatureMask,
                                       uint16_t);
void SigMatchFree(SigMatch *sm);
void SigCleanSignatures(DetectEngineCtx *);

void SigTableRegisterTests(void);
void SigRegisterTests(void);
void DetectSimdRegisterTests(void);
void TmModuleDetectRegister (void);

int SigGroupBuild(DetectEngineCtx *);
int SigGroupCleanup (DetectEngineCtx *de_ctx);
void SigAddressPrepareBidirectionals (DetectEngineCtx *);

char *DetectLoadCompleteSigPath(const DetectEngineCtx *, char *sig_file);
int SigLoadSignatures (DetectEngineCtx *, char *, int);
void SigTableList(const char *keyword);
void SigTableSetup(void);
int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);

int SignatureIsIPOnly(DetectEngineCtx *de_ctx, Signature *s);
SigGroupHead *SigMatchSignaturesGetSgh(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p);

Signature *DetectGetTagSignature(void);

int SignatureIsFilestoring(Signature *);
int SignatureIsFilemagicInspecting(Signature *);
int SignatureIsFileMd5Inspecting(Signature *);
int SignatureIsFilesizeInspecting(Signature *);

int DetectRegisterThreadCtxFuncs(DetectEngineCtx *, const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *), int);
void *DetectThreadCtxGetKeywordThreadCtx(DetectEngineThreadCtx *, int);

int SigMatchSignaturesRunPostMatch(ThreadVars *tv,
                                   DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p,
                                   Signature *s);
void DetectSignatureApplyActions(Packet *p, const Signature *s);

#endif /* __DETECT_H__ */

