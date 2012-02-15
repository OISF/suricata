/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#include "detect-mark.h"

#define COUNTER_DETECT_ALERTS 1

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
 * Signature->sm_lists[DETECT_SM_LIST_MAX] */
enum {
    DETECT_SM_LIST_MATCH = 0,
    DETECT_SM_LIST_PMATCH,
    /* list for http_uri keyword and the ones relative to it */
    DETECT_SM_LIST_UMATCH,
    DETECT_SM_LIST_AMATCH,
    DETECT_SM_LIST_DMATCH,
    DETECT_SM_LIST_TMATCH,
    /* list for http_client_body keyword and the ones relative to it */
    DETECT_SM_LIST_HCBDMATCH,
    /* list for http_server_body keyword and the ones relative to it */
    DETECT_SM_LIST_HSBDMATCH,
    /* list for http_header keyword and the ones relative to it */
    DETECT_SM_LIST_HHDMATCH,
    /* list for http_raw_header keyword and the ones relative to it */
    DETECT_SM_LIST_HRHDMATCH,
    /* list for http_method keyword and the ones relative to it */
    DETECT_SM_LIST_HMDMATCH,
    /* list for http_cookie keyword and the ones relative to it */
    DETECT_SM_LIST_HCDMATCH,
    /* list for http_raw_uri keyword and the ones relative to it */
    DETECT_SM_LIST_HRUDMATCH,
    /* list for http_stat_msg keyword and the ones relative to it */
    DETECT_SM_LIST_HSMDMATCH,
    /* list for http_stat_code keyword and the ones relative to it */
    DETECT_SM_LIST_HSCDMATCH,

    DETECT_SM_LIST_FILEMATCH,

    /* list for post match actions: flowbit set, flowint increment, etc */
    DETECT_SM_LIST_POSTMATCH,

    /* list for alert thresholding */
    DETECT_SM_LIST_THRESHOLD,
    DETECT_SM_LIST_MAX,
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
//    uint8_t family; /**< address family, AF_INET (IPv4) or AF_INET6 (IPv6) */
//    uint32_t ip[4]; /**< the address, or lower end of a range */
//    uint32_t ip2[4]; /**< higher end of a range */

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
#define SIG_FLAG_MPM_HTTP               (1<<15)
#define SIG_FLAG_MPM_HTTP_NEG           (1<<16)

#define SIG_FLAG_REQUIRE_FLOWVAR        (1<<17) /**< signature can only match if a flowbit, flowvar or flowint is available. */

#define SIG_FLAG_FILESTORE              (1<<18) /**< signature has filestore keyword */

#define SIG_FLAG_TOSERVER               (1<<19)
#define SIG_FLAG_TOCLIENT               (1<<20)

/* signature init flags */
#define SIG_FLAG_INIT_DEONLY         1  /**< decode event only signature */
#define SIG_FLAG_INIT_PACKET         (1<<1)  /**< signature has matches against a packet (as opposed to app layer) */
#define SIG_FLAG_INIT_FLOW           (1<<2)  /**< signature has a flow setting */
#define SIG_FLAG_INIT_BIDIREC        (1<<3)  /**< signature has bidirectional operator */
#define SIG_FLAG_INIT_PAYLOAD        (1<<4)  /**< signature is inspecting the packet payload */
#define SIG_FLAG_INIT_FILE_DATA      (1<<5)  /**< file_data set */

/* signature mask flags */
#define SIG_MASK_REQUIRE_PAYLOAD            1
#define SIG_MASK_REQUIRE_FLOW               (1<<1)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   (1<<2)    /* SYN, FIN, RST */
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      (1<<3)    /* URG, ECN, CWR */
#define SIG_MASK_REQUIRE_NO_PAYLOAD         (1<<4)
//
#define SIG_MASK_REQUIRE_HTTP_STATE         (1<<5)
#define SIG_MASK_REQUIRE_DCE_STATE          (1<<6)

/* for now a uint8_t is enough */
#define SignatureMask uint8_t

#define DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET 0x0001
#define DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM 0x0002

#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_TYPE          0x04
#define FILE_SIG_NEED_MAGIC         0x08    /**< need the start of the file */
#define FILE_SIG_NEED_FILECONTENT   0x10

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

/** \brief Subset of the Signature for cache efficient prefiltering
 */
typedef struct SignatureHeader_ {
    union {
        struct {
            uint32_t flags;
            uint16_t mpm_pattern_id_div_8;
            uint8_t mpm_pattern_id_mod_8;
            SignatureMask mask;
        };
        uint64_t hdr_copy1;
    };
    union {
        struct {
            uint16_t alproto;
            SigIntId num; /**< signature number, internal id */
        };
        uint32_t hdr_copy2;
    };
    union {
        struct {
            SigIntId order_id;

            /** inline -- action */
            uint8_t action;
            uint8_t file_flags;
        };
        uint32_t hdr_copy3;
    };

    /** pointer to the full signature */
    struct Signature_ *full_sig;
} SignatureHeader;

/** \brief a single match condition for a signature */
typedef struct SigMatch_ {
    uint16_t idx; /**< position in the signature */
    uint8_t type; /**< match type */
    void *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

/** \brief Signature container */
typedef struct Signature_ {
    union {
        struct {
            uint32_t flags;
            uint16_t mpm_pattern_id_div_8;
            uint8_t mpm_pattern_id_mod_8;
            SignatureMask mask;
        };
        uint64_t hdr_copy1;
    };
    union {
        struct {
            uint16_t alproto;
            SigIntId num; /**< signature number, internal id */
        };
        uint32_t hdr_copy2;
    };
    union {
        struct {
            SigIntId order_id;

            /** inline -- action */
            uint8_t action;
            uint8_t file_flags;
        };
        uint32_t hdr_copy3;
    };

    /* the fast pattern added from this signature */
    SigMatch *mpm_sm;

    /** ipv4 match arrays */
    DetectMatchAddressIPv4 *addr_dst_match4;
    uint16_t addr_dst_match4_cnt;
    DetectMatchAddressIPv4 *addr_src_match4;
    uint16_t addr_src_match4_cnt;
    /** ipv6 match arrays */
    DetectMatchAddressIPv6 *addr_dst_match6;
    uint16_t addr_dst_match6_cnt;
    DetectMatchAddressIPv6 *addr_src_match6;
    uint16_t addr_src_match6_cnt;

    /** port settings for this signature */
    DetectPort *sp, *dp;

    /** addresses, ports and proto this sig matches on */
    DetectProto proto;

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *CidrSrc, *CidrDst;

    /* helper for init phase */
    uint16_t mpm_content_maxlen;
    uint16_t mpm_uricontent_maxlen;

    /** number of sigmatches in the match and pmatch list */
    uint16_t sm_cnt;

    uint32_t id;  /**< sid, set by the 'sid' rule keyword */
    uint32_t gid; /**< generator id */
    uint32_t rev;

    /** classification id **/
    uint8_t class;

    int prio;

    char *msg;

    /** classification message */
    char *class_msg;

    /** Reference */
    DetectReference *references;

    /* Be careful, this pointer is only valid while parsing the sig,
     * to warn the user about any possible problem */
    char *sig_str;

#ifdef PROFILING
    uint16_t profiling_id;
#endif

    /* holds all sm lists */
    struct SigMatch_ *sm_lists[DETECT_SM_LIST_MAX];
    /* holds all sm lists' tails */
    struct SigMatch_ *sm_lists_tail[DETECT_SM_LIST_MAX];

    /** address settings for this signature */
    DetectAddressHead src, dst;

    /* used to hold flags that are predominantly used during init */
    uint32_t init_flags;

    /** ptr to the next sig in the list */
    struct Signature_ *next;
} Signature;

typedef struct DetectReplaceList_ {
    struct DetectContentData_ *cd;
    uint8_t *found;
    struct DetectReplaceList_ *next;
} DetectReplaceList;

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

/* mpm pattern id api */
typedef struct MpmPatternIdStore_ {
    HashTable *hash;
    PatIntId max_id;

    uint32_t unique_patterns;
    uint32_t shared_patterns;
} MpmPatternIdStore;

/** \brief threshold ctx */
typedef struct ThresholdCtx_    {
    HashListTable *threshold_hash_table_dst;        /**< Ipv4 dst hash table */
    HashListTable *threshold_hash_table_src;        /**< Ipv4 src hash table */
    HashListTable *threshold_hash_table_dst_ipv6;   /**< Ipv6 dst hash table */
    HashListTable *threshold_hash_table_src_ipv6;   /**< Ipv6 src hash table */
    SCMutex threshold_table_lock;                   /**< Mutex for hash table */

    /** to support rate_filter "by_rule" option */
    DetectThresholdEntry **th_entry;
    uint32_t th_size;
} ThresholdCtx;

/** \brief tag ctx */
typedef struct DetectTagHostCtx_ {
    HashListTable *tag_hash_table_ipv4;   /**< Ipv4 hash table      */
    HashListTable *tag_hash_table_ipv6;   /**< Ipv6 hash table      */
    SCMutex lock;                         /**< Mutex for the ctx    */
    struct timeval last_ts;               /**< Last time the ctx was pruned */
} DetectTagHostCtx;

/** \brief main detection engine ctx */
typedef struct DetectEngineCtx_ {
    uint8_t flags;
    int failure_fatal;

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
    /* hash table used for holding the reference config info */
    HashTable *reference_conf_ht;

    /* main sigs */
    DetectEngineLookupFlow flow_gh[FLOW_STATES];

    uint32_t mpm_unique, mpm_reuse, mpm_none,
        mpm_uri_unique, mpm_uri_reuse, mpm_uri_none;
    uint32_t gh_unique, gh_reuse;

    uint32_t mpm_max_patcnt, mpm_min_patcnt, mpm_tot_patcnt,
        mpm_uri_max_patcnt, mpm_uri_min_patcnt, mpm_uri_tot_patcnt;

    /* init phase vars */
    HashListTable *sgh_hash_table;

    HashListTable *sgh_mpm_hash_table;
    HashListTable *sgh_mpm_uri_hash_table;
    HashListTable *sgh_mpm_stream_hash_table;

    HashListTable *sgh_sport_hash_table;
    HashListTable *sgh_dport_hash_table;

    HashListTable *sport_hash_table;
    HashListTable *dport_hash_table;

    /* hash table used to cull out duplicate sigs */
    HashListTable *dup_sig_hash_table;

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
/*
    uint16_t max_uniq_small_toclient_src_groups;
    uint16_t max_uniq_small_toclient_dst_groups;
    uint16_t max_uniq_small_toclient_sp_groups;
    uint16_t max_uniq_small_toclient_dp_groups;

    uint16_t max_uniq_small_toserver_src_groups;
    uint16_t max_uniq_small_toserver_dst_groups;
    uint16_t max_uniq_small_toserver_sp_groups;
    uint16_t max_uniq_small_toserver_dp_groups;
*/

    /* specify the configuration for mpm context factory */
    uint8_t sgh_mpm_context;

    /** hash table for looking up patterns for
     *  id sharing and id tracking. */
    MpmPatternIdStore *mpm_pattern_id_store;

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
    int32_t sgh_mpm_context_app_proto_detect;

    /** sgh for signatures that match against invalid packets. In those cases
     *  we can't lookup by proto, address, port as we don't have these */
    struct SigGroupHead_ *decoder_event_sgh;
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

#define DETECT_FILESTORE_MAX 15

/**
  * Detection engine thread data.
  */
typedef struct DetectionEngineThreadCtx_ {
    /* the thread to which this detection engine thread belongs */
    ThreadVars *tv;

    /* detection engine variables */

    /** offset into the payload of the last match by:
     *  content, pcre, etc */
    uint32_t buffer_offset;
    /* used by pcre match function alone */
    uint32_t pcre_match_start_offset;

    uint8_t **hcbd_buffers;
    uint32_t *hcbd_buffers_len;
    uint16_t hcbd_buffers_list_len;

    /* counter for the filestore array below -- up here for cache reasons. */
    uint16_t filestore_cnt;

    uint16_t hhd_buffers_list_len;
    uint16_t hsbd_buffers_list_len;
    uint8_t **hsbd_buffers;
    uint32_t *hsbd_buffers_len;

    uint8_t **hhd_buffers;
    uint32_t *hhd_buffers_len;

    /** id for alert counter */
    uint16_t counter_alerts;

    /* used to discontinue any more matching */
    uint16_t discontinue_matching;
    uint16_t flags;

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
    PatternMatcherQueue smsg_pmq[256];

    /** ID of the transaction currently being inspected. */
    uint16_t tx_id;

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

    /** ip only rules ctx */
    DetectEngineIPOnlyThreadCtx io_ctx;

    /* byte jump values */
    uint64_t *bj_values;

    /* string to replace */
    DetectReplaceList *replist;

    /* Array in which the filestore keyword stores file id and tx id. If the
     * full signature matches, these are processed by a post-match filestore
     * function to finalize the store. */
    struct {
        uint16_t file_id;
        uint16_t tx_id;
    } filestore[DETECT_FILESTORE_MAX];
    SigMatch *filestore_sm;

    DetectEngineCtx *de_ctx;
#ifdef __SC_CUDA_SUPPORT__
    /* each detection thread would have it's own queue where the cuda dispatcher
     * thread can dump the packets once it has processed them */
    Tmq *cuda_mpm_rc_disp_outq;
#endif
} DetectEngineThreadCtx;

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

#define SIG_GROUP_HAVECONTENT           0x00000001
#define SIG_GROUP_HAVEURICONTENT        0x00000002
#define SIG_GROUP_HAVESTREAMCONTENT     0x00000004
#define SIG_GROUP_HAVEHCBDCONTENT       0x00000008
#define SIG_GROUP_HAVEHHDCONTENT        0x00000010
#define SIG_GROUP_HAVEHRHDCONTENT       0x00000020
#define SIG_GROUP_HAVEHMDCONTENT        0x00000040
#define SIG_GROUP_HAVEHCDCONTENT        0x00000080
#define SIG_GROUP_HAVEHRUDCONTENT       0x00000100
#define SIG_GROUP_HEAD_MPM_COPY         0x00000200
#define SIG_GROUP_HEAD_MPM_URI_COPY     0x00000400
#define SIG_GROUP_HEAD_MPM_STREAM_COPY  0x00000800
#define SIG_GROUP_HEAD_FREE             0x00001000
#define SIG_GROUP_HEAD_MPM_PACKET       0x00002000
#define SIG_GROUP_HEAD_MPM_STREAM       0x00004000
#define SIG_GROUP_HEAD_MPM_URI          0x00008000
#define SIG_GROUP_HEAD_MPM_HCBD         0x00010000
#define SIG_GROUP_HEAD_MPM_HHD          0x00020000
#define SIG_GROUP_HEAD_MPM_HRHD         0x00040000
#define SIG_GROUP_HEAD_MPM_HMD          0x00080000
#define SIG_GROUP_HEAD_MPM_HCD          0x00100000
#define SIG_GROUP_HEAD_MPM_HRUD         0x00200000
#define SIG_GROUP_HEAD_REFERENCED       0x00400000 /**< sgh is being referenced by others, don't clear */
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    0x00800000
#define SIG_GROUP_HAVEHSBDCONTENT       0x01000000
#define SIG_GROUP_HEAD_MPM_HSBD         0x02000000
#define SIG_GROUP_HAVEHSMDCONTENT       0x04000000
#define SIG_GROUP_HEAD_MPM_HSMD         0x08000000
#define SIG_GROUP_HAVEHSCDCONTENT       0x10000000
#define SIG_GROUP_HEAD_MPM_HSCD         0x20000000

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
    uint8_t *stream_content_array;
    uint32_t stream_content_size;

    /* "Normal" detection uses these only at init, but ip-only
     * uses it during runtime as well, thus not in init... */
    uint8_t *sig_array; /**< bit array of sig nums (internal id's) */
    uint32_t sig_size; /**< size in bytes */

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

/** \brief Container for matching data for a signature group */
typedef struct SigGroupHead_ {
    uint32_t flags;
    /* number of sigs in this head */
    SigIntId sig_cnt;

    uint16_t mpm_content_maxlen;

    /** array of masks, used to check multiple masks against
     *  a packet using SIMD. */
#if defined(__SSE3__)
    SignatureMask *mask_array;
#endif
    /** chunk of memory containing the "header" part of each
     *  signature ordered as an array. Used to pre-filter the
     *  signatures to be inspected in a cache efficient way. */
    SignatureHeader *head_array;

    /* pattern matcher instances */
    MpmCtx *mpm_proto_other_ctx;

    MpmCtx *mpm_proto_tcp_ctx_ts;
    MpmCtx *mpm_proto_udp_ctx_ts;
    MpmCtx *mpm_stream_ctx_ts;
    MpmCtx *mpm_uri_ctx_ts;
    MpmCtx *mpm_hcbd_ctx_ts;
    MpmCtx *mpm_hsbd_ctx_ts;
    MpmCtx *mpm_hhd_ctx_ts;
    MpmCtx *mpm_hrhd_ctx_ts;
    MpmCtx *mpm_hmd_ctx_ts;
    MpmCtx *mpm_hcd_ctx_ts;
    MpmCtx *mpm_hrud_ctx_ts;
    MpmCtx *mpm_hsmd_ctx_ts;
    MpmCtx *mpm_hscd_ctx_ts;

    MpmCtx *mpm_proto_tcp_ctx_tc;
    MpmCtx *mpm_proto_udp_ctx_tc;
    MpmCtx *mpm_stream_ctx_tc;
    MpmCtx *mpm_uri_ctx_tc;
    MpmCtx *mpm_hcbd_ctx_tc;
    MpmCtx *mpm_hsbd_ctx_tc;
    MpmCtx *mpm_hhd_ctx_tc;
    MpmCtx *mpm_hrhd_ctx_tc;
    MpmCtx *mpm_hmd_ctx_tc;
    MpmCtx *mpm_hcd_ctx_tc;
    MpmCtx *mpm_hrud_ctx_tc;
    MpmCtx *mpm_hsmd_ctx_tc;
    MpmCtx *mpm_hscd_ctx_tc;

    uint16_t mpm_uricontent_maxlen;

    /** the number of signatures in this sgh that have the filestore keyword
     *  set. */
    uint16_t filestore_cnt;

    /** Array with sig ptrs... size is sig_cnt * sizeof(Signature *) */
    Signature **match_array;

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
    DETECT_AL_SSH_PROTOVERSION,
    DETECT_AL_SSH_SOFTWAREVERSION,
    DETECT_AL_SSL_VERSION,
    DETECT_AL_SSL_STATE,
    DETECT_BYTE_EXTRACT,
    DETECT_FILE_DATA,
    DETECT_AL_APP_LAYER_EVENT,

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
int SigGroupCleanup (DetectEngineCtx *de_ctx);
void SigAddressPrepareBidirectionals (DetectEngineCtx *);

int SigLoadSignatures (DetectEngineCtx *, char *, int);
void SigTableList(void);
void SigTableSetup(void);
int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);

int SignatureIsIPOnly(DetectEngineCtx *de_ctx, Signature *s);
SigGroupHead *SigMatchSignaturesGetSgh(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p);

Signature *DetectGetTagSignature(void);

int SignatureIsFilestoring(Signature *);
int SignatureIsFilemagicInspecting(Signature *);

#endif /* __DETECT_H__ */

