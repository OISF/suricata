/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_IPV4_H__
#define __DECODE_IPV4_H__

#define IPV4_HEADER_LEN           20    /**< Header length */
#define IPV4_OPTMAX               40    /**< Max options length */
#define	IPV4_MAXPACKET_LEN        65535 /**< Maximum packet size */

/** IP Option Types */
#define IPV4_OPT_EOL              0x00  /**< Option: End of List */
#define IPV4_OPT_NOP              0x01  /**< Option: No op */
#define IPV4_OPT_RR               0x07  /**< Option: Record Route */
#define IPV4_OPT_QS               0x19  /**< Option: Quick Start */
#define IPV4_OPT_TS               0x44  /**< Option: Timestamp */
#define IPV4_OPT_SEC              0x82  /**< Option: Security */
#define IPV4_OPT_LSRR             0x83  /**< Option: Loose Source Route */
#define IPV4_OPT_CIPSO            0x86  /**< Option: Commercial IP Security */
#define IPV4_OPT_SID              0x88  /**< Option: Stream Identifier */
#define IPV4_OPT_SSRR             0x89  /**< Option: Strict Source Route */
#define IPV4_OPT_RTRALT           0x94  /**< Option: Router Alert */

/** IP Option Lengths (fixed) */
#define IPV4_OPT_SEC_LEN          11    /**< SEC Option Fixed Length */
#define IPV4_OPT_SID_LEN          4     /**< SID Option Fixed Length */
#define IPV4_OPT_RTRALT_LEN       4     /**< RTRALT Option Fixed Length */

/** IP Option Lengths (variable) */
#define IPV4_OPT_ROUTE_MIN        3     /**< RR, SRR, LTRR Option Min Length */
#define IPV4_OPT_QS_MIN           8     /**< QS Option Min Length */
#define IPV4_OPT_TS_MIN           5     /**< TS Option Min Length */
#define IPV4_OPT_CIPSO_MIN        10    /**< CIPSO Option Min Length */

/** IP Option fields */
#define IPV4_OPTS                 ip4vars.ip_opts
#define IPV4_OPTS_CNT             ip4vars.ip_opt_cnt

typedef struct IPV4Opt_ {
    /** \todo We may want to break type up into its 3 fields
     *        as the reassembler may want to know which options
     *        must be copied to each fragment.
     */
    uint8_t type;         /**< option type */
    uint8_t len;          /**< option length (type+len+data) */
    uint8_t *data;        /**< option data */
} IPV4Opt;

typedef struct IPV4Hdr_
{
    uint8_t ip_verhl;     /**< version & header length */
    uint8_t ip_tos;       /**< type of service */
    uint16_t ip_len;      /**< length */
    uint16_t ip_id;       /**< id */
    uint16_t ip_off;      /**< frag offset */
    uint8_t ip_ttl;       /**< time to live */
    uint8_t ip_proto;     /**< protocol (tcp, udp, etc) */
    uint16_t ip_csum;     /**< checksum */
    struct in_addr ip_src;/**< source address */
    struct in_addr ip_dst;/**< destination address */
} IPV4Hdr;

#define IPV4_GET_RAW_VER(ip4h)            (((ip4h)->ip_verhl & 0xf0) >> 4)
#define IPV4_GET_RAW_HLEN(ip4h)           ((ip4h)->ip_verhl & 0x0f)
#define IPV4_GET_RAW_IPTOS(ip4h)          ((ip4h)->ip_tos)
#define IPV4_GET_RAW_IPLEN(ip4h)          ((ip4h)->ip_len)
#define IPV4_GET_RAW_IPID(ip4h)           ((ip4h)->ip_id)
#define IPV4_GET_RAW_IPOFFSET(ip4h)       ((ip4h)->ip_off)
#define IPV4_GET_RAW_IPTTL(ip4h)          ((ip4h)->ip_ttl)
#define IPV4_GET_RAW_IPPROTO(ip4h)        ((ip4h)->ip_proto)
#define IPV4_GET_RAW_IPSRC(ip4h)          ((ip4h)->ip_src)
#define IPV4_GET_RAW_IPDST(ip4h)          ((ip4h)->ip_dst)

/* we need to change them as well as get them */
#define IPV4_SET_RAW_VER(ip4h, value)     ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0x0f) | (value << 4)))
#define IPV4_SET_RAW_HLEN(ip4h, value)    ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0xf0) | (value & 0x0f)))
#define IPV4_SET_RAW_IPTOS(ip4h, value)   ((ip4h)->ip_tos = value)
#define IPV4_SET_RAW_IPLEN(ip4h, value)   ((ip4h)->ip_len = value)
#define IPV4_SET_RAW_IPPROTO(ip4h, value) ((ip4h)->ip_proto = value)

/* this is enough since noone will access the cache without first
 * checking the flags */
#define IPV4_CACHE_INIT(p)                (p)->ip4c.flags = 0

/* ONLY call these functions after making sure that:
 * 1. p->ip4h is set
 * 2. p->ip4h is valid (len is correct)
 * 3. cache is initialized
 */
#define IPV4_GET_VER(p) \
    ((p)->ip4c.flags & IPV4_CACHE_VER ? \
    (p)->ip4c.ver : ((p)->ip4c.flags |= IPV4_CACHE_VER, (p)->ip4c.ver = IPV4_GET_RAW_VER((p)->ip4h)))
#define IPV4_GET_HLEN(p) \
    ((p)->ip4c.flags & IPV4_CACHE_HLEN ? \
    (p)->ip4c.hl : ((p)->ip4c.flags |= IPV4_CACHE_HLEN, (p)->ip4c.hl = IPV4_GET_RAW_HLEN((p)->ip4h) << 2))
#define IPV4_GET_IPTOS(p) \
     IPV4_GET_RAW_IPTOS(p)
#define IPV4_GET_IPLEN(p) \
    ((p)->ip4c.flags & IPV4_CACHE_IPLEN ? \
    (p)->ip4c.ip_len : ((p)->ip4c.flags |= IPV4_CACHE_IPLEN, (p)->ip4c.ip_len = ntohs(IPV4_GET_RAW_IPLEN((p)->ip4h))))
#define IPV4_GET_IPID(p) \
    ((p)->ip4c.flags & IPV4_CACHE_IPID ? \
    (p)->ip4c.ip_id : ((p)->ip4c.flags |= IPV4_CACHE_IPID, (p)->ip4c.ip_id = ntohs(IPV4_GET_RAW_IPID((p)->ip4h))))
/* _IPV4_GET_IPOFFSET: get the content of the offset header field in host order */
#define _IPV4_GET_IPOFFSET(p) \
    ((p)->ip4c.flags & IPV4_CACHE__IPOFF ? \
    (p)->ip4c._ip_off : ((p)->ip4c.flags |= IPV4_CACHE__IPOFF, (p)->ip4c._ip_off = ntohs(IPV4_GET_RAW_IPOFFSET((p)->ip4h))))
/* IPV4_GET_IPOFFSET: get the final offset */
#define IPV4_GET_IPOFFSET(p) \
    ((p)->ip4c.flags & IPV4_CACHE_IPOFF ? \
    (p)->ip4c.ip_off : ((p)->ip4c.flags |= IPV4_CACHE_IPOFF, (p)->ip4c.ip_off = _IPV4_GET_IPOFFSET(p) & 0x1fff))
/* IPV4_GET_RF: get the RF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_RF(p) \
    ((p)->ip4c.flags & IPV4_CACHE_RF ? \
    (p)->ip4c.rf : ((p)->ip4c.flags |= IPV4_CACHE_RF, (p)->ip4c.rf = (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x8000) >> 15)))
/* IPV4_GET_DF: get the DF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_DF(p) \
    ((p)->ip4c.flags & IPV4_CACHE_DF ? \
    (p)->ip4c.df : ((p)->ip4c.flags |= IPV4_CACHE_DF, (p)->ip4c.df = (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x4000) >> 14)))
/* IPV4_GET_MF: get the MF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_MF(p) \
    ((p)->ip4c.flags & IPV4_CACHE_MF ? \
    (p)->ip4c.mf : ((p)->ip4c.flags |= IPV4_CACHE_MF, (p)->ip4c.mf = (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x2000) >> 13)))
#define IPV4_GET_IPTTL(p) \
     IPV4_GET_RAW_IPTTL(p->ip4h)
#define IPV4_GET_IPPROTO(p) \
    ((p)->ip4c.flags & IPV4_CACHE_IPPROTO ? \
    (p)->ip4c.ip_proto : ((p)->ip4c.flags |= IPV4_CACHE_IPPROTO, (p)->ip4c.ip_proto = IPV4_GET_RAW_IPPROTO((p)->ip4h)))

#define IPV4_CACHE_VER                    0x0001 /* 1 */
#define IPV4_CACHE_HLEN                   0x0002 /* 2 */
#define IPV4_CACHE_IPTOS                  0x0004 /* 4 */
#define IPV4_CACHE_IPLEN                  0x0008 /* 8 */
#define IPV4_CACHE_IPID                   0x0010 /* 16 */
#define IPV4_CACHE_IPOFF                  0x0020 /* 32 */
#define IPV4_CACHE__IPOFF                 0x0040 /* 64 */
#define IPV4_CACHE_RF                     0x0080 /* 128*/
#define IPV4_CACHE_DF                     0x0100 /* 256 */
#define IPV4_CACHE_MF                     0x0200 /* 512 */
#define IPV4_CACHE_IPTTL                  0x0400 /* 1024*/
#define IPV4_CACHE_IPPROTO                0x0800 /* 2048 */

/**
 * IPv4 decoder cache
 *
 * Used for storing parsed values.
 */
typedef struct IPV4Cache_
{
    uint16_t flags;

    uint8_t ver;
    uint8_t hl;
    uint8_t ip_tos;        /* type of service */
    uint16_t ip_len;       /* datagram length */
    uint16_t ip_id;        /* identification  */
    uint16_t ip_off;       /* fragment offset */
    uint16_t _ip_off;      /* fragment offset - full field value, host order*/
    uint8_t rf;
    uint8_t df;
    uint8_t mf;
    uint8_t ip_ttl;        /* time to live field */
    uint8_t ip_proto;      /* datagram protocol */
    uint16_t ip_csum;      /* checksum */
    int32_t comp_csum;     /* checksum computed over the ipv4 packet */
    uint32_t ip_src_u32;   /* source IP */
    uint32_t ip_dst_u32;   /* dest IP */

} IPV4Cache;

/* helper structure with parsed ipv4 info */
typedef struct IPV4Vars_
{
    uint8_t ip_opt_len;
    IPV4Opt ip_opts[IPV4_OPTMAX];
    uint8_t ip_opt_cnt;

    /* These are here for direct access and dup tracking */
    IPV4Opt *o_rr;
    IPV4Opt *o_qs;
    IPV4Opt *o_ts;
    IPV4Opt *o_sec;
    IPV4Opt *o_lsrr;
    IPV4Opt *o_cipso;
    IPV4Opt *o_sid;
    IPV4Opt *o_ssrr;
    IPV4Opt *o_rtralt;
} IPV4Vars;

inline uint16_t IPV4CalculateChecksum(uint16_t *, uint16_t);
void DecodeIPV4RegisterTests(void);

#endif /* __DECODE_IPV4_H__ */

