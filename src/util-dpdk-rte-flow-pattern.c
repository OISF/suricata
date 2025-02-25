/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 *
 *
 * Modifications by Adam Kiripolsky:
 * - The code is a modification of the parser for dpdk-testpmd application
 *   located in DPDK 25.11 source code at  dpdk/app/testpmd/cmdline_flow.c
 * - Simplified the parser and it's corresponding parts to parse only
 *   pattern instead of the whole test-pmd commands
 * - Add ParsePattern function to utilize the parser from outside
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:

 * - Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.

 * - Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.

 * - Neither the name of the Qualys, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  \defgroup dpdk pattern parser
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK parser for pattern
 *
 */

#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-rte-flow-pattern.h"

#ifdef HAVE_DPDK
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)

#include <cmdline_parse_etheraddr.h>

enum index {
    /* Special tokens. */
    ZERO = 0,
    END,

    /* Create tokens */
    CREATE,

    /* Common tokens. */
    COMMON_UNSIGNED,
    COMMON_MAC_ADDR,
    COMMON_IPV4_ADDR,
    COMMON_IPV6_ADDR,

    /* Validate/create pattern. */
    ITEM_PATTERN,
    ITEM_PARAM_IS,
    ITEM_PARAM_SPEC,
    ITEM_PARAM_LAST,
    ITEM_PARAM_MASK,
    ITEM_NEXT,
    ITEM_END,
    ITEM_VOID,
    ITEM_ANY,
    ITEM_PORT_ID,
    ITEM_ETH,
    ITEM_ETH_DST,
    ITEM_ETH_SRC,
    ITEM_ETH_TYPE,
    ITEM_ETH_HAS_VLAN,
    ITEM_RAW,
    ITEM_VLAN,
    ITEM_IPV4,
    ITEM_IPV4_SRC,
    ITEM_IPV4_DST,
    ITEM_IPV6,
    ITEM_IPV6_SRC,
    ITEM_IPV6_DST,
    ITEM_ICMP,
    ITEM_ICMP_TYPE,
    ITEM_ICMP_CODE,
    ITEM_ICMP_IDENT,
    ITEM_ICMP_SEQ,
    ITEM_ICMP6,
    ITEM_ICMP6_TYPE,
    ITEM_ICMP6_CODE,
    ITEM_UDP,
    ITEM_UDP_SRC,
    ITEM_UDP_DST,
    ITEM_TCP,
    ITEM_TCP_SRC,
    ITEM_TCP_DST,
    ITEM_TCP_FLAGS,
    ITEM_SCTP,
    ITEM_SCTP_SRC,
    ITEM_SCTP_DST,
    ITEM_SCTP_TAG,
    ITEM_SCTP_CKSUM,
    ITEM_VXLAN,
    ITEM_E_TAG,
    ITEM_NVGRE,
    ITEM_MPLS,
    ITEM_GRE,
    ITEM_FUZZY,
    ITEM_GTP,
    ITEM_GTPC,
    ITEM_GTPU,
    ITEM_GENEVE,
    ITEM_VXLAN_GPE,
};

static const enum index item_param[] = {
    ITEM_PARAM_IS,
    ITEM_PARAM_SPEC,
    ITEM_PARAM_LAST,
    ITEM_PARAM_MASK,
    ZERO,
};

static const enum index next_item[] = {
    ITEM_END,
    ITEM_VOID,
    ITEM_ANY,
    ITEM_PORT_ID,
    ITEM_ETH,
    ITEM_RAW,
    ITEM_VLAN,
    ITEM_IPV4,
    ITEM_IPV6,
    ITEM_ICMP,
    ITEM_ICMP6,
    ITEM_UDP,
    ITEM_TCP,
    ITEM_SCTP,
    ITEM_VXLAN,
    ITEM_E_TAG,
    ITEM_NVGRE,
    ITEM_MPLS,
    ITEM_GRE,
    ITEM_FUZZY,
    ITEM_GTP,
    ITEM_GTPC,
    ITEM_GTPU,
    ITEM_GENEVE,
    ITEM_VXLAN_GPE,
    ZERO,
};

static const enum index item_any[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_port_id[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_eth[] = {
    ITEM_ETH_DST,
    ITEM_ETH_SRC,
    ITEM_ETH_TYPE,
    ITEM_ETH_HAS_VLAN,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_raw[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_vlan[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_ipv4[] = {
    ITEM_IPV4_SRC,
    ITEM_IPV4_DST,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_ipv6[] = {
    ITEM_IPV6_SRC,
    ITEM_IPV6_DST,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_icmp[] = {
    ITEM_ICMP_TYPE,
    ITEM_ICMP_CODE,
    ITEM_ICMP_IDENT,
    ITEM_ICMP_SEQ,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_icmp6[] = {
    ITEM_ICMP6_TYPE,
    ITEM_ICMP6_CODE,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_udp[] = {
    ITEM_UDP_SRC,
    ITEM_UDP_DST,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_tcp[] = {
    ITEM_TCP_SRC,
    ITEM_TCP_DST,
    ITEM_TCP_FLAGS,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_sctp[] = {
    ITEM_SCTP_SRC,
    ITEM_SCTP_DST,
    ITEM_SCTP_TAG,
    ITEM_SCTP_CKSUM,
    ITEM_NEXT,
    ZERO,
};

static const enum index item_vxlan[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_e_tag[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_nvgre[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_mpls[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_gre[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_gtp[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_gtpc[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_gtpu[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_geneve[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_fuzzy[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index item_vxlan_gpe[] = {
    ITEM_NEXT,
    ZERO,
};

static const enum index next_vc_attr[] = {
    ITEM_PATTERN,
    ZERO,
};

/** Maximum number of subsequent tokens and arguments on the stack. */
#define CTX_STACK_SIZE 16

/** Maximum size for pattern in struct rte_flow_item_raw. */
#define ITEM_RAW_PATTERN_SIZE 512

/** Static initializer for the args field. */
#define ARGS(...)                                                                                  \
    (const struct arg *const[])                                                                    \
    {                                                                                              \
        __VA_ARGS__, NULL,                                                                         \
    }

/** Same as ARGS_ENTRY() using network byte ordering. */
#define ARGS_ENTRY_HTON(s, f)                                                                      \
    (&(const struct arg){                                                                          \
            .hton = 1,                                                                             \
            .offset = offsetof(s, f),                                                              \
            .size = sizeof(((s *)0)->f),                                                           \
    })

/** Same as ARGS_ENTRY_HTON() for a single argument, without structure. */
#define ARG_ENTRY_HTON(s)                                                                          \
    (&(const struct arg){                                                                          \
            .hton = 1,                                                                             \
            .offset = 0,                                                                           \
            .size = sizeof(s),                                                                     \
    })

#define PRIV_ITEM(t, s)                                                                            \
    (&(const struct parse_item_priv){                                                              \
            .type = RTE_FLOW_ITEM_TYPE_##t,                                                        \
            .size = s,                                                                             \
    })

/** Static initializer for the args field. */
#define ARGS(...)                                                                                  \
    (const struct arg *const[])                                                                    \
    {                                                                                              \
        __VA_ARGS__, NULL,                                                                         \
    }

/** Static initializer for ARGS() to target a field. */
#define ARGS_ENTRY(s, f)                                                                           \
    (&(const struct arg){                                                                          \
            .offset = offsetof(s, f),                                                              \
            .size = sizeof(((s *)0)->f),                                                           \
    })

/** Static initializer for ARGS() to target a bit-field. */
#define ARGS_ENTRY_BF(s, f, b)                                                                     \
    (&(const struct arg){                                                                          \
            .size = sizeof(s),                                                                     \
            .mask = (const void *)&(const s){ .f = (1 << (b)) - 1 },                               \
    })

/** Static initializer for the next field. */
#define NEXT(...)                                                                                  \
    (const enum index *const[])                                                                    \
    {                                                                                              \
        __VA_ARGS__, NULL,                                                                         \
    }

/** Static initializer for a NEXT() entry. */
#define NEXT_ENTRY(...)                                                                            \
    (const enum index[])                                                                           \
    {                                                                                              \
        __VA_ARGS__, ZERO,                                                                         \
    }

/** Storage size for struct rte_flow_item_raw including pattern. */
#define ITEM_RAW_SIZE (sizeof(struct rte_flow_item_raw) + ITEM_RAW_PATTERN_SIZE)

/** Token argument. */
struct arg {
    uint32_t hton : 1;    /**< Use network byte ordering. */
    uint32_t sign : 1;    /**< Value is signed. */
    uint32_t bounded : 1; /**< Value is bounded. */
    uintmax_t min;        /**< Minimum value if bounded. */
    uintmax_t max;        /**< Maximum value if bounded. */
    uint32_t offset;      /**< Relative offset from ctx->object. */
    uint32_t size;        /**< Field size. */
    const uint8_t *mask;  /**< Bit-mask to use instead of offset/size. */
};

struct buffer {
    enum index command; /**< Flow command. */
    union {
        struct {
            struct rte_flow_attr attr;
            struct rte_flow_item *pattern;
            uint32_t pattern_n;
            uint8_t *data;
        } vc; /**< Validate/create arguments. */

    } args; /**< Command arguments. */
};

/** Parser context. */
struct context {
    /** Stack of subsequent token lists to process. */
    const enum index *next[CTX_STACK_SIZE];
    /** Arguments for stacked tokens. */
    const void *args[CTX_STACK_SIZE];
    enum index curr;   /**< Current token index. */
    enum index prev;   /**< Index of the last token seen. */
    int next_num;      /**< Number of entries in next[]. */
    int args_num;      /**< Number of entries in args[]. */
    uint32_t eol : 1;  /**< EOL has been detected. */
    uint32_t last : 1; /**< No more arguments. */
    uint16_t port;     /**< Current port ID (for completions). */
    uint32_t objdata;  /**< Object-specific data. */
    void *object;      /**< Address of current object for relative offsets. */
    void *objmask;     /**< Object a full mask must be written to. */
};

static struct context cmd_flow_context;

/** Initialize context. */
static void cmd_flow_context_init(struct context *ctx)
{
    /* A full memset() is not necessary. */
    ctx->curr = ZERO;
    ctx->prev = ZERO;
    ctx->next_num = 0;
    ctx->args_num = 0;
    ctx->eol = 0;
    ctx->last = 0;
    ctx->objdata = 0;
    ctx->object = NULL;
    ctx->objmask = NULL;
}

struct token {
    /** Type displayed during completion (defaults to "TOKEN"). */
    const char *type;
    /** Private data used by parser functions. */
    const void *priv;
    /**
     * Lists of subsequent tokens to push on the stack. Each call to the
     * parser consumes the last entry of that stack.
     */
    const enum index *const *next;
    /** Arguments stack for subsequent tokens that need them. */
    const struct arg *const *args;
    /**
     * Token-processing callback, returns -1 in case of error, the
     * length of the matched string otherwise. If NULL, attempts to
     * match the token name.
     *
     * If buf is not NULL, the result should be stored in it according
     * to context. An error is returned if not large enough.
     */
    int (*call)(struct context *ctx, const struct token *token, const char *str, unsigned int len,
            void *buf, unsigned int size);
    /** Mandatory token name, no default value. */
    const char *name;
};

/**
 * Maximum IPv6 address size in bytes.
 */
#define RTE_IPV6_ADDR_SIZE 16

#if RTE_VERSION < RTE_VERSION_NUM(24, 0, 0, 0)
/**
 * IPv6 Address
 */
struct rte_ipv6_addr {
    uint8_t a[RTE_IPV6_ADDR_SIZE];
};
#endif /* RTE_VERSION < RTE_VERSION_NUM(24, 0, 0, 0) */

struct parse_item_priv {
    enum rte_flow_item_type type; /**< Item type. */
    uint32_t size;                /**< Size of item specification structure. */
};

static int parse_vc(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_vc_spec(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_init(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_int(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_mac_addr(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_ipv4_addr(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);
static int parse_ipv6_addr(
        struct context *, const struct token *, const char *, unsigned int, void *, unsigned int);

static int parse_default(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size);

static const struct token token_list[] = {

    /* Starts parsing from ITEM_PATTERN */
	[ZERO] = {
		.name = "ZERO",
		.next = NEXT(NEXT_ENTRY(ITEM_PATTERN)),
	},
	/* Create Token, not used directly */
	[CREATE] = {
		.name = "create",
		.next = NEXT(next_vc_attr),
		.call = parse_vc,
	},	
    /* Common tokens. */
	[COMMON_UNSIGNED] = {
		.name = "{unsigned}",
		.type = "UNSIGNED",
		.call = parse_int,
	},
	[COMMON_MAC_ADDR] = {
		.name = "{MAC address}",
		.type = "MAC-48",
		.call = parse_mac_addr,
	},
	[COMMON_IPV4_ADDR] = {
		.name = "{IPv4 address}",
		.type = "IPV4 ADDRESS",
		.call = parse_ipv4_addr,
	},
	[COMMON_IPV6_ADDR] = {
		.name = "{IPv6 address}",
		.type = "IPV6 ADDRESS",
		.call = parse_ipv6_addr,
	},
	/* Validate/create pattern. */
	[ITEM_PATTERN] = {
		.name = "pattern",
		.next = NEXT(next_item),
		.call = parse_init,
	},
	[ITEM_PARAM_IS] = {
		.name = "is",
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_SPEC] = {
		.name = "spec",
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_LAST] = {
		.name = "last",
		.call = parse_vc_spec,
	},
	[ITEM_PARAM_MASK] = {
		.name = "mask",
		.call = parse_vc_spec,
	},
	[ITEM_NEXT] = {
		.name = "/",
		.next = NEXT(next_item),
	},
    [ITEM_END] = {
		.name = "end",
		.priv = PRIV_ITEM(END, 0),
		.next = NEXT(NEXT_ENTRY(END)),
		.call = parse_vc,
	},
	[ITEM_VOID] = {
		.name = "void",
		.priv = PRIV_ITEM(VOID, 0),
		.next = NEXT(NEXT_ENTRY(ITEM_NEXT)),
		.call = parse_vc,
	},
	[ITEM_ANY] = {
		.name = "any",
		.priv = PRIV_ITEM(ANY, sizeof(struct rte_flow_item_any)),
		.next = NEXT(item_any),
		.call = parse_vc,
	},
	[ITEM_PORT_ID] = {
		.name = "port_id",
		.priv = PRIV_ITEM(PORT_ID,
				  sizeof(struct rte_flow_item_port_id)),
		.next = NEXT(item_port_id),
		.call = parse_vc,
	},
	[ITEM_RAW] = {
		.name = "raw",
		.priv = PRIV_ITEM(RAW, ITEM_RAW_SIZE),
		.next = NEXT(item_raw),
		.call = parse_vc,
	},
	[ITEM_ETH] = {
		.name = "eth",
		.priv = PRIV_ITEM(ETH, sizeof(struct rte_flow_item_eth)),
		.next = NEXT(item_eth),
		.call = parse_vc,
	},
	[ITEM_ETH_SRC] = {
		.name = "src",
		.next = NEXT(item_eth, NEXT_ENTRY(COMMON_MAC_ADDR), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_eth, hdr.src_addr)),
	},
	[ITEM_ETH_DST] = {
		.name = "dst",
		.next = NEXT(item_eth, NEXT_ENTRY(COMMON_MAC_ADDR), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_eth, hdr.dst_addr)),
	},
	[ITEM_ETH_TYPE] = {
		.name = "type",
		.next = NEXT(item_eth, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_eth, hdr.ether_type)),
	},
	[ITEM_ETH_HAS_VLAN] = {
		.name = "has_vlan",
		.next = NEXT(item_eth, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_BF(struct rte_flow_item_eth,
					   has_vlan, 1)),
	},
	[ITEM_VLAN] = {
		.name = "vlan",
		.priv = PRIV_ITEM(VLAN, sizeof(struct rte_flow_item_vlan)),
		.next = NEXT(item_vlan),
		.call = parse_vc,
	},
	[ITEM_IPV4] = {
		.name = "ipv4",
		.priv = PRIV_ITEM(IPV4, sizeof(struct rte_flow_item_ipv4)),
		.next = NEXT(item_ipv4),
		.call = parse_vc,
	},
	[ITEM_IPV4_SRC] = {
		.name = "src",
		.next = NEXT(item_ipv4, NEXT_ENTRY(COMMON_IPV4_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv4,
					     hdr.src_addr)),
	},
	[ITEM_IPV4_DST] = {
		.name = "dst",
		.next = NEXT(item_ipv4, NEXT_ENTRY(COMMON_IPV4_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv4,
					     hdr.dst_addr)),
	},
	[ITEM_IPV6] = {
		.name = "ipv6",
		.priv = PRIV_ITEM(IPV6, sizeof(struct rte_flow_item_ipv6)),
		.next = NEXT(item_ipv6),
		.call = parse_vc,
	},
	[ITEM_IPV6_SRC] = {
		.name = "src",
		.next = NEXT(item_ipv6, NEXT_ENTRY(COMMON_IPV6_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv6,
					     hdr.src_addr)),
	},
	[ITEM_IPV6_DST] = {
		.name = "dst",
		.next = NEXT(item_ipv6, NEXT_ENTRY(COMMON_IPV6_ADDR),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_ipv6,
					     hdr.dst_addr)),
	},
	[ITEM_ICMP] = {
		.name = "icmp",
		.priv = PRIV_ITEM(ICMP, sizeof(struct rte_flow_item_icmp)),
		.next = NEXT(item_icmp),
		.call = parse_vc,
	},
	[ITEM_ICMP_TYPE] = {
		.name = "type",
		.next = NEXT(item_icmp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_icmp,
					     hdr.icmp_type)),
	},
	[ITEM_ICMP_CODE] = {
		.name = "code",
		.next = NEXT(item_icmp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_icmp,
					     hdr.icmp_code)),
	},
	[ITEM_ICMP_IDENT] = {
		.name = "ident",
		.next = NEXT(item_icmp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_icmp,
					     hdr.icmp_ident)),
	},
	[ITEM_ICMP_SEQ] = {
		.name = "seq",
		.next = NEXT(item_icmp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_icmp,
					     hdr.icmp_seq_nb)),
	},
	[ITEM_UDP] = {
		.name = "udp",
		.priv = PRIV_ITEM(UDP, sizeof(struct rte_flow_item_udp)),
		.next = NEXT(item_udp),
		.call = parse_vc,
	},
	[ITEM_UDP_SRC] = {
		.name = "src",
		.next = NEXT(item_udp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_udp,
					     hdr.src_port)),
	},
	[ITEM_UDP_DST] = {
		.name = "dst",
		.next = NEXT(item_udp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_udp,
					     hdr.dst_port)),
	},
	[ITEM_TCP] = {
		.name = "tcp",
		.priv = PRIV_ITEM(TCP, sizeof(struct rte_flow_item_tcp)),
		.next = NEXT(item_tcp),
		.call = parse_vc,
	},
	[ITEM_TCP_SRC] = {
		.name = "src",
		.next = NEXT(item_tcp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_tcp,
					     hdr.src_port)),
	},
	[ITEM_TCP_DST] = {
		.name = "dst",
		.next = NEXT(item_tcp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_tcp,
					     hdr.dst_port)),
	},
	[ITEM_TCP_FLAGS] = {
		.name = "flags",
		.next = NEXT(item_tcp, NEXT_ENTRY(COMMON_UNSIGNED), item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_tcp,
					     hdr.tcp_flags)),
	},
	[ITEM_SCTP] = {
		.name = "sctp",
		.priv = PRIV_ITEM(SCTP, sizeof(struct rte_flow_item_sctp)),
		.next = NEXT(item_sctp),
		.call = parse_vc,
	},
	[ITEM_SCTP_SRC] = {
		.name = "src",
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.src_port)),
	},
	[ITEM_SCTP_DST] = {
		.name = "dst",
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.dst_port)),
	},
	[ITEM_SCTP_TAG] = {
		.name = "tag",
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.tag)),
	},
	[ITEM_SCTP_CKSUM] = {
		.name = "cksum",
		.next = NEXT(item_sctp, NEXT_ENTRY(COMMON_UNSIGNED),
			     item_param),
		.args = ARGS(ARGS_ENTRY_HTON(struct rte_flow_item_sctp,
					     hdr.cksum)),
	},
	[ITEM_VXLAN] = {
		.name = "vxlan",
		.priv = PRIV_ITEM(VXLAN, sizeof(struct rte_flow_item_vxlan)),
		.next = NEXT(item_vxlan),
		.call = parse_vc,
	},
	[ITEM_E_TAG] = {
		.name = "e_tag",
		.priv = PRIV_ITEM(E_TAG, sizeof(struct rte_flow_item_e_tag)),
		.next = NEXT(item_e_tag),
		.call = parse_vc,
	},
	[ITEM_NVGRE] = {
		.name = "nvgre",
		.priv = PRIV_ITEM(NVGRE, sizeof(struct rte_flow_item_nvgre)),
		.next = NEXT(item_nvgre),
		.call = parse_vc,
	},
	[ITEM_MPLS] = {
		.name = "mpls",
		.priv = PRIV_ITEM(MPLS, sizeof(struct rte_flow_item_mpls)),
		.next = NEXT(item_mpls),
		.call = parse_vc,
	},
	[ITEM_GRE] = {
		.name = "gre",
		.priv = PRIV_ITEM(GRE, sizeof(struct rte_flow_item_gre)),
		.next = NEXT(item_gre),
		.call = parse_vc,
	},
	[ITEM_FUZZY] = {
		.name = "fuzzy",
		.priv = PRIV_ITEM(FUZZY,
				sizeof(struct rte_flow_item_fuzzy)),
		.next = NEXT(item_fuzzy),
		.call = parse_vc,
	},

	[ITEM_GTP] = {
		.name = "gtp",
		.priv = PRIV_ITEM(GTP, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtp),
		.call = parse_vc,
	},

	[ITEM_GTPC] = {
		.name = "gtpc",
		.priv = PRIV_ITEM(GTPC, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtpc),
		.call = parse_vc,
	},
	[ITEM_GTPU] = {
		.name = "gtpu",
		.priv = PRIV_ITEM(GTPU, sizeof(struct rte_flow_item_gtp)),
		.next = NEXT(item_gtpu),
		.call = parse_vc,
	},
	[ITEM_GENEVE] = {
		.name = "geneve",
		.priv = PRIV_ITEM(GENEVE, sizeof(struct rte_flow_item_geneve)),
		.next = NEXT(item_geneve),
		.call = parse_vc,
	},
	[ITEM_VXLAN_GPE] = {
		.name = "vxlan-gpe",
		.priv = PRIV_ITEM(VXLAN_GPE,
				  sizeof(struct rte_flow_item_vxlan_gpe)),
		.next = NEXT(item_vxlan_gpe),
		.call = parse_vc,
	},

	[ITEM_ICMP6] = {
		.name = "icmp6",
		.priv = PRIV_ITEM(ICMP6, sizeof(struct rte_flow_item_icmp6)),
		.next = NEXT(item_icmp6),
		.call = parse_vc,
	},

};

/** Remove and return last entry from argument stack. */
static const struct arg *pop_args(struct context *ctx)
{
    return ctx->args_num ? ctx->args[--ctx->args_num] : NULL;
}

/** Add entry on top of the argument stack. */
static int push_args(struct context *ctx, const struct arg *arg)
{
    if (ctx->args_num == CTX_STACK_SIZE)
        return -1;
    ctx->args[ctx->args_num++] = arg;
    return 0;
}

/** Spread value into buffer according to bit-mask. */
static size_t arg_entry_bf_fill(void *dst, uintmax_t val, const struct arg *arg)
{
    uint32_t i = arg->size;
    uint32_t end = 0;
    int sub = 1;
    int add = 0;
    size_t len = 0;

    if (!arg->mask)
        return 0;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
    if (!arg->hton) {
        i = 0;
        end = arg->size;
        sub = 0;
        add = 1;
    }
#endif
    while (i != end) {
        unsigned int shift = 0;
        uint8_t *buf = (uint8_t *)dst + arg->offset + (i -= sub);

        for (shift = 0; arg->mask[i] >> shift; ++shift) {
            if (!(arg->mask[i] & (1 << shift)))
                continue;
            ++len;
            if (!dst)
                continue;
            *buf &= ~(1 << shift);
            *buf |= (val & 1) << shift;
            val >>= 1;
        }
        i += add;
    }
    return len;
}

/** Compare a string with a partial one of a given length. */
static int strcmp_partial(const char *full, const char *partial, size_t partial_len)
{
    int r = strncmp(full, partial, partial_len);

    if (r)
        return r;
    if (strlen(full) <= partial_len)
        return 0;
    return full[partial_len];
}

/** Parse flow command, initialize output buffer for subsequent tokens. */
static int parse_init(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    struct buffer *out = buf;

    /* Token name must match. */
    if (parse_default(ctx, token, str, len, NULL, 0) < 0)
        return -1;
    /* Nothing else to do if there is no buffer. */
    if (!out)
        return len;
    /* Make sure buffer is large enough. */
    if (size < sizeof(*out))
        return -1;
    /* Initialize buffer. */
    memset(out, 0x00, sizeof(*out));
    memset((uint8_t *)out + sizeof(*out), 0x22, size - sizeof(*out));
    ctx->objdata = 0;
    ctx->object = out;
    ctx->objmask = NULL;
    parse_vc(ctx, token, str, len, buf, size);
    return len;
}

/**
 * Parse a MAC address.
 *
 * Last argument (ctx->args) is retrieved to determine storage size and
 * location.
 */
static int parse_mac_addr(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    const struct arg *arg = pop_args(ctx);
    struct rte_ether_addr tmp;
    int ret;

    (void)token;
    /* Argument is expected. */
    if (!arg)
        return -1;
    size = arg->size;
    /* Bit-mask fill is not supported. */
    if (arg->mask || size != sizeof(tmp))
        goto error;
    /* Only network endian is supported. */
    if (!arg->hton)
        goto error;
    ret = cmdline_parse_etheraddr(NULL, str, &tmp, size);
    if (ret < 0 || (unsigned int)ret != len)
        goto error;
    if (!ctx->object)
        return len;
    buf = (uint8_t *)ctx->object + arg->offset;
    memcpy(buf, &tmp, size);
    if (ctx->objmask)
        memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
    return len;
error:
    push_args(ctx, arg);
    return -1;
}

/**
 * Parse an IPv4 address.
 *
 * Last argument (ctx->args) is retrieved to determine storage size and
 * location.
 */
static int parse_ipv4_addr(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    const struct arg *arg = pop_args(ctx);
    char str2[len + 1];
    struct in_addr tmp;
    int ret;

    /* Argument is expected. */
    if (!arg)
        return -1;
    size = arg->size;
    /* Bit-mask fill is not supported. */
    if (arg->mask || size != sizeof(tmp))
        goto error;
    /* Only network endian is supported. */
    if (!arg->hton)
        goto error;
    memcpy(str2, str, len);
    str2[len] = '\0';
    ret = inet_pton(AF_INET, str2, &tmp);
    if (ret != 1) {
        /* Attempt integer parsing. */
        push_args(ctx, arg);
        return parse_int(ctx, token, str, len, buf, size);
    }
    if (!ctx->object)
        return len;
    buf = (uint8_t *)ctx->object + arg->offset;
    memcpy(buf, &tmp, size);
    if (ctx->objmask)
        memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
    return len;
error:
    push_args(ctx, arg);
    return -1;
}

/**
 * Parse an IPv6 address.
 *
 * Last argument (ctx->args) is retrieved to determine storage size and
 * location.
 */
static int parse_ipv6_addr(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    const struct arg *arg = pop_args(ctx);
    char str2[len + 1];
    struct rte_ipv6_addr tmp;
    int ret;

    (void)token;
    /* Argument is expected. */
    if (!arg)
        return -1;
    size = arg->size;
    /* Bit-mask fill is not supported. */
    if (arg->mask || size != sizeof(tmp))
        goto error;
    /* Only network endian is supported. */
    if (!arg->hton)
        goto error;
    memcpy(str2, str, len);
    str2[len] = '\0';
    ret = inet_pton(AF_INET6, str2, &tmp);
    if (ret != 1)
        goto error;
    if (!ctx->object)
        return len;
    buf = (uint8_t *)ctx->object + arg->offset;
    memcpy(buf, &tmp, size);
    if (ctx->objmask)
        memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
    return len;
error:
    push_args(ctx, arg);
    return -1;
}

/**
 * Parse signed/unsigned integers 8 to 64-bit long.
 *
 * Last argument (ctx->args) is retrieved to determine integer type and
 * storage location.
 */
static int parse_int(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    const struct arg *arg = pop_args(ctx);
    uintmax_t u;
    char *end;

    (void)token;
    /* Argument is expected. */
    if (!arg)
        return -1;
    errno = 0;
    u = arg->sign ? (uintmax_t)strtoimax(str, &end, 0) : strtoumax(str, &end, 0);
    if (errno || (size_t)(end - str) != len)
        goto error;
    if (arg->bounded && ((arg->sign && ((intmax_t)u < (intmax_t)arg->min ||
                                               (intmax_t)u > (intmax_t)arg->max)) ||
                                (!arg->sign && (u < arg->min || u > arg->max))))
        goto error;
    if (!ctx->object)
        return len;
    if (arg->mask) {
        if (!arg_entry_bf_fill(ctx->object, u, arg) || !arg_entry_bf_fill(ctx->objmask, -1, arg))
            goto error;
        return len;
    }
    buf = (uint8_t *)ctx->object + arg->offset;
    size = arg->size;
    if (u > RTE_LEN2MASK(size * CHAR_BIT, uint64_t))
        return -1;
objmask:
    switch (size) {
        case sizeof(uint8_t):
            *(uint8_t *)buf = u;
            break;
        case sizeof(uint16_t):
            *(uint16_t *)buf = arg->hton ? rte_cpu_to_be_16(u) : u;
            break;
        case sizeof(uint8_t[3]):
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
            if (!arg->hton) {
                ((uint8_t *)buf)[0] = u;
                ((uint8_t *)buf)[1] = u >> 8;
                ((uint8_t *)buf)[2] = u >> 16;
                break;
            }
#endif
            ((uint8_t *)buf)[0] = u >> 16;
            ((uint8_t *)buf)[1] = u >> 8;
            ((uint8_t *)buf)[2] = u;
            break;
        case sizeof(uint32_t):
            *(uint32_t *)buf = arg->hton ? rte_cpu_to_be_32(u) : u;
            break;
        case sizeof(uint64_t):
            *(uint64_t *)buf = arg->hton ? rte_cpu_to_be_64(u) : u;
            break;
        default:
            goto error;
    }
    if (ctx->objmask && buf != (uint8_t *)ctx->objmask + arg->offset) {
        u = -1;
        buf = (uint8_t *)ctx->objmask + arg->offset;
        goto objmask;
    }
    return len;
error:
    push_args(ctx, arg);
    return -1;
}

/** Default parsing function for token name matching. */
static int parse_default(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    (void)ctx;
    (void)buf;
    (void)size;
    if (strcmp_partial(token->name, str, len))
        return -1;
    return len;
}

/** Parse tokens for validate/create commands. */
static int parse_vc(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    struct buffer *out = buf;
    uint8_t *data;
    uint32_t data_size;

    /* Token name must match. */
    if (parse_default(ctx, token, str, len, NULL, 0) < 0)
        return -1;
    /* Nothing else to do if there is no buffer. */
    if (!out)
        return len;
    if (!out->command) {
        if (sizeof(*out) > size)
            return -1;
        out->command = CREATE;
        ctx->objdata = 0;
        ctx->object = out;
        ctx->objmask = NULL;
        out->args.vc.data = (uint8_t *)out + size;
    }
    ctx->objdata = 0;
    ctx->object = &out->args.vc.attr;
    ctx->objmask = NULL;
    switch (ctx->curr) {
        case ITEM_PATTERN:
            out->args.vc.pattern = (void *)RTE_ALIGN_CEIL((uintptr_t)(out + 1), sizeof(double));
            ctx->object = out->args.vc.pattern;
            ctx->objmask = NULL;
            return len;
        default:
            if (!token->priv)
                return -1;
            break;
    }
    const struct parse_item_priv *priv = token->priv;
    struct rte_flow_item *item = out->args.vc.pattern + out->args.vc.pattern_n;

    data_size = priv->size * 3; /* spec, last, mask */
    data = (void *)RTE_ALIGN_FLOOR((uintptr_t)(out->args.vc.data - data_size), sizeof(double));
    if ((uint8_t *)item + sizeof(*item) > data)
        return -1;
    *item = (struct rte_flow_item){
        .type = priv->type,
    };
    ++out->args.vc.pattern_n;
    ctx->object = item;
    ctx->objmask = NULL;

    memset(data, 0, data_size);
    out->args.vc.data = data;
    ctx->objdata = data_size;
    return len;
}

/** Parse pattern item parameter type. */
static int parse_vc_spec(struct context *ctx, const struct token *token, const char *str,
        unsigned int len, void *buf, unsigned int size)
{
    struct buffer *out = buf;
    struct rte_flow_item *item;
    uint32_t data_size;
    int index;
    int objmask = 0;

    (void)size;
    /* Token name must match. */
    if (parse_default(ctx, token, str, len, NULL, 0) < 0)
        return -1;
    /* Parse parameter types. */
    switch (ctx->curr) {

        case ITEM_PARAM_IS:
            index = 0;
            objmask = 1;
            break;
        case ITEM_PARAM_SPEC:
            index = 0;
            break;
        case ITEM_PARAM_LAST:
            index = 1;
            break;
        case ITEM_PARAM_MASK:
            index = 2;
            break;
        default:
            return -1;
    }
    /* Nothing else to do if there is no buffer. */
    if (!out)
        return len;
    if (!out->args.vc.pattern_n)
        return -1;
    item = &out->args.vc.pattern[out->args.vc.pattern_n - 1];
    data_size = ctx->objdata / 3; /* spec, last, mask */
    /* Point to selected object. */
    ctx->object = out->args.vc.data + (data_size * index);
    if (objmask) {
        ctx->objmask = out->args.vc.data + (data_size * 2); /* mask */
        item->mask = ctx->objmask;
    } else
        ctx->objmask = NULL;
    /* Update relevant item pointer. */
    *((const void **[]){ &item->spec, &item->last, &item->mask })[index] = ctx->object;
    return len;
}

/** Parse a token (cmdline API). */
static int cmd_flow_parse(const char *src, void *result, unsigned int size)
{
    struct context *ctx = &cmd_flow_context;
    const struct token *token;
    const enum index *list;
    int len;
    int i;

    token = &token_list[ctx->curr];
    /* Check argument length. */
    ctx->eol = 0;
    ctx->last = 1;
    for (len = 0; src[len]; ++len)
        if (src[len] == '#' || isspace(src[len]))
            break;
    if (!len)
        return -1;
    /* Last argument and EOL detection. */
    for (i = len; src[i]; ++i)
        if (src[i] == '#' || src[i] == '\r' || src[i] == '\n')
            break;
        else if (!isspace(src[i])) {
            ctx->last = 0;
            break;
        }
    for (; src[i]; ++i)
        if (src[i] == '\r' || src[i] == '\n') {
            ctx->eol = 1;
            break;
        }
    /* Initialize context if necessary. */
    if (!ctx->next_num) {
        if (!token->next)
            return 0;
        ctx->next[ctx->next_num++] = token->next[0];
    }
    /* Process argument through candidates. */
    ctx->prev = ctx->curr;
    list = ctx->next[ctx->next_num - 1];
    for (i = 0; list[i]; ++i) {
        const struct token *next = &token_list[list[i]];
        int tmp;

        ctx->curr = list[i];
        if (next->call)
            tmp = next->call(ctx, next, src, len, result, size);
        else
            tmp = parse_default(ctx, next, src, len, result, size);
        if (tmp == -1 || tmp != len)
            continue;
        token = next;
        break;
    }
    if (!list[i])
        return -1;
    --ctx->next_num;
    /* Push subsequent tokens if any. */
    if (token->next)
        for (i = 0; token->next[i]; ++i) {
            if (ctx->next_num == RTE_DIM(ctx->next))
                return -1;
            ctx->next[ctx->next_num++] = token->next[i];
        }
    /* Push arguments if any. */
    if (token->args)
        for (i = 0; token->args[i]; ++i) {
            if (ctx->args_num == RTE_DIM(ctx->args))
                return -1;
            ctx->args[ctx->args_num++] = token->args[i];
        }
    return len;
}

static int flow_parse(
        const char *src, void *result, unsigned int size, struct rte_flow_item **pattern)
{
    int ret;
    struct context saved_flow_ctx = cmd_flow_context;

    memset(result, 0x00, sizeof(*result));
    memset((uint8_t *)result + sizeof(*result), 0x22, size - sizeof(*result));

    cmd_flow_context_init(&cmd_flow_context);
    do {
        ret = cmd_flow_parse(src, result, size);
        if (ret > 0) {
            src += ret;
            while (isspace(*src))
                src++;
        }
    } while (ret > 0 && strlen(src));
    cmd_flow_context = saved_flow_ctx;
    *pattern = ((struct buffer *)result)->args.vc.pattern;

    return (ret >= 0 && !strlen(src)) ? 0 : -1;
}
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)*/

/**
 * \brief Parse rte_flow rule pattern and store individual pattern items in items and their
 *        attributes in buffer data
 *
 * \param pattern rte_flow rule pattern to be parsed
 * \param data buffer to store parsed pattern
 * \param size size of buffer
 * \param items parsed items used when creating rte_flow rules
 * \return int 0 on success, -1 on error
 */
int ParsePattern(
        char *pattern, uint8_t *items_data_buffer, unsigned int size, struct rte_flow_item **items)
{
    SCEnter();
#if RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)
    SCReturnInt(flow_parse(pattern, (void *)items_data_buffer, size, items));
#else
    SCReturnInt(0);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0)*/
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
