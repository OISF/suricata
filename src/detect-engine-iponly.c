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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Signatures that only inspect IP addresses are processed here
 * We use radix trees for src dst ipv4 and ipv6 addresses
 * This radix trees hold information for subnets and hosts in a
 * hierarchical distribution
 *
 * Building of the matching radix tree:
 * 1. parse each individual sig and record for each address/range whether it is negated or not
 *    (regular)
 * 2. fill hash tables to track each block. We split this per cidr. In each block we track the sids
 * and the negs (negated sids)
 * 3. build the radix from these hashes, where we start with /0, then /1, etc. This is to make sure
 *    sids/negs are properly propegated from the broader ranges to the more specific
 * ranges/addresses.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "decode.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"

#include "detect-engine-threshold.h"
#include "detect-engine-ip.h"
#include "detect-engine-iponly.h"
#include "detect-threshold.h"
#include "util-classification-config.h"
#include "util-rule-vars.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-print.h"
#include "util-byte.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-cidr.h"

#ifdef OS_WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif /* OS_WIN32 */

/** \brief user data for storing signature id's in the radix tree
 *
 *  Bit array representing signature internal id's (Signature::num).
 */
typedef struct SigNumArray_ {
    uint8_t *array; /* bit array of sig nums */
    uint32_t size;  /* size in bytes of the array */
} SigNumArray;

/**
 * \brief This function print a SigNumArray, it's used with the
 *        radix tree print function to help debugging
 * \param tmp Pointer to the head of SigNumArray
 */
static void SigNumArrayPrint(void *tmp)
{
    if (tmp == NULL)
        return;
    SigNumArray *sna = (SigNumArray *)tmp;
    printf("sids: ");
    for (uint32_t u = 0; u < sna->size; u++) {
        uint8_t bitarray = sna->array[u];
        for (uint8_t i = 0; i < 8; i++) {
            if (bitarray & 0x01)
                printf("%" PRIu32 " ", u * 8 + i);
            bitarray = bitarray >> 1;
        }
    }
    printf("[ user %p ]\n", tmp);
}
static void SigNumArrayDebug(void *tmp)
{
    if (tmp == NULL)
        return;
    if (SCLogDebugEnabled()) {
        SigNumArray *sna = (SigNumArray *)tmp;
        for (uint32_t u = 0; u < sna->size; u++) {
            uint8_t bitarray = sna->array[u];
            for (uint8_t i = 0; i < 8; i++) {
                if (bitarray & 0x01)
                    SCLogDebug("sid %" PRIu32 " ", u * 8 + i);
                bitarray = bitarray >> 1;
            }
        }
    }
}

/**
 * \brief This function creates a new SigNumArray with the
 *        size fixed to the io_ctx->max_idx
 * \param de_ctx Pointer to the current detection context
 * \param io_ctx Pointer to the current ip only context
 *
 * \retval SigNumArray address of the new instance
 */
static SigNumArray *SigNumArrayNew(DetectEngineIPOnlyCtx *io_ctx)
{
    SigNumArray *n = SCCalloc(1, sizeof(SigNumArray));
    if (unlikely(n == NULL)) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SigNumArrayNew. Exiting...");
    }

    n->array = SCCalloc(1, io_ctx->max_idx / 8 + 1);
    if (n->array == NULL) {
        FatalError(SC_ERR_FATAL, "Fatal error encountered in SigNumArrayNew. Exiting...");
    }
    n->size = io_ctx->max_idx / 8 + 1;
    SCLogDebug("max idx= %u", io_ctx->max_idx);
    return n;
}

/**
 * \brief This function creates a new SigNumArray with the
 *        same data as the argument
 *
 * \param orig Pointer to the original SigNumArray to copy
 *
 * \retval SigNumArray address of the new instance
 */
static SigNumArray *SigNumArrayCopy(SigNumArray *orig)
{
    SigNumArray *n = SCCalloc(1, sizeof(SigNumArray));
    if (unlikely(n == NULL)) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SigNumArrayCopy. Exiting...");
    }
    n->size = orig->size;

    n->array = SCMalloc(orig->size);
    if (n->array == NULL) {
        FatalError(SC_ERR_FATAL, "Fatal error encountered in SigNumArrayCopy. Exiting...");
    }
    memcpy(n->array, orig->array, orig->size);
    return n;
}

static void SigNumArrayAdd(SigNumArray *dst, SigNumArray *src)
{
    BUG_ON(dst->size != src->size);
    for (uint32_t i = 0; i < src->size; i++) {
        dst->array[i] |= src->array[i];
    }
}

static void SigNumArrayMask(SigNumArray *sna, const SigNumArray *mask)
{
    if (mask == NULL)
        return;
    BUG_ON(mask->size != sna->size);
    for (uint32_t x = 0; x < sna->size; x++) {
        uint8_t tmp = sna->array[x] & mask->array[x];
        sna->array[x] &= ~tmp;
    }
}

/**
 * \brief This function free() a SigNumArray
 * \param orig Pointer to the original SigNumArray to copy
 */
static void SigNumArrayFree(void *tmp)
{
    SigNumArray *sna = (SigNumArray *)tmp;

    if (sna == NULL)
        return;

    if (sna->array != NULL)
        SCFree(sna->array);

    SCFree(sna);
}

static const SCRadix4Config iponly_radix4_config = { SigNumArrayFree, SigNumArrayPrint };
static const SCRadix6Config iponly_radix6_config = { SigNumArrayFree, SigNumArrayPrint };

/**
 * \brief Setup the IP Only detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{
    io_ctx->tree_ipv4src = SCRadix4TreeInitialize();
    io_ctx->tree_ipv4dst = SCRadix4TreeInitialize();
    io_ctx->tree_ipv6src = SCRadix6TreeInitialize();
    io_ctx->tree_ipv6dst = SCRadix6TreeInitialize();
}

/**
 * \brief Setup the IP Only thread detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only thread detection engine
 */
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *de_ctx,
                                  DetectEngineIPOnlyThreadCtx *io_tctx)
{
    /* initialize the signature bitarray */
    io_tctx->sig_match_size = de_ctx->io_ctx.max_idx / 8 + 1;
    io_tctx->sig_match_array = SCMalloc(io_tctx->sig_match_size);
    if (io_tctx->sig_match_array == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(io_tctx->sig_match_array, 0, io_tctx->sig_match_size);
}

/**
 * \brief Print stats of the IP Only engine
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyPrint(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{
    /* XXX: how are we going to print the stats now? */
}

/**
 * \brief Deinitialize the IP Only detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyDeinit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{
    if (io_ctx == NULL)
        return;

    SCRadix4TreeRelease(&io_ctx->tree_ipv4src, &iponly_radix4_config);
    SCRadix4TreeRelease(&io_ctx->tree_ipv4dst, &iponly_radix4_config);
    SCRadix6TreeRelease(&io_ctx->tree_ipv6src, &iponly_radix6_config);
    SCRadix6TreeRelease(&io_ctx->tree_ipv6dst, &iponly_radix6_config);
}

/**
 * \brief Deinitialize the IP Only thread detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void DetectEngineIPOnlyThreadDeinit(DetectEngineIPOnlyThreadCtx *io_tctx)
{
    SCFree(io_tctx->sig_match_array);
}

static inline
int IPOnlyMatchCompatSMs(ThreadVars *tv,
                         DetectEngineThreadCtx *det_ctx,
                         Signature *s, Packet *p)
{
    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_MATCH);
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_MATCH];
    if (smd) {
        while (1) {
            DEBUG_VALIDATE_BUG_ON(!(sigmatch_table[smd->type].flags & SIGMATCH_IPONLY_COMPAT));
            KEYWORD_PROFILING_START;
            if (sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx) > 0) {
                KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                if (smd->is_last)
                    break;
                smd++;
                continue;
            }
            KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
            return 0;
        }
    }
    return 1;
}

/**
 * \brief Match a packet against the IP Only detection engine contexts
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 * \param io_ctx Pointer to the current ip only thread detection engine
 * \param p Pointer to the Packet to match against
 */
void IPOnlyMatchPacket(ThreadVars *tv,
                       const DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx,
                       const DetectEngineIPOnlyCtx *io_ctx,
                       DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p)
{
    SigNumArray *src = NULL;
    SigNumArray *dst = NULL;
    void *user_data_src = NULL, *user_data_dst = NULL;

    SCEnter();

    if (p->src.family == AF_INET) {
        (void)SCRadix4TreeFindBestMatch(
                &io_ctx->tree_ipv4src, (uint8_t *)&GET_IPV4_SRC_ADDR_U32(p), &user_data_src);
    } else if (p->src.family == AF_INET6) {
        (void)SCRadix6TreeFindBestMatch(
                &io_ctx->tree_ipv6src, (uint8_t *)&GET_IPV6_SRC_ADDR(p), &user_data_src);
    }

    if (p->dst.family == AF_INET) {
        (void)SCRadix4TreeFindBestMatch(
                &io_ctx->tree_ipv4dst, (uint8_t *)&GET_IPV4_DST_ADDR_U32(p), &user_data_dst);
    } else if (p->dst.family == AF_INET6) {
        (void)SCRadix6TreeFindBestMatch(
                &io_ctx->tree_ipv6dst, (uint8_t *)&GET_IPV6_DST_ADDR(p), &user_data_dst);
    }

    src = user_data_src;
    dst = user_data_dst;

    if (src == NULL || dst == NULL)
        SCReturn;

    uint32_t u;
    for (u = 0; u < src->size; u++) {
        SCLogDebug("And %"PRIu8" & %"PRIu8, src->array[u], dst->array[u]);

        /* The final results will be at io_tctx */
        io_tctx->sig_match_array[u] = dst->array[u] & src->array[u];

        /* We have to move the logic of the signature checking
         * to the main detect loop, in order to apply the
         * priority of actions (pass, drop, reject, alert) */
        if (io_tctx->sig_match_array[u] != 0) {
            /* We have a match :) Let's see from which signum's */
            uint8_t bitarray = io_tctx->sig_match_array[u];
            uint8_t i = 0;

            for (; i < 8; i++, bitarray = bitarray >> 1) {
                if (bitarray & 0x01) {
                    Signature *s = de_ctx->sig_array[u * 8 + i];

                    if ((s->proto.flags & DETECT_PROTO_IPV4) && !PKT_IS_IPV4(p)) {
                        SCLogDebug("ip version didn't match");
                        continue;
                    }
                    if ((s->proto.flags & DETECT_PROTO_IPV6) && !PKT_IS_IPV6(p)) {
                        SCLogDebug("ip version didn't match");
                        continue;
                    }

                    if (DetectProtoContainsProto(&s->proto, IP_GET_IPPROTO(p)) == 0) {
                        SCLogDebug("proto didn't match");
                        continue;
                    }

                    /* check the source & dst port in the sig */
                    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
                        if (!(s->flags & SIG_FLAG_DP_ANY)) {
                            if (p->flags & PKT_IS_FRAGMENT)
                                continue;

                            DetectPort *dport = DetectPortLookupGroup(s->dp, p->dp);
                            if (dport == NULL) {
                                SCLogDebug("dport didn't match.");
                                continue;
                            }
                        }
                        if (!(s->flags & SIG_FLAG_SP_ANY)) {
                            if (p->flags & PKT_IS_FRAGMENT)
                                continue;

                            DetectPort *sport = DetectPortLookupGroup(s->sp, p->sp);
                            if (sport == NULL) {
                                SCLogDebug("sport didn't match.");
                                continue;
                            }
                        }
                    } else if ((s->flags & (SIG_FLAG_DP_ANY | SIG_FLAG_SP_ANY)) !=
                               (SIG_FLAG_DP_ANY | SIG_FLAG_SP_ANY)) {
                        SCLogDebug("port-less protocol and sig needs ports");
                        continue;
                    }

                    if (!IPOnlyMatchCompatSMs(tv, det_ctx, s, p)) {
                        continue;
                    }

                    SCLogDebug("Signum %" PRIu32 " match (sid: %" PRIu32 ", msg: %s)", u * 8 + i,
                            s->id, s->msg);

                    if (s->sm_arrays[DETECT_SM_LIST_POSTMATCH] != NULL) {
                        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);
                        SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];

                        SCLogDebug("running match functions, sm %p", smd);

                        if (smd != NULL) {
                            while (1) {
                                KEYWORD_PROFILING_START;
                                (void)sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx);
                                KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                                if (smd->is_last)
                                    break;
                                smd++;
                            }
                        }
                    }
                    AlertQueueAppend(det_ctx, s, p, 0, 0);
                }
            }
        }
    }
    SCReturn;
}

struct AddressCidrStore {
    union {
        uint8_t a_u8[4];
        uint32_t a_u32;
    } addr;
    uint8_t cidr;
    SigNumArray *sids;
    SigNumArray *negs;
};

// TODO move into a setup struct (needed for multi loader)
static HashListTable *src_cidr_tables_v4[33] = { NULL }; // for cidrs 0-32
static HashListTable *dst_cidr_tables_v4[33] = { NULL }; // for cidrs 0-32

static uint32_t AddressCidrHash(HashListTable *table, void *data, uint16_t len)
{
    struct AddressCidrStore *acs = data;
    uint32_t hash = acs->addr.a_u32 + acs->cidr;
    return hash % table->array_size;
}

static char AddressCidrCompare(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    struct AddressCidrStore *acs1 = data1;
    struct AddressCidrStore *acs2 = data2;
    return (acs1->addr.a_u32 == acs2->addr.a_u32 && acs1->cidr == acs2->cidr);
}

static void AddrCidrFree(void *ptr)
{
    struct AddressCidrStore *acs = ptr;
    SigNumArrayFree(acs->sids);
    SigNumArrayFree(acs->negs);
    SCFree(ptr);
}

struct IPOnlyPrepareData {
    SCRadix4Tree *tree_ipv4;
    SCRadix6Tree *tree_ipv6;
    DetectEngineIPOnlyCtx *io_ctx;
    uint32_t sid;
    SigIntId num;
    bool dst; // false if src range
};

static int IPOnlyPrepareCallbackBuildHashes(
        const SCRadix4Node *node, void *user_data, const uint8_t netmask, void *data)
{
    const struct IPOnlyPrepareData *pd = data;
    SCLogDebug("sid %u: node %p user_data %p %s/%u data %p (%s)", pd->sid, node, user_data,
            inet_ntoa(*(struct in_addr *)node->prefix_stream), netmask, data,
            (const char *)user_data);

    BUG_ON(netmask > 32);

    HashListTable *ht = NULL;

    if (pd->dst) {
        if (dst_cidr_tables_v4[netmask] == NULL) {
            dst_cidr_tables_v4[netmask] =
                    HashListTableInit(4096, AddressCidrHash, AddressCidrCompare, AddrCidrFree);
            BUG_ON(dst_cidr_tables_v4[netmask] == NULL);
        }
        ht = dst_cidr_tables_v4[netmask];
    } else {
        if (src_cidr_tables_v4[netmask] == NULL) {
            src_cidr_tables_v4[netmask] =
                    HashListTableInit(4096, AddressCidrHash, AddressCidrCompare, AddrCidrFree);
            BUG_ON(src_cidr_tables_v4[netmask] == NULL);
        }
        ht = src_cidr_tables_v4[netmask];
    }

    struct AddressCidrStore lookup;
    memset(&lookup, 0, sizeof(lookup));
    memcpy(lookup.addr.a_u8, node->prefix_stream, 4);
    lookup.cidr = netmask;

    struct AddressCidrStore *found = HashListTableLookup(ht, &lookup, 0);
    if (found) {
        SCLogDebug("found %s/%u already in the hash, lets update it",
                inet_ntoa(*(struct in_addr *)found->addr.a_u8), found->cidr);
        SigNumArray *sids = found->sids;
        SigNumArray *negs = found->negs;
        uint8_t tmp = 1 << (pd->num % 8);

        const struct AddrState *as = user_data;
        if (as->state == 0) {
            if (negs == NULL) {
                negs = SigNumArrayNew(pd->io_ctx);
                found->negs = negs;
            }
            negs->array[pd->num / 8] |= tmp;
        }
        sids->array[pd->num / 8] |= tmp;
    } else {
        struct AddressCidrStore *add = SCCalloc(1, sizeof(*add));
        if (add == NULL)
            return -1;

        SigNumArray *sids = SigNumArrayNew(pd->io_ctx);
        SigNumArray *negs = NULL;
        /* Update the sig */
        uint8_t tmp = 1 << (pd->num % 8);
        const struct AddrState *as = user_data;
        if (as->state == 0) {
            negs = SigNumArrayNew(pd->io_ctx);
            negs->array[pd->num / 8] |= tmp;
        }
        sids->array[pd->num / 8] |= tmp;
        *add = lookup;
        add->sids = sids;
        add->negs = negs;

        if (HashListTableAdd(ht, add, 0) < 0) {
            abort();
            // TODO free add
            return -1;
        }
        SCLogDebug(
                "added %s/%u to the hash", inet_ntoa(*(struct in_addr *)add->addr.a_u8), add->cidr);
    }
    return 0;
}

struct AddressCidrStoreV6 {
    union {
        uint8_t a_u8[16];
        uint32_t a_u32[4];
    } addr;
    uint8_t cidr;
    SigNumArray *sids;
    SigNumArray *negs;
};

// TODO move into a setup struct (needed for multi loader)
static HashListTable *src_cidr_tables_v6[129] = { NULL }; // for cidrs 0-128
static HashListTable *dst_cidr_tables_v6[129] = { NULL }; // for cidrs 0-128

static uint32_t AddressCidrHashV6(HashListTable *table, void *data, uint16_t len)
{
    struct AddressCidrStoreV6 *acs = data;
    uint32_t hash = acs->cidr;
    for (int i = 0; i < 4; i++) {
        hash += acs->addr.a_u32[i];
    }
    return hash % table->array_size;
}

static char AddressCidrCompareV6(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    struct AddressCidrStoreV6 *acs1 = data1;
    struct AddressCidrStoreV6 *acs2 = data2;
    return (memcmp(acs1->addr.a_u8, acs2->addr.a_u8, 16) == 0 && acs1->cidr == acs2->cidr);
}

static void AddrCidrFreeV6(void *ptr)
{
    struct AddressCidrStoreV6 *acs = ptr;
    SigNumArrayFree(acs->sids);
    SigNumArrayFree(acs->negs);
    SCFree(ptr);
}

static int IPOnlyPrepareCallbackBuildHashesV6(
        const SCRadix6Node *node, void *user_data, const uint8_t netmask, void *data)
{
    const struct IPOnlyPrepareData *pd = data;
    SCLogDebug("sid %u: node %p user_data %p %s/%u data %p (%s)", pd->sid, node, user_data,
            inet_ntoa(*(struct in_addr *)node->prefix_stream), netmask, data,
            (const char *)user_data);

    BUG_ON(netmask > 128);

    HashListTable *ht = NULL;

    if (pd->dst) {
        if (dst_cidr_tables_v6[netmask] == NULL) {
            dst_cidr_tables_v6[netmask] = HashListTableInit(
                    4096, AddressCidrHashV6, AddressCidrCompareV6, AddrCidrFreeV6);
            BUG_ON(dst_cidr_tables_v6[netmask] == NULL);
        }
        ht = dst_cidr_tables_v6[netmask];
    } else {
        if (src_cidr_tables_v6[netmask] == NULL) {
            src_cidr_tables_v6[netmask] = HashListTableInit(
                    4096, AddressCidrHashV6, AddressCidrCompareV6, AddrCidrFreeV6);
            BUG_ON(src_cidr_tables_v6[netmask] == NULL);
        }
        ht = src_cidr_tables_v6[netmask];
    }

    struct AddressCidrStoreV6 lookup;
    memset(&lookup, 0, sizeof(lookup));
    memcpy(lookup.addr.a_u8, node->prefix_stream, 16);
    lookup.cidr = netmask;

    struct AddressCidrStoreV6 *found = HashListTableLookup(ht, &lookup, 0);
    if (found) {
        SCLogDebug("found %s/%u already in the hash, lets update it",
                inet_ntoa(*(struct in_addr *)found->addr.a_u8), found->cidr);
        SigNumArray *sids = found->sids;
        SigNumArray *negs = found->negs;
        uint8_t tmp = 1 << (pd->num % 8);
        const struct AddrState *as = user_data;
        if (as->state == 0) {
            if (negs == NULL) {
                negs = SigNumArrayNew(pd->io_ctx);
                found->negs = negs;
            }
            negs->array[pd->num / 8] |= tmp;
        }
        sids->array[pd->num / 8] |= tmp;
    } else {
        struct AddressCidrStoreV6 *add = SCCalloc(1, sizeof(*add));
        if (add == NULL)
            return -1;

        SigNumArray *sids = SigNumArrayNew(pd->io_ctx);
        SigNumArray *negs = NULL;
        /* Update the sig */
        uint8_t tmp = 1 << (pd->num % 8);
        const struct AddrState *as = user_data;
        if (as->state == 0) {
            negs = SigNumArrayNew(pd->io_ctx);
            negs->array[pd->num / 8] |= tmp;
        }
        sids->array[pd->num / 8] |= tmp;
        *add = lookup;
        add->sids = sids;
        add->negs = negs;

        if (HashListTableAdd(ht, add, 0) < 0) {
            abort();
            // TODO free add
            return -1;
        }
        SCLogDebug(
                "added %s/%u to the hash", inet_ntoa(*(struct in_addr *)add->addr.a_u8), add->cidr);
    }
    return 0;
}

static int AddOneV4(SCRadix4Tree *ipv4_tree, const struct AddressCidrStore *acs, const uint8_t cidr)
{
    BUG_ON(acs == NULL);
    SCLogDebug("%d: %s/%u", cidr, inet_ntoa(*(struct in_addr *)acs->addr.a_u8), acs->cidr);
    SigNumArrayDebug(acs->sids);

    SCRadix4Node *node = NULL;
    void *user_data = NULL;
    if (acs->cidr == 32)
        (void)SCRadix4TreeFindExactMatch(ipv4_tree, (uint8_t *)&acs->addr, &user_data);
    else
        (void)SCRadix4TreeFindNetblock(ipv4_tree, (uint8_t *)&acs->addr, acs->cidr, &user_data);
    if (user_data == NULL) {
        SCLogDebug("Exact match not found");

        /* Not found, look if there's a subnet of this range with
         * bigger netmask */
        (void)SCRadix4TreeFindBestMatch(ipv4_tree, (uint8_t *)&acs->addr, &user_data);
        if (user_data == NULL) {
            SCLogDebug("best match not found");

            SigNumArray *sids = SigNumArrayCopy(acs->sids);
            SigNumArrayMask(sids, acs->negs);
            SigNumArrayDebug(sids);
            if (acs->cidr == 32)
                node = SCRadix4AddKeyIPV4(
                        ipv4_tree, &iponly_radix4_config, (uint8_t *)&acs->addr, sids);
            else
                node = SCRadix4AddKeyIPV4Netblock(
                        ipv4_tree, &iponly_radix4_config, (uint8_t *)&acs->addr, acs->cidr, sids);
            BUG_ON(node == NULL);
        } else {
            SCLogDebug("Best match found");

            SigNumArray *sids = SigNumArrayCopy(user_data);
            SigNumArrayAdd(sids, acs->sids);
            SigNumArrayMask(sids, acs->negs);
            SigNumArrayDebug(sids);

            if (acs->cidr == 32)
                node = SCRadix4AddKeyIPV4(
                        ipv4_tree, &iponly_radix4_config, (uint8_t *)&acs->addr, sids);
            else
                node = SCRadix4AddKeyIPV4Netblock(
                        ipv4_tree, &iponly_radix4_config, (uint8_t *)&acs->addr, acs->cidr, sids);
            BUG_ON(node == NULL);
        }
    } else {
        SCLogDebug("Exact match found");

        /* it's already inserted. Update it */
        SigNumArray *sids = (SigNumArray *)user_data;
        SigNumArrayAdd(sids, acs->sids);
        SigNumArrayMask(sids, acs->negs);
        SigNumArrayDebug(sids);
    }
    return 0;
}

static int AddOneV6(
        SCRadix6Tree *ipv6_tree, const struct AddressCidrStoreV6 *acs, const uint8_t cidr)
{
    BUG_ON(acs == NULL);
    SCLogDebug("%d: %s/%u", cidr, inet_ntoa(*(struct in_addr *)acs->addr.a_u8), acs->cidr);
    SigNumArrayDebug(acs->sids);

    SCRadix6Node *node = NULL;
    void *user_data = NULL;
    if (acs->cidr == 128)
        (void)SCRadix6TreeFindExactMatch(ipv6_tree, (uint8_t *)&acs->addr, &user_data);
    else
        (void)SCRadix6TreeFindNetblock(ipv6_tree, (uint8_t *)&acs->addr, acs->cidr, &user_data);
    if (user_data == NULL) {
        SCLogDebug("Exact match not found");

        /* Not found, look if there's a subnet of this range with
         * bigger netmask */
        (void)SCRadix6TreeFindBestMatch(ipv6_tree, (uint8_t *)&acs->addr, &user_data);
        if (user_data == NULL) {
            SCLogDebug("best match not found");

            SigNumArray *sids = SigNumArrayCopy(acs->sids);
            SigNumArrayMask(sids, acs->negs);
            SigNumArrayDebug(sids);
            if (acs->cidr == 128)
                node = SCRadix6AddKeyIPV6(
                        ipv6_tree, &iponly_radix6_config, (uint8_t *)&acs->addr, sids);
            else
                node = SCRadix6AddKeyIPV6Netblock(
                        ipv6_tree, &iponly_radix6_config, (uint8_t *)&acs->addr, acs->cidr, sids);
            BUG_ON(node == NULL);
        } else {
            SCLogDebug("Best match found");

            SigNumArray *sids = SigNumArrayCopy(user_data);
            SigNumArrayAdd(sids, acs->sids);
            SigNumArrayMask(sids, acs->negs);
            SigNumArrayDebug(sids);

            if (acs->cidr == 128)
                node = SCRadix6AddKeyIPV6(
                        ipv6_tree, &iponly_radix6_config, (uint8_t *)&acs->addr, sids);
            else
                node = SCRadix6AddKeyIPV6Netblock(
                        ipv6_tree, &iponly_radix6_config, (uint8_t *)&acs->addr, acs->cidr, sids);
            BUG_ON(node == NULL);
        }
    } else {
        SCLogDebug("Exact match found");

        /* it's already inserted. Update it */
        SigNumArray *sids = (SigNumArray *)user_data;
        SigNumArrayAdd(sids, acs->sids);
        SigNumArrayMask(sids, acs->negs);
        SigNumArrayDebug(sids);
    }
    return 0;
}

/**
 * \brief Build the radix trees from the lists of parsed addresses in CIDR format
 *        the result should be 4 radix trees: src/dst ipv4 and src/dst ipv6
 *        holding SigNumArrays, each of them with a hierarchical relation
 *        of subnets and hosts
 *
 * \param de_ctx Pointer to the current detection engine
 */
void IPOnlyPrepare(DetectEngineCtx *de_ctx)
{
    SCLogDebug("Preparing Final Lists");

    for (int i = 0; i <= 32; i++) {
        if (src_cidr_tables_v4[i] == NULL)
            continue;

        HashListTableBucket *htb = NULL;
        for (htb = HashListTableGetListHead(src_cidr_tables_v4[i]); htb != NULL;
                htb = HashListTableGetListNext(htb)) {
            struct AddressCidrStore *acs = HashListTableGetListData(htb);
            AddOneV4(&de_ctx->io_ctx.tree_ipv4src, acs, i);
        }
        HashListTableFree(src_cidr_tables_v4[i]);
        src_cidr_tables_v4[i] = NULL;
    }
    for (int i = 0; i <= 32; i++) {
        if (dst_cidr_tables_v4[i] == NULL)
            continue;

        HashListTableBucket *htb = NULL;
        for (htb = HashListTableGetListHead(dst_cidr_tables_v4[i]); htb != NULL;
                htb = HashListTableGetListNext(htb)) {
            struct AddressCidrStore *acs = HashListTableGetListData(htb);
            AddOneV4(&de_ctx->io_ctx.tree_ipv4dst, acs, i);
        }
        HashListTableFree(dst_cidr_tables_v4[i]);
        dst_cidr_tables_v4[i] = NULL;
    }
    for (int i = 0; i <= 128; i++) {
        if (src_cidr_tables_v6[i] == NULL)
            continue;

        HashListTableBucket *htb = NULL;
        for (htb = HashListTableGetListHead(src_cidr_tables_v6[i]); htb != NULL;
                htb = HashListTableGetListNext(htb)) {
            struct AddressCidrStoreV6 *acs = HashListTableGetListData(htb);
            AddOneV6(&de_ctx->io_ctx.tree_ipv6src, acs, i);
        }
        HashListTableFree(src_cidr_tables_v6[i]);
        src_cidr_tables_v6[i] = NULL;
    }
    for (int i = 0; i <= 128; i++) {
        if (dst_cidr_tables_v6[i] == NULL)
            continue;

        HashListTableBucket *htb = NULL;
        for (htb = HashListTableGetListHead(dst_cidr_tables_v6[i]); htb != NULL;
                htb = HashListTableGetListNext(htb)) {
            struct AddressCidrStoreV6 *acs = HashListTableGetListData(htb);
            AddOneV6(&de_ctx->io_ctx.tree_ipv6dst, acs, i);
        }
        HashListTableFree(dst_cidr_tables_v6[i]);
        dst_cidr_tables_v6[i] = NULL;
    }
}

/**
 * \brief Add a signature to the lists of Addresses in CIDR format (sorted)
 *        this step is necessary to build the radix tree with a hierarchical
 *        relation between nodes
 * \param de_ctx Pointer to the current detection engine context
 * \param de_ctx Pointer to the current ip only detection engine contest
 * \param s Pointer to the current signature
 */
void IPOnlyAddSignature(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx,
                        Signature *s)
{
    if (!(s->flags & SIG_FLAG_IPONLY))
        return;

    struct IPOnlyPrepareData src_data = { .tree_ipv4 = &io_ctx->tree_ipv4src,
        .tree_ipv6 = &io_ctx->tree_ipv6src,
        .io_ctx = io_ctx,
        .sid = s->id,
        .num = s->num,
        .dst = false };

    int r = SCRadix4ForEachNode(&s->ip_src.ipv4, IPOnlyPrepareCallbackBuildHashes, &src_data);
    SCLogDebug("r %d", r);
    if (r != 0)
        return; // TODO error
    r = SCRadix6ForEachNode(&s->ip_src.ipv6, IPOnlyPrepareCallbackBuildHashesV6, &src_data);
    SCLogDebug("r %d", r);
    if (r != 0)
        return; // TODO error

    struct IPOnlyPrepareData dst_data = { .tree_ipv4 = &io_ctx->tree_ipv4dst,
        .tree_ipv6 = &io_ctx->tree_ipv6dst,
        .io_ctx = io_ctx,
        .sid = s->id,
        .num = s->num,
        .dst = true };

    r = SCRadix4ForEachNode(&s->ip_dst.ipv4, IPOnlyPrepareCallbackBuildHashes, &dst_data);
    SCLogDebug("r %d", r);
    if (r != 0)
        return; // TODO error
    r = SCRadix6ForEachNode(&s->ip_dst.ipv6, IPOnlyPrepareCallbackBuildHashesV6, &dst_data);
    SCLogDebug("r %d", r);
    if (r != 0)
        return; // TODO error
}

#ifdef UNITTESTS
/**
 * \test check that we set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch and no port is fixed
 */

static int IPOnlyTestSig01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,"alert tcp any any -> any any (sid:400001; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check that we don't set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch but a port is fixed
 */

static int IPOnlyTestSig02 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,"alert tcp any any -> any 80 (sid:400001; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check that we set don't set a Signature as IPOnly
 *  because it has rule options appending a SigMatch like content, and pcre
 */

static int IPOnlyTestSig03 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* combination of pcre and content */
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (content:\"php\"; pcre:\"/require(_once)?/i\"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* content */
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"match something\"; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* uricontent */
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (uricontent:\"match something\"; sid:3;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* pcre */
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (pcre:\"/e?idps rule[sz]/i\"; sid:4;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* flow */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:to_server; sid:5;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* dsize */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (dsize:100; sid:6;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* flowbits */
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (flowbits:unset,somebit; sid:7;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* flowvar */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (pcre:\"/(?<flow_var>.*)/i\"; "
                                      "flowvar:var,\"str\"; sid:8;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    /* pktvar */
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (pcre:\"/(?<pkt_var>.*)/i\"; "
                                      "pktvar:var,\"str\"; sid:9;)");
    FAIL_IF_NULL(s);
    FAIL_IF(SignatureIsIPOnly(de_ctx, s));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig05(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig06(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "80.58.0.33", "195.235.113.3");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig07(void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    uint8_t numpkts = 1;
    uint8_t numsigs = 7;
    Packet *p[1];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    const char *sigs[numsigs];
    sigs[0] = "alert tcp 192.168.1.5 any -> 192.168.0.0/16 any (sid:1;)";
    sigs[1] = "alert tcp [192.168.1.2,192.168.1.5,192.168.1.4] any -> 192.168.1.1 any (sid:2;)";
    sigs[2] = "alert tcp [192.168.1.0/24,!192.168.1.1] any -> 192.168.1.1 any (sid:3;)";
    sigs[3] = "alert tcp [192.0.0.0/8,!192.168.0.0/16,192.168.1.0/24,!192.168.1.1] any -> "
              "[192.168.1.0/24,!192.168.1.5] any (sid:4;)";
    sigs[4] = "alert tcp any any -> any any (sid:5;)";
    sigs[5] = "alert tcp any any -> [192.168.0.0/16,!192.168.1.0/24,192.168.1.1] any (sid:6;)";
    sigs[6] =
            "alert tcp "
            "[78.129.202.0/"
            "24,192.168.1.5,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,"
            "78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141."
            "114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16."
            "7,78.143.46.124,78.157.129.71] any -> 192.168.1.1 any (sid:7;)"; /* real sid:"2407490"
                                                                               */
    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 0, 1, 0, 1 };
    int result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *)results, numsigs);
    FAIL_IF_NOT(result == 1);
    UTHFreePackets(p, numpkts);
    PASS;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig08(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"192.168.1.1","192.168.1.5");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp [192.168.1.2,192.168.1.5,192.168.1.4] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [192.168.1.0/24,!192.168.1.1] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [192.0.0.0/8,!192.168.0.0/16,192.168.1.0/24,!192.168.1.1] any -> [192.168.1.0/24,!192.168.1.5] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> !192.168.1.5 any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> [192.168.0.0/16,!192.168.1.0/24,192.168.1.1] any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,192.168.1.5,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> 192.168.1.1 any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig09(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:0/96 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig10(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> !3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562/96 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp !3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> !3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> 3FFE:FFFF:7654:FEDB:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match) with ipv4 and ipv6 mixed
 */
static int IPOnlyTestSig11(void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    uint8_t numpkts = 2;
    uint8_t numsigs = 7;
    Packet *p[2];
    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"192.168.1.1","192.168.1.5");
    const char *sigs[numsigs];
    sigs[0] = "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1 any -> "
              "3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.5 any (sid:1;)";
    sigs[1] = "alert tcp "
              "[3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,0.0.0.0/0,!192.168.1.0/"
              "24,192.168.1.1,192.168.1.4,192.168.1.5] any -> "
              "[3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.0/24] any (sid:2;)";
    sigs[2] =
            "alert tcp "
            "[3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] "
            "any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (sid:3;)";
    sigs[3] =
            "alert tcp "
            "[3FFE:FFFF:0:0:0:0:0:0/32,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:0:0:0:0/"
            "64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> "
            "[3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.0/"
            "24,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565] any (sid:4;)";
    sigs[4] = "alert tcp any any -> any any (sid:5;)";
    sigs[5] = "alert tcp any any -> "
              "[3FFE:FFFF:7654:FEDA:0:0:0:0/"
              "64,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.0.0.0/8] any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */
    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[2][7] = { { 1, 1, 1, 0, 1, 1, 1 }, { 1, 0, 1, 1, 1, 1, 1 } };
    int result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *)results, numsigs);
    FAIL_IF_NOT(result == 1);
    UTHFreePackets(p, numpkts);
    PASS;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match) with ipv4 and ipv6 mixed
 */
static int IPOnlyTestSig12(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 2;
    uint8_t numsigs = 7;

    Packet *p[2];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"3FBE:FFFF:7654:FEDA:1245:BA98:3210:4562","3FBE:FFFF:7654:FEDA:1245:BA98:3210:4565");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"195.85.1.1","80.198.1.5");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1 any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.5 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1] = "alert tcp "
              "[3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,0.0.0.0/0,!192.168.1.0/"
              "24,192.168.1.1,192.168.1.4,192.168.1.5] any -> "
              "[3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.0/24] any (msg:\"Testing src/dst "
              "ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [3FFE:FFFF:0:0:0:0:0:0/32,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.0/24,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> [!3FBE:FFFF:7654:FEDA:1245:BA98:3210:4565,!80.198.1.5] any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5] =
            "alert tcp any any -> "
            "[3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] "
            "any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.0.0.0/8] any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[2][7] = {{ 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0}};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

static int IPOnlyTestSig13(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
                           "alert tcp any any -> any any (msg:\"Test flowbits ip only\"; "
                           "flowbits:set,myflow1; sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int IPOnlyTestSig14(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
                           "alert tcp any any -> any any (msg:\"Test flowbits ip only\"; "
                           "flowbits:set,myflow1; flowbits:isset,myflow2; sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 1);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int IPOnlyTestSig15(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];
    Flow f;
    GenericVar flowvar;
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));
    FLOW_INITIALIZE(&f);

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    p[0]->flow = &f;
    p[0]->flow->flowvar = &flowvar;
    p[0]->flags |= PKT_HAS_FLOW;
    p[0]->flowflags |= FLOW_PKT_TOSERVER;

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; "
        "flowbits:set,one; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; "
        "flowbits:set,two; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; "
        "flowbits:set,three; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; "
        "flowbits:set,four; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; "
        "flowbits:set,five; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; "
        "flowbits:set,six; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; "
        "flowbits:set,seven; content:\"Hi all\"; sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    FLOW_DESTROY(&f);
    return result;
}

/**
 * \brief Unittest to show #599.  We fail to match if we have negated addresses.
 */
static int IPOnlyTestSig16(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 2;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "100.100.0.0", "50.0.0.0");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp !100.100.0.1 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> !50.0.0.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[2] = { 1, 2};
    uint32_t results[2] = { 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \brief Unittest to show #611. Ports on portless protocols.
 */
static int IPOnlyTestSig17(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 2;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_ICMP, "100.100.0.0", "50.0.0.0");

    const char *sigs[numsigs];
    sigs[0]= "alert ip 100.100.0.0 80 -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert ip any any -> 50.0.0.0 123 (msg:\"Testing dst ip (sid 2)\"; sid:2;)";

    uint32_t sid[2] = { 1, 2};
    uint32_t results[2] = { 0, 0}; /* neither should match */

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \brief Unittest to show #3568 -- IP address range handling
 */
static int IPOnlyTestSig18(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 4;
    uint8_t numsigs = 4;

    Packet *p[4];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "10.10.10.1", "50.0.0.1");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "220.10.10.1", "5.0.0.1");
    p[2] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "0.0.0.1", "50.0.0.1");
    p[3] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "255.255.255.254", "5.0.0.1");

    const char *sigs[numsigs];
    // really many IP addresses
    sigs[0]= "alert ip 1.2.3.4-219.6.7.8 any -> any any (sid:1;)";
    sigs[1]= "alert ip 51.2.3.4-253.1.2.3 any -> any any (sid:2;)";
    sigs[2]= "alert ip 0.0.0.0-50.0.0.2 any -> any any (sid:3;)";
    sigs[3]= "alert ip 50.0.0.0-255.255.255.255 any -> any any (sid:4;)";

    uint32_t sid[4] = { 1, 2, 3, 4, };
    uint32_t results[4][4] = {
        { 1, 0, 1, 0, }, { 0, 1, 0, 1}, { 0, 0, 1, 0 }, { 0, 0, 0, 1}};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    FAIL_IF(result != 1);

    PASS;
}

/** \test build IP-only tree */
static int IPOnlyTestSig19(void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    uint8_t numpkts = 1;
    uint8_t numsigs = 1;
    Packet *p[1];
    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_ICMP, "192.168.2.5", "50.0.0.0");
    const char *sigs[numsigs];
    sigs[0] = "alert ip [!192.168.0.0/16,192.168.0.0/16,192.168.2.5] any -> any any (sid:1;)";
    uint32_t sid[1] = { 1 };
    uint32_t results[1] = { 0 };
    int result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *)results, numsigs);
    FAIL_IF_NOT(result == 1);
    UTHFreePackets(p, numpkts);
    PASS;
}

#endif /* UNITTESTS */

void IPOnlyRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPOnlyTestSig01", IPOnlyTestSig01);
    UtRegisterTest("IPOnlyTestSig02", IPOnlyTestSig02);
    UtRegisterTest("IPOnlyTestSig03", IPOnlyTestSig03);
    UtRegisterTest("IPOnlyTestSig05", IPOnlyTestSig05);
    UtRegisterTest("IPOnlyTestSig06", IPOnlyTestSig06);
    UtRegisterTest("IPOnlyTestSig07", IPOnlyTestSig07);
    UtRegisterTest("IPOnlyTestSig08", IPOnlyTestSig08);
    UtRegisterTest("IPOnlyTestSig09", IPOnlyTestSig09);
    UtRegisterTest("IPOnlyTestSig10", IPOnlyTestSig10);
    UtRegisterTest("IPOnlyTestSig11", IPOnlyTestSig11);
    UtRegisterTest("IPOnlyTestSig12", IPOnlyTestSig12);
    UtRegisterTest("IPOnlyTestSig13", IPOnlyTestSig13);
    UtRegisterTest("IPOnlyTestSig14", IPOnlyTestSig14);
    UtRegisterTest("IPOnlyTestSig15", IPOnlyTestSig15);
    UtRegisterTest("IPOnlyTestSig16", IPOnlyTestSig16);
    UtRegisterTest("IPOnlyTestSig17", IPOnlyTestSig17);
    UtRegisterTest("IPOnlyTestSig18", IPOnlyTestSig18);
    UtRegisterTest("IPOnlyTestSig19", IPOnlyTestSig19);

#endif
}

