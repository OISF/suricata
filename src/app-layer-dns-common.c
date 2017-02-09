/* Copyright (C) 2013-2014 Open Information Security Foundation
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

#include "suricata-common.h"
#include "stream.h"
#include "app-layer-parser.h"
#include "app-layer-dns-common.h"
#ifdef DEBUG
#include "util-print.h"
#endif
#include "util-memcmp.h"
#include "util-atomic.h"

typedef struct DNSConfig_ {
    uint32_t request_flood;
    uint32_t state_memcap;  /**< memcap in bytes per state */
    uint64_t global_memcap; /**< memcap in bytes globally for parser */
} DNSConfig;
static DNSConfig dns_config;

void DNSConfigInit(void)
{
    memset(&dns_config, 0x00, sizeof(dns_config));
}

void DNSConfigSetRequestFlood(uint32_t value)
{
    dns_config.request_flood = value;
}

void DNSConfigSetStateMemcap(uint32_t value)
{
    dns_config.state_memcap = value;
}

SC_ATOMIC_DECLARE(uint64_t, dns_memuse); /**< byte counter of current memuse */
SC_ATOMIC_DECLARE(uint64_t, dns_memcap_state); /**< counts number of 'rejects' */
SC_ATOMIC_DECLARE(uint64_t, dns_memcap_global); /**< counts number of 'rejects' */

void DNSConfigSetGlobalMemcap(uint64_t value)
{
    dns_config.global_memcap = value;

    SC_ATOMIC_INIT(dns_memuse);
    SC_ATOMIC_INIT(dns_memcap_state);
    SC_ATOMIC_INIT(dns_memcap_global);
}

void DNSIncrMemcap(uint32_t size, DNSState *state)
{
    if (state != NULL) {
        state->memuse += size;
    }
    SC_ATOMIC_ADD(dns_memuse, size);
}

void DNSDecrMemcap(uint32_t size, DNSState *state)
{
    if (state != NULL) {
        BUG_ON(size > state->memuse); /**< TODO remove later */
        state->memuse -= size;
    }

    BUG_ON(size > SC_ATOMIC_GET(dns_memuse)); /**< TODO remove later */
    (void)SC_ATOMIC_SUB(dns_memuse, size);
}

int DNSCheckMemcap(uint32_t want, DNSState *state)
{
    if (state != NULL) {
        if (state->memuse + want > dns_config.state_memcap) {
            SC_ATOMIC_ADD(dns_memcap_state, 1);
            DNSSetEvent(state, DNS_DECODER_EVENT_STATE_MEMCAP_REACHED);
            return -1;
        }
    }

    if (SC_ATOMIC_GET(dns_memuse) + (uint64_t)want > dns_config.global_memcap) {
        SC_ATOMIC_ADD(dns_memcap_global, 1);
        return -2;
    }

    return 0;
}

uint64_t DNSMemcapGetMemuseCounter(void)
{
    uint64_t x = SC_ATOMIC_GET(dns_memuse);
    return x;
}

uint64_t DNSMemcapGetMemcapStateCounter(void)
{
    uint64_t x = SC_ATOMIC_GET(dns_memcap_state);
    return x;
}

uint64_t DNSMemcapGetMemcapGlobalCounter(void)
{
    uint64_t x = SC_ATOMIC_GET(dns_memcap_global);
    return x;
}

SCEnumCharMap dns_decoder_event_table[ ] = {
    { "UNSOLLICITED_RESPONSE",      DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE, },
    { "MALFORMED_DATA",             DNS_DECODER_EVENT_MALFORMED_DATA, },
    { "NOT_A_REQUEST",              DNS_DECODER_EVENT_NOT_A_REQUEST, },
    { "NOT_A_RESPONSE",             DNS_DECODER_EVENT_NOT_A_RESPONSE, },
    { "Z_FLAG_SET",                 DNS_DECODER_EVENT_Z_FLAG_SET, },
    { "FLOODED",                    DNS_DECODER_EVENT_FLOODED, },
    { "STATE_MEMCAP_REACHED",       DNS_DECODER_EVENT_STATE_MEMCAP_REACHED, },

    { NULL,                         -1 },
};

int DNSStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, dns_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "dns's enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

void DNSAppLayerRegisterGetEventInfo(uint8_t ipproto, AppProto alproto)
{
    AppLayerParserRegisterGetEventInfo(ipproto, alproto, DNSStateGetEventInfo);

    return;
}

AppLayerDecoderEvents *DNSGetEvents(void *state, uint64_t id)
{
    DNSState *dns_state = (DNSState *)state;
    DNSTransaction *tx;

    if (dns_state->curr && dns_state->curr->tx_num == (id + 1)) {
        return dns_state->curr->decoder_events;
    }

    TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
        if (tx->tx_num == (id+1))
            return tx->decoder_events;
    }
    return NULL;
}

int DNSHasEvents(void *state)
{
    DNSState *dns_state = (DNSState *)state;
    return (dns_state->events > 0);
}

void *DNSGetTx(void *alstate, uint64_t tx_id)
{
    DNSState *dns_state = (DNSState *)alstate;
    DNSTransaction *tx = NULL;

    /* fast track: try the current tx */
    if (dns_state->curr && dns_state->curr->tx_num == tx_id + 1)
        return dns_state->curr;

    /* fast track:
     * if the prev tx_id is equal to the stored tx ptr, we can
     * use this shortcut to get to the next. */
    if (dns_state->iter) {
        if (tx_id == dns_state->iter->tx_num) {
            tx = TAILQ_NEXT(dns_state->iter, next);
            if (tx && tx->tx_num == tx_id + 1) {
                dns_state->iter = tx;
                return tx;
            }
        }
    }

    /* no luck with the fast tracks, do the full list walk */
    TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
        SCLogDebug("tx->tx_num %u, tx_id %"PRIu64, tx->tx_num, (tx_id+1));
        if ((tx_id+1) != tx->tx_num)
            continue;

        SCLogDebug("returning tx %p", tx);
        dns_state->iter = tx;
        return tx;
    }

    return NULL;
}

uint64_t DNSGetTxCnt(void *alstate)
{
    DNSState *dns_state = (DNSState *)alstate;
    return (uint64_t)dns_state->transaction_max;
}

int DNSGetAlstateProgress(void *tx, uint8_t direction)
{
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    if (direction & STREAM_TOCLIENT) {
        /* response side of the tx is done if we parsed a reply
         * or if we tagged this tx as 'reply lost'. */
        return (dns_tx->replied|dns_tx->reply_lost) ? 1 : 0;
    }
    else {
        /* tx is only created if we have a complete request,
         * or if we lost the request. Either way, if we have
         * a tx it we consider the request complete. */
        return 1;
    }
}

void DNSSetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    dns_tx->logged |= logger;
}

int DNSGetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    if (dns_tx->logged & logger)
        return 1;

    return 0;
}

/** \brief get value for 'complete' status in DNS
 *
 *  For DNS we use a simple bool. 1 means done.
 */
int DNSGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

void DNSSetEvent(DNSState *s, uint8_t e)
{
    if (s && s->curr) {
        SCLogDebug("s->curr->decoder_events %p", s->curr->decoder_events);
        AppLayerDecoderEventsSetEventRaw(&s->curr->decoder_events, e);
        SCLogDebug("s->curr->decoder_events %p", s->curr->decoder_events);
        s->events++;
    } else {
        SCLogDebug("couldn't set event %u", e);
    }
}

/** \internal
 *  \brief Allocate a DNS TX
 *  \retval tx or NULL */
static DNSTransaction *DNSTransactionAlloc(DNSState *state, const uint16_t tx_id)
{
    if (DNSCheckMemcap(sizeof(DNSTransaction), state) < 0)
        return NULL;

    DNSTransaction *tx = SCMalloc(sizeof(DNSTransaction));
    if (unlikely(tx == NULL))
        return NULL;
    DNSIncrMemcap(sizeof(DNSTransaction), state);

    memset(tx, 0x00, sizeof(DNSTransaction));

    TAILQ_INIT(&tx->query_list);
    TAILQ_INIT(&tx->answer_list);
    TAILQ_INIT(&tx->authority_list);

    tx->tx_id = tx_id;
    return tx;
}

/** \internal
 *  \brief Free a DNS TX
 *  \param tx DNS TX to free */
static void DNSTransactionFree(DNSTransaction *tx, DNSState *state)
{
    SCEnter();

    DNSQueryEntry *q = NULL;
    while ((q = TAILQ_FIRST(&tx->query_list))) {
        TAILQ_REMOVE(&tx->query_list, q, next);
        DNSDecrMemcap((sizeof(DNSQueryEntry) + q->len), state);
        SCFree(q);
    }

    DNSAnswerEntry *a = NULL;
    while ((a = TAILQ_FIRST(&tx->answer_list))) {
        TAILQ_REMOVE(&tx->answer_list, a, next);
        DNSDecrMemcap((sizeof(DNSAnswerEntry) + a->fqdn_len + a->data_len), state);
        SCFree(a);
    }
    while ((a = TAILQ_FIRST(&tx->authority_list))) {
        TAILQ_REMOVE(&tx->authority_list, a, next);
        DNSDecrMemcap((sizeof(DNSAnswerEntry) + a->fqdn_len + a->data_len), state);
        SCFree(a);
    }

    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    if (tx->de_state != NULL) {
        DetectEngineStateFree(tx->de_state);
        BUG_ON(state->tx_with_detect_state_cnt == 0);
        state->tx_with_detect_state_cnt--;
    }

    if (state->iter == tx)
        state->iter = NULL;

    DNSDecrMemcap(sizeof(DNSTransaction), state);
    SCFree(tx);
    SCReturn;
}

/**
 *  \brief dns transaction cleanup callback
 */
void DNSStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();

    DNSState *dns_state = state;
    DNSTransaction *tx = NULL;

    SCLogDebug("state %p, id %"PRIu64, dns_state, tx_id);

    TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
        SCLogDebug("tx %p tx->tx_num %u, tx_id %"PRIu64, tx, tx->tx_num, (tx_id+1));
        if ((tx_id+1) < tx->tx_num)
            break;
        else if ((tx_id+1) > tx->tx_num)
            continue;

        if (tx == dns_state->curr)
            dns_state->curr = NULL;

        if (tx->decoder_events != NULL) {
            if (tx->decoder_events->cnt <= dns_state->events)
                dns_state->events -= tx->decoder_events->cnt;
            else
                dns_state->events = 0;
        }

        TAILQ_REMOVE(&dns_state->tx_list, tx, next);
        DNSTransactionFree(tx, state);
        break;
    }
    SCReturn;
}

/** \internal
 *  \brief Find the DNS Tx in the state
 *  \param tx_id id of the tx
 *  \retval tx or NULL if not found */
DNSTransaction *DNSTransactionFindByTxId(const DNSState *dns_state, const uint16_t tx_id)
{
    if (dns_state->curr == NULL)
        return NULL;

    /* fast path */
    if (dns_state->curr->tx_id == tx_id) {
        return dns_state->curr;

    /* slow path, iterate list */
    } else {
        DNSTransaction *tx = NULL;
        TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
            if (tx->tx_id == tx_id) {
                return tx;
            } else if ((dns_state->transaction_max - tx->tx_num) >
                (dns_state->window - 1U)) {
                tx->reply_lost = 1;
            }
        }
    }
    /* not found */
    return NULL;
}

int DNSStateHasTxDetectState(void *alstate)
{
    DNSState *state = (DNSState *)alstate;
    return (state->tx_with_detect_state_cnt > 0);
}

DetectEngineState *DNSGetTxDetectState(void *vtx)
{
    DNSTransaction *tx = (DNSTransaction *)vtx;
    return tx->de_state;
}

int DNSSetTxDetectState(void *alstate, void *vtx, DetectEngineState *s)
{
    DNSState *state = (DNSState *)alstate;
    DNSTransaction *tx = (DNSTransaction *)vtx;
    state->tx_with_detect_state_cnt++;
    tx->de_state = s;
    return 0;
}

void *DNSStateAlloc(void)
{
    void *s = SCMalloc(sizeof(DNSState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(DNSState));

    DNSState *dns_state = (DNSState *)s;

    DNSIncrMemcap(sizeof(DNSState), dns_state);

    TAILQ_INIT(&dns_state->tx_list);
    return s;
}

void DNSStateFree(void *s)
{
    SCEnter();
    if (s) {
        DNSState *dns_state = (DNSState *) s;

        DNSTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&dns_state->tx_list))) {
            TAILQ_REMOVE(&dns_state->tx_list, tx, next);
            DNSTransactionFree(tx, dns_state);
        }

        if (dns_state->buffer != NULL) {
            DNSDecrMemcap(0xffff, dns_state); /** TODO update if/once we alloc
                                               *  in a smarter way */
            SCFree(dns_state->buffer);
        }

        BUG_ON(dns_state->tx_with_detect_state_cnt > 0);

        DNSDecrMemcap(sizeof(DNSState), dns_state);
        BUG_ON(dns_state->memuse > 0);
        SCFree(s);
    }
    SCReturn;
}

/** \brief Validation checks for DNS request header
 *
 *  Will set decoder events if anomalies are found.
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int DNSValidateRequestHeader(DNSState *dns_state, const DNSHeader *dns_header)
{
    uint16_t flags = ntohs(dns_header->flags);

    if ((flags & 0x8000) != 0) {
        SCLogDebug("not a request 0x%04x", flags);
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_NOT_A_REQUEST);
        goto bad_data;
    }

    if ((flags & 0x0040) != 0) {
        SCLogDebug("Z flag not 0, 0x%04x", flags);
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_Z_FLAG_SET);
        goto bad_data;
    }

    return 0;
bad_data:
    return -1;
}

/** \brief Validation checks for DNS response header
 *
 *  Will set decoder events if anomalies are found.
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int DNSValidateResponseHeader(DNSState *dns_state, const DNSHeader *dns_header)
{
    uint16_t flags = ntohs(dns_header->flags);

    if ((flags & 0x8000) == 0) {
        SCLogDebug("not a response 0x%04x", flags);
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_NOT_A_RESPONSE);
        goto bad_data;
    }

    if ((flags & 0x0040) != 0) {
        SCLogDebug("Z flag not 0, 0x%04x", flags);
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_Z_FLAG_SET);
        goto bad_data;
    }

    return 0;
bad_data:
    return -1;
}

/** \internal
 *  \brief check the query list to see if we already have this exact query
 *  \retval bool true or false
 */
static int QueryIsDuplicate(DNSTransaction *tx, const uint8_t *fqdn, const uint16_t fqdn_len,
        const uint16_t type, const uint16_t class)
{
    DNSQueryEntry *q = NULL;

    TAILQ_FOREACH(q, &tx->query_list, next) {
        uint8_t *qfqdn = (uint8_t *)q + sizeof(DNSQueryEntry);

        if (q->len == fqdn_len && q->type == type &&
            q->class == class &&
            SCMemcmp(qfqdn, fqdn, fqdn_len) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

void DNSStoreQueryInState(DNSState *dns_state, const uint8_t *fqdn, const uint16_t fqdn_len,
        const uint16_t type, const uint16_t class, const uint16_t tx_id)
{
    /* flood protection */
    if (dns_state->givenup)
        return;

    /* find the tx and see if this is an exact duplicate */
    DNSTransaction *tx = DNSTransactionFindByTxId(dns_state, tx_id);
    if ((tx != NULL) && (QueryIsDuplicate(tx, fqdn, fqdn_len, type, class) == TRUE)) {
        SCLogDebug("query is duplicate");
        return;
    }

    /* check flood limit */
    if (dns_config.request_flood != 0 &&
        dns_state->unreplied_cnt > dns_config.request_flood) {
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_FLOODED);
        dns_state->givenup = 1;
    }

    if (tx == NULL) {
        tx = DNSTransactionAlloc(dns_state, tx_id);
        if (tx == NULL)
            return;
        dns_state->transaction_max++;
        SCLogDebug("dns_state->transaction_max updated to %"PRIu64, dns_state->transaction_max);
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
        dns_state->curr = tx;
        tx->tx_num = dns_state->transaction_max;
        SCLogDebug("new tx %u with internal id %u", tx->tx_id, tx->tx_num);
        dns_state->unreplied_cnt++;
    }

    if (DNSCheckMemcap((sizeof(DNSQueryEntry) + fqdn_len), dns_state) < 0)
        return;
    DNSQueryEntry *q = SCMalloc(sizeof(DNSQueryEntry) + fqdn_len);
    if (unlikely(q == NULL))
        return;
    DNSIncrMemcap((sizeof(DNSQueryEntry) + fqdn_len), dns_state);

    q->type = type;
    q->class = class;
    q->len = fqdn_len;
    memcpy((uint8_t *)q + sizeof(DNSQueryEntry), fqdn, fqdn_len);

    TAILQ_INSERT_TAIL(&tx->query_list, q, next);

    SCLogDebug("Query for TX %04x stored", tx_id);
}

void DNSStoreAnswerInState(DNSState *dns_state, const int rtype, const uint8_t *fqdn,
        const uint16_t fqdn_len, const uint16_t type, const uint16_t class, const uint16_t ttl,
        const uint8_t *data, const uint16_t data_len, const uint16_t tx_id)
{
    DNSTransaction *tx = DNSTransactionFindByTxId(dns_state, tx_id);
    if (tx == NULL) {
        tx = DNSTransactionAlloc(dns_state, tx_id);
        if (tx == NULL)
            return;
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
        dns_state->curr = tx;
        dns_state->transaction_max++;
        tx->tx_num = dns_state->transaction_max;
    }

    if (DNSCheckMemcap((sizeof(DNSAnswerEntry) + fqdn_len + data_len), dns_state) < 0)
        return;
    DNSAnswerEntry *q = SCMalloc(sizeof(DNSAnswerEntry) + fqdn_len + data_len);
    if (unlikely(q == NULL))
        return;
    DNSIncrMemcap((sizeof(DNSAnswerEntry) + fqdn_len + data_len), dns_state);

    q->type = type;
    q->class = class;
    q->ttl = ttl;
    q->fqdn_len = fqdn_len;
    q->data_len = data_len;

    uint8_t *ptr = (uint8_t *)q + sizeof(DNSAnswerEntry);
    if (fqdn != NULL && fqdn_len > 0) {
        memcpy(ptr, fqdn, fqdn_len);
        ptr += fqdn_len;
    }
    if (data != NULL && data_len > 0) {
        memcpy(ptr, data, data_len);
    }

    if (rtype == DNS_LIST_ANSWER)
        TAILQ_INSERT_TAIL(&tx->answer_list, q, next);
    else if (rtype == DNS_LIST_AUTHORITY)
        TAILQ_INSERT_TAIL(&tx->authority_list, q, next);
    else
        BUG_ON(1);

    SCLogDebug("Answer for TX %04x stored", tx_id);

    /* mark tx is as replied so we can log it */
    tx->replied = 1;
}

/** \internal
 *  \brief get domain name from dns packet
 *
 *  In case of compressed name storage this function follows the ptrs to
 *  create the full domain name.
 *
 *  The length bytes are converted into dots, e.g. |03|com|00| becomes
 *  .com
 *  The trailing . is not stored.
 *
 *  \param input input buffer (complete dns record)
 *  \param input_len lenght of input buffer
 *  \param offset offset into @input where dns name starts
 *  \param fqdn buffer to store result
 *  \param fqdn_size size of @fqdn buffer
 *  \retval 0 on error/no buffer
 *  \retval size size of fqdn
 */
static uint16_t DNSResponseGetNameByOffset(const uint8_t * const input, const uint32_t input_len,
        const uint16_t offset, uint8_t *fqdn, const size_t fqdn_size)
{
    if (offset >= input_len) {
        SCLogDebug("input buffer too small for domain of len %u", offset);
        goto insufficient_data;
    }

    int steps = 0;
    uint16_t fqdn_offset = 0;
    uint8_t length = *(input + offset);
    const uint8_t *qdata = input + offset;
    SCLogDebug("qry length %u", length);

    if (length == 0) {
        memcpy(fqdn, "<root>", 6);
        SCReturnUInt(6U);
    }

    if ((uint64_t)((qdata + 1) - input) >= (uint64_t)input_len) {
        SCLogDebug("input buffer too small");
        goto insufficient_data;
    }

    while (length != 0) {
        int cnt = 0;
        while (length & 0xc0) {
            uint16_t off = ((length & 0x3f) << 8) + *(qdata+1);
            qdata = (const uint8_t *)input + off;

            if ((uint64_t)((qdata + 1) - input) >= (uint64_t)input_len) {
                SCLogDebug("input buffer too small");
                goto insufficient_data;
            }

            length = *qdata;
            SCLogDebug("qry length %u", length);

            if (cnt++ == 100) {
                SCLogDebug("too many pointer iterations, loop?");
                goto bad_data;
            }
        }
        qdata++;

        if (length == 0) {
            break;
        }

        if (input + input_len < qdata + length) {
            SCLogDebug("input buffer too small for domain of len %u", length);
            goto insufficient_data;
        }
        //PrintRawDataFp(stdout, qdata, length);

        if ((size_t)(fqdn_offset + length + 1) < fqdn_size) {
            memcpy(fqdn + fqdn_offset, qdata, length);
            fqdn_offset += length;
            fqdn[fqdn_offset++] = '.';
        }
        qdata += length;

        /* if we're at the end of the input data, we're done */
        if ((uint64_t)((qdata + 1) - input) == (uint64_t)input_len) {
            break;
        }
        else if ((uint64_t)((qdata + 1) - input) > (uint64_t)input_len) {
            SCLogDebug("input buffer too small");
            goto insufficient_data;
        }

        length = *qdata;
        SCLogDebug("qry length %u", length);
        steps++;
        if (steps >= 255)
            goto bad_data;
    }
    if (fqdn_offset) {
        fqdn_offset--;
    }
    //PrintRawDataFp(stdout, fqdn, fqdn_offset);
    SCReturnUInt(fqdn_offset);
bad_data:
insufficient_data:
    SCReturnUInt(0U);
}

/** \internal
 *  \brief skip past domain name field
 *
 *  Skip the domain at position data. We don't care about following compressed names
 *  as we only want to know when the next part of the buffer starts
 *
 *  \param input input buffer (complete dns record)
 *  \param input_len lenght of input buffer
 *  \param data current position
 *
 *  \retval NULL on out of bounds data
 *  \retval sdata ptr to position in buffer past the name
 */
static const uint8_t *SkipDomain(const uint8_t * const input,
        const uint32_t input_len, const uint8_t *data)
{
    const uint8_t *sdata = data;
    while (*sdata != 0x00) {
        if (*sdata & 0xc0) {
            sdata++;
            break;
        } else {
            sdata += ((*sdata) + 1);
        }
        if (input + input_len < sdata) {
            SCLogDebug("input buffer too small for data of len");
            goto insufficient_data;
        }
    }
    sdata++;
    if (input + input_len < sdata) {
        SCLogDebug("input buffer too small for data of len");
        goto insufficient_data;
    }
    return sdata;
insufficient_data:
    return NULL;
}

const uint8_t *DNSReponseParse(DNSState *dns_state, const DNSHeader * const dns_header,
        const uint16_t num, const DnsListEnum list, const uint8_t * const input,
        const uint32_t input_len, const uint8_t *data)
{
    if (input + input_len < data + 2) {
        SCLogDebug("input buffer too small for record 'name' field, record %u, "
                "total answer_rr %u", num, ntohs(dns_header->answer_rr));
        goto insufficient_data;
    }

    uint8_t fqdn[DNS_MAX_SIZE];
    uint16_t fqdn_len = 0;

    /* see if name is compressed */
    if (!(data[0] & 0xc0)) {
        if ((fqdn_len = DNSResponseGetNameByOffset(input, input_len,
                        data - input, fqdn, sizeof(fqdn))) == 0)
        {
            DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
            goto insufficient_data;
        }
        //PrintRawDataFp(stdout, fqdn, fqdn_len);
        const uint8_t *tdata = SkipDomain(input, input_len, data);
        if (tdata == NULL) {
            goto insufficient_data;
        }
        data = tdata;
    } else {
        uint16_t offset = (data[0] & 0x3f) << 8 | data[1];

        if ((fqdn_len = DNSResponseGetNameByOffset(input, input_len,
                        offset, fqdn, sizeof(fqdn))) == 0)
        {
            DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
            goto insufficient_data;
        }
        //PrintRawDataFp(stdout, fqdn, fqdn_len);
        data += 2;
    }

    if (input + input_len < data + sizeof(DNSAnswerHeader)) {
        SCLogDebug("input buffer too small for DNSAnswerHeader");
        goto insufficient_data;
    }

    const DNSAnswerHeader *head = (DNSAnswerHeader *)data;
    const uint16_t datalen = ntohs(head->len);

    data += sizeof(DNSAnswerHeader);

    SCLogDebug("head->len %u", ntohs(head->len));

    if (input + input_len < data + ntohs(head->len)) {
        SCLogDebug("input buffer too small for data of len %u", ntohs(head->len));
        goto insufficient_data;
    }

    SCLogDebug("TTL %u", ntohl(head->ttl));

    switch (ntohs(head->type)) {
        case DNS_RECORD_TYPE_A:
        {
            if (datalen == 0 || datalen == 4) {
                //PrintRawDataFp(stdout, data, ntohs(head->len));
                //char a[16];
                //PrintInet(AF_INET, (const void *)data, a, sizeof(a));
                //SCLogInfo("A %s TTL %u", a, ntohl(head->ttl));

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        data, datalen, ntohs(dns_header->tx_id));
            } else {
                SCLogDebug("invalid length for A response data: %u", ntohs(head->len));
                goto bad_data;
            }

            data += datalen;
            break;
        }
        case DNS_RECORD_TYPE_AAAA:
        {
            if (datalen == 0 || datalen == 16) {
                //char a[46];
                //PrintInet(AF_INET6, (const void *)data, a, sizeof(a));
                //SCLogInfo("AAAA %s TTL %u", a, ntohl(head->ttl));

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        data, datalen, ntohs(dns_header->tx_id));
            } else {
                SCLogDebug("invalid length for AAAA response data: %u", ntohs(head->len));
                goto bad_data;
            }

            data += datalen;
            break;
        }
        case DNS_RECORD_TYPE_MX:
        case DNS_RECORD_TYPE_CNAME:
        case DNS_RECORD_TYPE_PTR:
        {
            uint8_t name[DNS_MAX_SIZE];
            uint16_t name_len = 0;
            uint8_t skip = 0;

            if (ntohs(head->type) == DNS_RECORD_TYPE_MX) {
                // Skip the preference header
                skip = 2;
            }

            if ((name_len = DNSResponseGetNameByOffset(input, input_len,
                            data - input + skip, name, sizeof(name))) == 0)
            {
                DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
                goto insufficient_data;
            }

            DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    name, name_len, ntohs(dns_header->tx_id));

            data += ntohs(head->len);
            break;
        }
        case DNS_RECORD_TYPE_NS:
        case DNS_RECORD_TYPE_SOA:
        {
            uint8_t pname[DNS_MAX_SIZE];
            uint16_t pname_len = 0;

            if ((pname_len = DNSResponseGetNameByOffset(input, input_len,
                            data - input, pname, sizeof(pname))) == 0)
            {
                DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
                goto insufficient_data;
            }

            if (ntohs(head->type) == DNS_RECORD_TYPE_SOA) {
                const uint8_t *sdata = SkipDomain(input, input_len, data);
                if (sdata == NULL) {
                    goto insufficient_data;
                }

                uint8_t pmail[DNS_MAX_SIZE];
                uint16_t pmail_len = 0;
                SCLogDebug("getting pmail");
                if ((pmail_len = DNSResponseGetNameByOffset(input, input_len,
                                sdata - input, pmail, sizeof(pmail))) == 0)
                {
                    DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
                    goto insufficient_data;
                }
                SCLogDebug("pmail_len %u", pmail_len);
                //PrintRawDataFp(stdout, (uint8_t *)pmail, pmail_len);

                const uint8_t *tdata = SkipDomain(input, input_len, sdata);
                if (tdata == NULL) {
                    goto insufficient_data;
                }
#if DEBUG
                struct Trailer {
                    uint32_t serial;
                    uint32_t refresh;
                    uint32_t retry;
                    uint32_t experiation;
                    uint32_t minttl;
                } *tail = (struct Trailer *)tdata;

                if (input + input_len < tdata + sizeof(struct Trailer)) {
                    SCLogDebug("input buffer too small for data of len");
                    goto insufficient_data;
                }

                SCLogDebug("serial %u refresh %u retry %u exp %u min ttl %u",
                        ntohl(tail->serial), ntohl(tail->refresh),
                        ntohl(tail->retry), ntohl(tail->experiation),
                        ntohl(tail->minttl));
#endif
            }

            DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    pname, pname_len, ntohs(dns_header->tx_id));

            data += ntohs(head->len);
            break;
        }
        case DNS_RECORD_TYPE_TXT:
        {
            uint16_t txtdatalen = datalen;

            if (txtdatalen == 0) {
                DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
                goto bad_data;
            }

            uint8_t txtlen = *data;
            const uint8_t *tdata = data + 1;

            do {
                //PrintRawDataFp(stdout, (uint8_t*)tdata, txtlen);

                if (txtlen >= txtdatalen)
                    goto bad_data;

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        (uint8_t*)tdata, (uint16_t)txtlen, ntohs(dns_header->tx_id));

                txtdatalen -= txtlen;
                tdata += txtlen;
                txtlen = *tdata;

                tdata++;
                txtdatalen--;

                SCLogDebug("datalen %u, txtlen %u", txtdatalen, txtlen);
            } while (txtdatalen > 1);

            data += datalen;
            break;
        }
        case DNS_RECORD_TYPE_SSHFP:
        {
            /* data here should be:
             * [1 byte algo][1 byte type][var bytes fingerprint]
             * As we currently can't store each of those in the state,
             * we just store the raw data an let the output/detect
             * code figure out what to do with it. */

            DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    data, ntohs(head->len), ntohs(dns_header->tx_id));

            data += datalen;
            break;
        }
        default:    /* unsupported record */
        {
            DNSStoreAnswerInState(dns_state, list, NULL, 0,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    NULL, 0, ntohs(dns_header->tx_id));

            //PrintRawDataFp(stdout, data, ntohs(head->len));
            data += datalen;
            break;
        }
    }
    return data;
bad_data:
insufficient_data:
    return NULL;
}

void DNSCreateTypeString(uint16_t type, char *str, size_t str_size)
{
    switch (type) {
        case DNS_RECORD_TYPE_A:
            snprintf(str, str_size, "A");
            break;
        case DNS_RECORD_TYPE_NS:
            snprintf(str, str_size, "NS");
            break;
        case DNS_RECORD_TYPE_AAAA:
            snprintf(str, str_size, "AAAA");
            break;
        case DNS_RECORD_TYPE_CNAME:
            snprintf(str, str_size, "CNAME");
            break;
        case DNS_RECORD_TYPE_TXT:
            snprintf(str, str_size, "TXT");
            break;
        case DNS_RECORD_TYPE_MX:
            snprintf(str, str_size, "MX");
            break;
        case DNS_RECORD_TYPE_SOA:
            snprintf(str, str_size, "SOA");
            break;
        case DNS_RECORD_TYPE_PTR:
            snprintf(str, str_size, "PTR");
            break;
        case DNS_RECORD_TYPE_SIG:
            snprintf(str, str_size, "SIG");
            break;
        case DNS_RECORD_TYPE_KEY:
            snprintf(str, str_size, "KEY");
            break;
        case DNS_RECORD_TYPE_WKS:
            snprintf(str, str_size, "WKS");
            break;
        case DNS_RECORD_TYPE_TKEY:
            snprintf(str, str_size, "TKEY");
            break;
        case DNS_RECORD_TYPE_TSIG:
            snprintf(str, str_size, "TSIG");
            break;
        case DNS_RECORD_TYPE_ANY:
            snprintf(str, str_size, "ANY");
            break;
        case DNS_RECORD_TYPE_RRSIG:
            snprintf(str, str_size, "RRSIG");
            break;
        case DNS_RECORD_TYPE_NSEC:
            snprintf(str, str_size, "NSEC");
            break;
        case DNS_RECORD_TYPE_DNSKEY:
            snprintf(str, str_size, "DNSKEY");
            break;
        case DNS_RECORD_TYPE_HINFO:
            snprintf(str, str_size, "HINFO");
            break;
        case DNS_RECORD_TYPE_MINFO:
            snprintf(str, str_size, "MINFO");
            break;
        case DNS_RECORD_TYPE_RP:
            snprintf(str, str_size, "RP");
            break;
        case DNS_RECORD_TYPE_AFSDB:
            snprintf(str, str_size, "AFSDB");
            break;
        case DNS_RECORD_TYPE_X25:
            snprintf(str, str_size, "X25");
            break;
        case DNS_RECORD_TYPE_ISDN:
            snprintf(str, str_size, "ISDN");
            break;
        case DNS_RECORD_TYPE_RT:
            snprintf(str, str_size, "RT");
            break;
        case DNS_RECORD_TYPE_NSAP:
            snprintf(str, str_size, "NSAP");
            break;
        case DNS_RECORD_TYPE_NSAPPTR:
            snprintf(str, str_size, "NSAPPTR");
            break;
        case DNS_RECORD_TYPE_PX:
            snprintf(str, str_size, "PX");
            break;
        case DNS_RECORD_TYPE_GPOS:
            snprintf(str, str_size, "GPOS");
            break;
        case DNS_RECORD_TYPE_LOC:
            snprintf(str, str_size, "LOC");
            break;
        case DNS_RECORD_TYPE_SRV:
            snprintf(str, str_size, "SRV");
            break;
        case DNS_RECORD_TYPE_ATMA:
            snprintf(str, str_size, "ATMA");
            break;
        case DNS_RECORD_TYPE_NAPTR:
            snprintf(str, str_size, "NAPTR");
            break;
        case DNS_RECORD_TYPE_KX:
            snprintf(str, str_size, "KX");
            break;
        case DNS_RECORD_TYPE_CERT:
            snprintf(str, str_size, "CERT");
            break;
        case DNS_RECORD_TYPE_A6:
            snprintf(str, str_size, "A6");
            break;
        case DNS_RECORD_TYPE_DNAME:
            snprintf(str, str_size, "DNAME");
            break;
        case DNS_RECORD_TYPE_OPT:
            snprintf(str, str_size, "OPT");
            break;
        case DNS_RECORD_TYPE_APL:
            snprintf(str, str_size, "APL");
            break;
        case DNS_RECORD_TYPE_DS:
            snprintf(str, str_size, "DS");
            break;
        case DNS_RECORD_TYPE_SSHFP:
            snprintf(str, str_size, "SSHFP");
            break;
        case DNS_RECORD_TYPE_IPSECKEY:
            snprintf(str, str_size, "IPSECKEY");
            break;
        case DNS_RECORD_TYPE_DHCID:
            snprintf(str, str_size, "DHCID");
            break;
        case DNS_RECORD_TYPE_NSEC3:
            snprintf(str, str_size, "NSEC3");
            break;
        case DNS_RECORD_TYPE_NSEC3PARAM:
            snprintf(str, str_size, "NSEC3PARAM");
            break;
        case DNS_RECORD_TYPE_TLSA:
            snprintf(str, str_size, "TLSA");
            break;
        case DNS_RECORD_TYPE_HIP:
            snprintf(str, str_size, "HIP");
            break;
        case DNS_RECORD_TYPE_CDS:
            snprintf(str, str_size, "CDS");
            break;
        case DNS_RECORD_TYPE_CDNSKEY:
            snprintf(str, str_size, "CDNSKEY");
            break;
        case DNS_RECORD_TYPE_MAILA:
            snprintf(str, str_size, "MAILA");
            break;
        case DNS_RECORD_TYPE_URI:
            snprintf(str, str_size, "URI");
            break;
        case DNS_RECORD_TYPE_MB:
            snprintf(str, str_size, "MB");
            break;
        case DNS_RECORD_TYPE_MG:
            snprintf(str, str_size, "MG");
            break;
        case DNS_RECORD_TYPE_MR:
            snprintf(str, str_size, "MR");
            break;
        case DNS_RECORD_TYPE_NULL:
            snprintf(str, str_size, "NULL");
            break;
        case DNS_RECORD_TYPE_SPF:
            snprintf(str, str_size, "SPF");
            break;
        case DNS_RECORD_TYPE_NXT:
            snprintf(str, str_size, "NXT");
            break;
        case DNS_RECORD_TYPE_MD:
            snprintf(str, str_size, "MD");
            break;
        case DNS_RECORD_TYPE_MF:
            snprintf(str, str_size, "MF");
            break;
        default:
            snprintf(str, str_size, "%04x/%u", type, type);
    }
}

void DNSCreateRcodeString(uint8_t rcode, char *str, size_t str_size)
{
    switch (rcode) {
        case DNS_RCODE_NOERROR:
            snprintf(str, str_size, "NOERROR");
            break;
        case DNS_RCODE_FORMERR:
            snprintf(str, str_size, "FORMERR");
            break;
        case DNS_RCODE_SERVFAIL:
            snprintf(str, str_size, "SERVFAIL");
            break;
        case DNS_RCODE_NXDOMAIN:
            snprintf(str, str_size, "NXDOMAIN");
            break;
        case DNS_RCODE_NOTIMP:
            snprintf(str, str_size, "NOTIMP");
            break;
        case DNS_RCODE_REFUSED:
            snprintf(str, str_size, "REFUSED");
            break;
        case DNS_RCODE_YXDOMAIN:
            snprintf(str, str_size, "YXDOMAIN");
            break;
        case DNS_RCODE_YXRRSET:
            snprintf(str, str_size, "YXRRSET");
            break;
        case DNS_RCODE_NXRRSET:
            snprintf(str, str_size, "NXRRSET");
            break;
        case DNS_RCODE_NOTAUTH:
            snprintf(str, str_size, "NOTAUTH");
            break;
        case DNS_RCODE_NOTZONE:
            snprintf(str, str_size, "NOTZONE");
            break;
        /* these are the same, need more logic */
        case DNS_RCODE_BADVERS:
        //case DNS_RCODE_BADSIG:
            snprintf(str, str_size, "BADVERS/BADSIG");
            break;
        case DNS_RCODE_BADKEY:
            snprintf(str, str_size, "BADKEY");
            break;
        case DNS_RCODE_BADTIME:
            snprintf(str, str_size, "BADTIME");
            break;
        case DNS_RCODE_BADMODE:
            snprintf(str, str_size, "BADMODE");
            break;
        case DNS_RCODE_BADNAME:
            snprintf(str, str_size, "BADNAME");
            break;
        case DNS_RCODE_BADALG:
            snprintf(str, str_size, "BADALG");
            break;
        case DNS_RCODE_BADTRUNC:
            snprintf(str, str_size, "BADTRUNC");
            break;
        default:
            SCLogDebug("could not map DNS rcode to name, bug!");
            snprintf(str, str_size, "%04x/%u", rcode, rcode);
    }
}
