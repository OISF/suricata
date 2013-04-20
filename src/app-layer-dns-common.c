/* Copyright (C) 2013 Open Information Security Foundation
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
#include "app-layer-dns-common.h"
#ifdef DEBUG
#include "util-print.h"
#endif

SCEnumCharMap dns_decoder_event_table[ ] = {
    { "UNSOLLICITED_RESPONSE",      DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE, },
    { "MALFORMED_DATA",             DNS_DECODER_EVENT_MALFORMED_DATA, },
    { "NOT_A_REQUEST",              DNS_DECODER_EVENT_NOT_A_REQUEST, },
    { "NOT_A_RESPONSE",             DNS_DECODER_EVENT_NOT_A_RESPONSE, },
    { "Z_FLAG_SET",                 DNS_DECODER_EVENT_Z_FLAG_SET, },

    { NULL,                         -1 },
};

/** \brief register event map */
void DNSAppLayerDecoderEventsRegister(int alproto) {
    AppLayerDecoderEventsModuleRegister(alproto, dns_decoder_event_table);
}

void *DNSStateAlloc(void) {
    void *s = SCMalloc(sizeof(DNSState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(DNSState));

    DNSState *dns_state = (DNSState *)s;

    TAILQ_INIT(&dns_state->tx_list);
    return s;
}

void DNSStateFree(void *s) {
    if (s) {
        DNSState *dns_state = (DNSState *) s;

        DNSTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&dns_state->tx_list))) {
            TAILQ_REMOVE(&dns_state->tx_list, tx, next);
            DNSTransactionFree(tx);
        }

        if (dns_state->buffer != NULL)
            SCFree(dns_state->buffer);

        SCFree(s);
        s = NULL;
    }
}

void *DNSGetTx(void *alstate, uint64_t tx_id) {
    DNSState *dns_state = (DNSState *)alstate;
    DNSTransaction *tx = NULL;

    TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
        SCLogDebug("tx->tx_num %u, tx_id %"PRIu64, tx->tx_num, tx_id);
        if ((tx_id+1) != tx->tx_num)
            continue;

        return tx;
    }

    return NULL;
}

uint64_t DNSGetTxCnt(void *alstate) {
    DNSState *dns_state = (DNSState *)alstate;
    return (uint64_t)dns_state->transaction_max;
}

int DNSGetAlstateProgress(void *tx, uint8_t direction) {
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    return dns_tx->replied;
}

/* value for tx->replied value */
int DNSGetAlstateProgressCompletionStatus(uint8_t direction) {
    return (direction == 0) ? 0 : 1;
}

/** \internal
 *  \brief Allocate a DNS TX
 *  \retval tx or NULL */
DNSTransaction *DNSTransactionAlloc(const uint16_t tx_id) {
    DNSTransaction *tx = SCMalloc(sizeof(DNSTransaction));
    if (tx == NULL)
        return NULL;
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
void DNSTransactionFree(DNSTransaction *tx) {
    DNSQueryEntry *q = NULL;
    while ((q = TAILQ_FIRST(&tx->query_list))) {
        TAILQ_REMOVE(&tx->query_list, q, next);
        SCFree(q);
    }

    DNSAnswerEntry *a = NULL;
    while ((a = TAILQ_FIRST(&tx->answer_list))) {
        TAILQ_REMOVE(&tx->answer_list, a, next);
        SCFree(a);
    }
    while ((a = TAILQ_FIRST(&tx->authority_list))) {
        TAILQ_REMOVE(&tx->authority_list, a, next);
        SCFree(a);
    }
    SCFree(tx);
}

/** \internal
 *  \brief Find the DNS Tx in the state
 *  \param tx_id id of the tx
 *  \retval tx or NULL if not found */
DNSTransaction *DNSTransactionFindByTxId(const DNSState *dns_state, const uint16_t tx_id) {
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
            }
        }
    }
    /* not found */
    return NULL;
}

/** \brief Validation checks for DNS request header
 *
 *  Will set decoder events if anomalies are found.
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int DNSValidateRequestHeader(Flow *f, const DNSHeader *dns_header) {
    uint16_t flags = ntohs(dns_header->flags);

    if ((flags & 0x8000) != 0) {
        SCLogDebug("not a request 0x%04x", flags);
        if (f != NULL)
            AppLayerDecoderEventsSetEvent(f, DNS_DECODER_EVENT_NOT_A_REQUEST);
        goto bad_data;
    }

    if ((flags & 0x0040) != 0) {
        SCLogDebug("Z flag not 0, 0x%04x", flags);
        if (f != NULL)
            AppLayerDecoderEventsSetEvent(f, DNS_DECODER_EVENT_Z_FLAG_SET);
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
int DNSValidateResponseHeader(Flow *f, const DNSHeader *dns_header) {
    uint16_t flags = ntohs(dns_header->flags);

    if ((flags & 0x8000) == 0) {
        SCLogDebug("not a response 0x%04x", flags);
        AppLayerDecoderEventsSetEvent(f, DNS_DECODER_EVENT_NOT_A_RESPONSE);
        goto bad_data;
    }

    if ((flags & 0x0040) != 0) {
        SCLogDebug("Z flag not 0, 0x%04x", flags);
        AppLayerDecoderEventsSetEvent(f, DNS_DECODER_EVENT_Z_FLAG_SET);
        goto bad_data;
    }

    return 0;
bad_data:
    return -1;
}

void DNSStoreQueryInState(DNSState *dns_state, const uint8_t *fqdn, const uint16_t fqdn_len,
        const uint16_t type, const uint16_t class, const uint16_t tx_id)
{
    DNSTransaction *tx = DNSTransactionFindByTxId(dns_state, tx_id);
    if (tx == NULL) {
        tx = DNSTransactionAlloc(tx_id);
        if (tx == NULL)
            return;
        dns_state->transaction_max++;
        SCLogDebug("dns_state->transaction_max updated to %u", dns_state->transaction_max);
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
        dns_state->curr = tx;
        tx->tx_num = dns_state->transaction_max;
        SCLogDebug("new tx %u with internal id %u", tx->tx_id, tx->tx_num);
    }

    DNSQueryEntry *q = SCMalloc(sizeof(DNSQueryEntry) + fqdn_len);
    if (q == NULL)
        return;
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
        tx = DNSTransactionAlloc(tx_id);
        if (tx == NULL)
            return;
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
        dns_state->curr = tx;
        tx->tx_num = dns_state->transaction_max;

    }

    DNSAnswerEntry *q = SCMalloc(sizeof(DNSAnswerEntry) + fqdn_len + data_len);
    if (q == NULL)
        return;
    q->type = type;
    q->class = class;
    q->ttl = ttl;
    q->fqdn_len = fqdn_len;
    q->data_len = data_len;

    uint8_t *ptr = (uint8_t *)q + sizeof(DNSAnswerEntry);
    memcpy(ptr, fqdn, fqdn_len);
    ptr += fqdn_len;
    memcpy(ptr, data, data_len);

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
    if (input + input_len < input + offset + 1) {
        SCLogInfo("input buffer too small for domain of len %u", offset);
        goto insufficient_data;
    }

    uint16_t fqdn_offset = 0;
    uint8_t length = *(input + offset);
    const uint8_t *qdata = input + offset;
    SCLogDebug("qry length %u", length);

    if (length == 0) {
        memcpy(fqdn, "<root>", fqdn_size);
        SCReturnUInt(6U);
    }

    while (length != 0) {
        if (length & 0xc0) {
            uint16_t offset = ((length & 0x3f) << 8) + *(qdata+1);
            qdata = (const uint8_t *)input + offset;

            if (input + input_len < qdata + 1) {
                SCLogInfo("input buffer too small");
                goto insufficient_data;
            }

            length = *qdata;
            SCLogDebug("qry length %u", length);
        }
        qdata++;

        if (length > 0) {
            if (input + input_len < qdata + length) {
                SCLogInfo("input buffer too small for domain of len %u", length);
                goto insufficient_data;
            }
            //PrintRawDataFp(stdout, qdata, length);

            if ((size_t)(fqdn_offset + length + 1) < fqdn_size) {
                memcpy(fqdn + fqdn_offset, qdata, length);
                fqdn_offset += length;
                fqdn[fqdn_offset++] = '.';
            }
        }
        qdata += length;

        if (input + input_len < qdata + 1) {
            SCLogInfo("input buffer too small for len field");
            goto insufficient_data;
        }

        length = *qdata;
        SCLogDebug("qry length %u", length);
    }
    if (fqdn_offset) {
        fqdn_offset--;
    }
    //PrintRawDataFp(stdout, fqdn, fqdn_offset);
    SCReturnUInt(fqdn_offset);
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
            SCLogInfo("input buffer too small for data of len");
            goto insufficient_data;
        }
    }
    sdata++;
    if (input + input_len < sdata) {
        SCLogInfo("input buffer too small for data of len");
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
        SCLogInfo("input buffer too small for record 'name' field, record %u, "
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
#if DEBUG
            PrintRawDataFp(stdout, (uint8_t *)input, input_len);
            BUG_ON(1);
#endif
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
#if DEBUG
            PrintRawDataFp(stdout, (uint8_t *)input, input_len);
            BUG_ON(1);
#endif
            goto insufficient_data;
        }
        //PrintRawDataFp(stdout, fqdn, fqdn_len);
        data += 2;
    }

    if (input + input_len < data + sizeof(DNSAnswerHeader)) {
        SCLogInfo("input buffer too small for DNSAnswerHeader");
        goto insufficient_data;
    }

    const DNSAnswerHeader *head = (DNSAnswerHeader *)data;
    switch (ntohs(head->type)) {
        case DNS_RECORD_TYPE_A:
        case DNS_RECORD_TYPE_AAAA:
        case DNS_RECORD_TYPE_CNAME:
        {
            data += sizeof(DNSAnswerHeader);

            SCLogDebug("head->len %u", ntohs(head->len));

            if (input + input_len < data + ntohs(head->len)) {
                SCLogInfo("input buffer too small for data of len %u", ntohs(head->len));
                goto insufficient_data;
            }
            SCLogDebug("TTL %u", ntohl(head->ttl));

            if (ntohs(head->type) == DNS_RECORD_TYPE_A && ntohs(head->len) == 4) {
                //PrintRawDataFp(stdout, data, ntohs(head->len));
                //char a[16];
                //PrintInet(AF_INET, (const void *)data, a, sizeof(a));
                //SCLogInfo("A %s TTL %u", a, ntohl(head->ttl));

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        data, 4, ntohs(dns_header->tx_id));
            } else if (ntohs(head->type) == DNS_RECORD_TYPE_AAAA && ntohs(head->len) == 16) {
                //char a[46];
                //PrintInet(AF_INET6, (const void *)data, a, sizeof(a));
                //SCLogInfo("AAAA %s TTL %u", a, ntohl(head->ttl));

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        data, 16, ntohs(dns_header->tx_id));
            } else if (ntohs(head->type) == DNS_RECORD_TYPE_CNAME) {
                uint8_t cname[DNS_MAX_SIZE];
                uint16_t cname_len = 0;

                if ((cname_len = DNSResponseGetNameByOffset(input, input_len,
                                data - input, cname, sizeof(cname))) == 0)
                {
#if DEBUG
                    PrintRawDataFp(stdout, (uint8_t *)input, input_len);
                    BUG_ON(1);
#endif
                    goto insufficient_data;
                }

                DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                        ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                        cname, cname_len, ntohs(dns_header->tx_id));
            }

            data += ntohs(head->len);
            break;
        }
        case DNS_RECORD_TYPE_MX:
        {
            data += sizeof(DNSAnswerHeader);

            SCLogDebug("head->len %u", ntohs(head->len));

            if (input + input_len < data + ntohs(head->len)) {
                SCLogInfo("input buffer too small for data of len %u", ntohs(head->len));
                goto insufficient_data;
            }

            SCLogDebug("TTL %u", ntohl(head->ttl));

            uint8_t mxname[DNS_MAX_SIZE];
            uint16_t mxname_len = 0;

            if ((mxname_len = DNSResponseGetNameByOffset(input, input_len,
                            data - input + 2, mxname, sizeof(mxname))) == 0) {
#if DEBUG
                PrintRawDataFp(stdout, (uint8_t *)input, input_len);
                BUG_ON(1);
#endif
                goto insufficient_data;
            }

            DNSStoreAnswerInState(dns_state, list, fqdn, fqdn_len,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    mxname, mxname_len, ntohs(dns_header->tx_id));

            data += ntohs(head->len);
            break;
        }
        case DNS_RECORD_TYPE_NS:
        case DNS_RECORD_TYPE_SOA:
        {
            data += sizeof(DNSAnswerHeader);

            if (input + input_len < data + ntohs(head->len)) {
                SCLogInfo("input buffer too small for data of len %u", ntohs(head->len));
                goto insufficient_data;
            }

            SCLogDebug("TTL %u", ntohl(head->ttl));

            uint8_t pname[DNS_MAX_SIZE];
            uint16_t pname_len = 0;

            if ((pname_len = DNSResponseGetNameByOffset(input, input_len,
                            data - input, pname, sizeof(pname))) == 0)
            {
#if DEBUG
                PrintRawDataFp(stdout, (uint8_t *)input, input_len);
                BUG_ON(1);
#endif
                goto insufficient_data;
            }

            if (ntohs(head->type) == DNS_RECORD_TYPE_SOA) {
                const uint8_t *sdata = SkipDomain(input, input_len, data);
                if (sdata == NULL) {
                    goto insufficient_data;
                }

                uint8_t pmail[DNS_MAX_SIZE];
                uint16_t pmail_len = 0;

                if ((pmail_len = DNSResponseGetNameByOffset(input, input_len,
                                sdata - input, pmail, sizeof(pmail))) == 0)
                {
#if DEBUG
                    PrintRawDataFp(stdout, (uint8_t *)input, input_len);
                    BUG_ON(1);
#endif
                    goto insufficient_data;
                }

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
                    SCLogInfo("input buffer too small for data of len");
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
        default:    /* unsupported record */
        {
            data += sizeof(DNSAnswerHeader);

            if (input + input_len < data + ntohs(head->len)) {
                SCLogInfo("input buffer too small for data of len %u", ntohs(head->len));
                goto insufficient_data;
            }

            DNSStoreAnswerInState(dns_state, list, NULL, 0,
                    ntohs(head->type), ntohs(head->class), ntohl(head->ttl),
                    NULL, 0, ntohs(dns_header->tx_id));

            //PrintRawDataFp(stdout, data, ntohs(head->len));
            data += ntohs(head->len);
            break;
        }
    }
    return data;
insufficient_data:
    return NULL;
}
