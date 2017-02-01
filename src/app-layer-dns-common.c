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
#if 0
            DNSSetEvent(state, DNS_DECODER_EVENT_STATE_MEMCAP_REACHED);
#endif
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
    return rs_dns_state_get_events(dns_state->rs_state, id);
}

int DNSHasEvents(void *state)
{
    DNSState *dns_state = (DNSState *)state;
    return rs_dns_state_has_events(dns_state->rs_state);
}

void *DNSGetTx(void *alstate, uint64_t tx_id)
{
    DNSState *dns_state = (DNSState *)alstate;
    return rs_dns_state_tx_get(dns_state->rs_state, tx_id);
#if 0
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
#endif
}

uint64_t DNSGetTxCnt(void *alstate)
{
    DNSState *dns_state = (DNSState *)alstate;
    return rs_dns_state_get_tx_count(dns_state->rs_state);
}

int DNSGetAlstateProgress(void *tx, uint8_t direction)
{
#if 0
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    BUG_ON(dns_tx == NULL);
    BUG_ON(dns_tx->rs_tx == NULL);
#endif
    return rs_dns_tx_get_alstate_progress(tx,
        direction & STREAM_TOCLIENT ? 1 : 0);
}

void DNSSetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    rs_dns_tx_set_logged(alstate, tx, logger);
}

int DNSGetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    return rs_dns_tx_get_logged(alstate, tx, logger);
}

/** \brief get value for 'complete' status in DNS
 *
 *  For DNS we use a simple bool. 1 means done.
 */
int DNSGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

/** \internal
 *  \brief Allocate a DNS TX
 *  \retval tx or NULL */
DNSTransaction *DNSTransactionAlloc(DNSState *state, const uint16_t tx_id)
{
    if (DNSCheckMemcap(sizeof(DNSTransaction), state) < 0)
        return NULL;

    DNSTransaction *tx = SCCalloc(1, sizeof(DNSTransaction));
    if (unlikely(tx == NULL))
        return NULL;
    DNSIncrMemcap(sizeof(DNSTransaction), state);

    return tx;
}

#if 0
/** \internal
 *  \brief Free a DNS TX
 *  \param tx DNS TX to free */
static void DNSTransactionFree(DNSTransaction *tx, DNSState *state)
{
    SCEnter();

    DetectEngineState *de_state = rs_dns_tx_get_detect_state(tx->rs_tx);
    if (de_state != NULL) {
        DetectEngineStateFree(de_state);
        BUG_ON(state->tx_with_detect_state_cnt == 0);
        state->tx_with_detect_state_cnt--;
    }

    rs_dns_state_tx_free(state->rs_state, tx->tx_num - 1);

    SCReturn;
}
#endif

/**
 *  \brief dns transaction cleanup callback
 */
void DNSStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();

    DNSState *dns_state = state;
    rs_dns_state_tx_free(dns_state->rs_state, tx_id);

    SCReturn;
}

int DNSStateHasTxDetectState(void *alstate)
{
    DNSState *state = (DNSState *)alstate;
    return (state->tx_with_detect_state_cnt > 0);
}

DetectEngineState *DNSGetTxDetectState(void *vtx)
{
    return rs_dns_tx_get_detect_state(vtx);
}

int DNSSetTxDetectState(void *alstate, void *vtx, DetectEngineState *s)
{
    DNSState *state = (DNSState *)alstate;
    state->tx_with_detect_state_cnt++;
    rs_dns_tx_set_detect_state(state->rs_state, vtx, s);
    return 0;
}

void *DNSStateAlloc(void)
{
    DNSState *state  = SCCalloc(1, sizeof(*state));
    if (unlikely(state == NULL)) {
        return NULL;
    }

    DNSIncrMemcap(sizeof(*state), state);
    state->rs_state = rs_dns_state_new(); /* TODO: memcap, null check? */

    return (void *)state;
}

void DNSStateFree(void *s)
{
    SCEnter();
    if (s) {
        DNSState *dns_state = (DNSState *) s;
        if (dns_state->buffer.size > 0) {
            SCFree(dns_state->buffer.buffer);
        }
        //BUG_ON(dns_state->tx_with_detect_state_cnt > 0);
        DNSDecrMemcap(sizeof(DNSState), dns_state);
        rs_dns_state_free(dns_state->rs_state);
        BUG_ON(dns_state->memuse > 0);
        SCFree(s);
    }
    SCReturn;
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
