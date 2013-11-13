/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements JSON DNS logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "output-dnslog.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

static void CreateTypeString(uint16_t type, char *str, size_t str_size) {
    if (type == DNS_RECORD_TYPE_A) {
        snprintf(str, str_size, "A");
    } else if (type == DNS_RECORD_TYPE_NS) {
        snprintf(str, str_size, "NS");
    } else if (type == DNS_RECORD_TYPE_AAAA) {
        snprintf(str, str_size, "AAAA");
    } else if (type == DNS_RECORD_TYPE_TXT) {
        snprintf(str, str_size, "TXT");
    } else if (type == DNS_RECORD_TYPE_CNAME) {
        snprintf(str, str_size, "CNAME");
    } else if (type == DNS_RECORD_TYPE_SOA) {
        snprintf(str, str_size, "SOA");
    } else if (type == DNS_RECORD_TYPE_MX) {
        snprintf(str, str_size, "MX");
    } else if (type == DNS_RECORD_TYPE_PTR) {
        snprintf(str, str_size, "PTR");
    } else if (type == DNS_RECORD_TYPE_ANY) {
        snprintf(str, str_size, "ANY");
    } else if (type == DNS_RECORD_TYPE_TKEY) {
        snprintf(str, str_size, "TKEY");
    } else if (type == DNS_RECORD_TYPE_TSIG) {
        snprintf(str, str_size, "TSIG");
    } else {
        snprintf(str, str_size, "%04x/%u", type, type);
    }
}

static void LogQuery(AlertJsonThread/*LogDnsLogThread*/ *aft, json_t *js, /*char *timebuf, char *srcip, char *dstip, Port sp, Port dp, char *proto, */ DNSTransaction *tx, DNSQueryEntry *entry) {
    MemBuffer *buffer = (MemBuffer *)aft->buffer;

    SCLogDebug("got a DNS request and now logging !!");

    /* reset */
    MemBufferReset(buffer);

    json_t *djs = json_object();
    if (djs == NULL) {
        return;
    }

    /* type */
    json_object_set_new(djs, "type", json_string("query"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    /* query */
    char *c;
    json_object_set_new(djs, "query",
                        json_string(c = strndup(
            (char *)((char *)entry + sizeof(DNSQueryEntry)),
            entry->len)));
    if (c) free(c);

    /* name */
    char record[16] = "";
    CreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(djs, "record", json_string(record));

    /* dns */
    json_object_set_new(js, "dns", djs);
    OutputJSON(js, aft, &aft->dns_cnt);
    json_object_del(js, "dns");
}

static void AppendAnswer(json_t *djs, DNSTransaction *tx, DNSAnswerEntry *entry) {
    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            json_object_set_new(js, "query",
                            json_string(c = strndup(
                (char *)((char *)entry + sizeof(DNSAnswerEntry)),
                entry->fqdn_len)));
            if (c) free(c);
        }

        /* name */
        char record[16] = "";
        CreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(js, "record", json_string(record));

        /* ttl */
        json_object_set_new(js, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "addr", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "addr", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(js, "addr", json_string(""));
        }
    }
    json_array_append_new(djs, js);
}

static void LogAnswers(AlertJsonThread/*LogDnsLogThread*/ *aft, json_t *js, /*char *timebuf, char *srcip, char *dstip, Port sp, Port dp, char *proto,*/ DNSTransaction *tx) {
    MemBuffer *buffer = (MemBuffer *)aft->buffer;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(buffer);

    json_t *djs = json_array();
    if (djs == NULL) {
        return;
    }

    if (tx->no_such_name) {
        AppendAnswer(djs, tx, NULL);
    }

    DNSAnswerEntry *entry = NULL;
    TAILQ_FOREACH(entry, &tx->answer_list, next) {
        AppendAnswer(djs, tx, entry);
    }

    entry = NULL;
    TAILQ_FOREACH(entry, &tx->authority_list, next) {
        AppendAnswer(djs, tx, entry);
    }

    /* dns */
    json_object_set_new(js, "dns", djs);
    OutputJSON(js, aft, &aft->dns_cnt);
    json_object_del(js, "dns");
}

static TmEcode DnsJsonIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    AlertJsonThread *aft = (AlertJsonThread *)data;

    /* check if we have DNS state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_DNS_UDP && proto != ALPROTO_DNS_TCP) {
        SCLogDebug("proto not ALPROTO_DNS_UDP: %u", proto);
        goto end;
    }

    DNSState *dns_state = (DNSState *)AppLayerGetProtoStateFromPacket(p);
    if (dns_state == NULL) {
        SCLogDebug("no dns state, so no request logging");
        goto end;
    }

    uint64_t total_txs = AppLayerGetTxCnt(proto, dns_state);
    uint64_t tx_id = AppLayerTransactionGetLogId(p->flow);
    //int tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(proto, 0);
    //int tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(proto, 1);

    json_t *js = CreateJSONHeader(p, 1);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

#if QUERY
    if (PKT_IS_TOSERVER(p)) {
        DNSTransaction *tx = NULL;
        TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
            DNSQueryEntry *entry = NULL;
            TAILQ_FOREACH(entry, &tx->query_list, next) {
                LogQuery(aft, timebuf, srcip, dstip, sp, dp, tx, proto_s, entry);
            }
        }
    } else
#endif
    if ((PKT_IS_TOCLIENT(p))) {
        DNSTransaction *tx = NULL;
        for (; tx_id < total_txs; tx_id++)
        {
            tx = AppLayerGetTx(proto, dns_state, tx_id);
            if (tx == NULL)
                continue;

            DNSQueryEntry *query = NULL;
            TAILQ_FOREACH(query, &tx->query_list, next) {
                LogQuery(aft, js, /*timebuf, dstip, srcip, dp, sp, proto_s,*/ tx, query);
            }

            LogAnswers(aft, js, /*timebuf, srcip, dstip, sp, dp, proto_s,*/ tx);

            SCLogDebug("calling AppLayerTransactionUpdateLoggedId");
            AppLayerTransactionUpdateLogId(ALPROTO_DNS_UDP, p->flow);
        }
    }
    json_decref(js);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode OutputDnsLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_UDP(p)) && !(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    DnsJsonIPWrapper(tv, p, data, pq, postpq, AF_INET);

    SCReturnInt(TM_ECODE_OK);
}
#endif
