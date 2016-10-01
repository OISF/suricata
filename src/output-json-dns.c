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
#include "util-mem.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"


#ifdef HAVE_LIBJANSSON

typedef struct OutputDoc_ {
    json_t *js;
    TAILQ_ENTRY(OutputDoc_) next;
} OutputDoc;

typedef TAILQ_HEAD(OutputDocList_, OutputDoc_) OutputDocList;

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

#define LOG_QUERIES    BIT_U64(0)
#define LOG_ANSWERS    BIT_U64(1)

#define LOG_TO_SERVER  LOG_QUERIES
#define LOG_TO_CLIENT  LOG_ANSWERS

/* Should split these into separate flags fields when we run out of bits below.
 */
#define LOG_A          BIT_U64(2)
#define LOG_NS         BIT_U64(3)
#define LOG_MD         BIT_U64(4)
#define LOG_MF         BIT_U64(5)
#define LOG_CNAME      BIT_U64(6)
#define LOG_SOA        BIT_U64(7)
#define LOG_MB         BIT_U64(8)
#define LOG_MG         BIT_U64(9)
#define LOG_MR         BIT_U64(10)
#define LOG_NULL       BIT_U64(11)
#define LOG_WKS        BIT_U64(12)
#define LOG_PTR        BIT_U64(13)
#define LOG_HINFO      BIT_U64(14)
#define LOG_MINFO      BIT_U64(15)
#define LOG_MX         BIT_U64(16)
#define LOG_TXT        BIT_U64(17)
#define LOG_RP         BIT_U64(18)
#define LOG_AFSDB      BIT_U64(19)
#define LOG_X25        BIT_U64(20)
#define LOG_ISDN       BIT_U64(21)
#define LOG_RT         BIT_U64(22)
#define LOG_NSAP       BIT_U64(23)
#define LOG_NSAPPTR    BIT_U64(24)
#define LOG_SIG        BIT_U64(25)
#define LOG_KEY        BIT_U64(26)
#define LOG_PX         BIT_U64(27)
#define LOG_GPOS       BIT_U64(28)
#define LOG_AAAA       BIT_U64(29)
#define LOG_LOC        BIT_U64(30)
#define LOG_NXT        BIT_U64(31)
#define LOG_SRV        BIT_U64(32)
#define LOG_ATMA       BIT_U64(33)
#define LOG_NAPTR      BIT_U64(34)
#define LOG_KX         BIT_U64(35)
#define LOG_CERT       BIT_U64(36)
#define LOG_A6         BIT_U64(37)
#define LOG_DNAME      BIT_U64(38)
#define LOG_OPT        BIT_U64(39)
#define LOG_APL        BIT_U64(40)
#define LOG_DS         BIT_U64(41)
#define LOG_SSHFP      BIT_U64(42)
#define LOG_IPSECKEY   BIT_U64(43)
#define LOG_RRSIG      BIT_U64(44)
#define LOG_NSEC       BIT_U64(45)
#define LOG_DNSKEY     BIT_U64(46)
#define LOG_DHCID      BIT_U64(47)
#define LOG_NSEC3      BIT_U64(48)
#define LOG_NSEC3PARAM BIT_U64(49)
#define LOG_TLSA       BIT_U64(50)
#define LOG_HIP        BIT_U64(51)
#define LOG_CDS        BIT_U64(52)
#define LOG_CDNSKEY    BIT_U64(53)
#define LOG_SPF        BIT_U64(54)
#define LOG_TKEY       BIT_U64(55)
#define LOG_TSIG       BIT_U64(56)
#define LOG_MAILA      BIT_U64(57)
#define LOG_ANY        BIT_U64(58)
#define LOG_URI        BIT_U64(59)

#define LOG_ALL_RRTYPES (~(uint64_t)(LOG_QUERIES|LOG_ANSWERS))

typedef enum {
    DNS_DISCRETE, /* the classic style of an event per question and answer */
    DNS_SPLIT,    /* one event per request, one event per response */
    DNS_UNIFIED   /* one event containing request and response */
} DnsOutputMode;


#define ALL_FILTERS     ~0UL

typedef enum {
    DNS_RRTYPE_A = 0,
    DNS_RRTYPE_NS,
    DNS_RRTYPE_MD,
    DNS_RRTYPE_MF,
    DNS_RRTYPE_CNAME,
    DNS_RRTYPE_SOA,
    DNS_RRTYPE_MB,
    DNS_RRTYPE_MG,
    DNS_RRTYPE_MR,
    DNS_RRTYPE_NULL,
    DNS_RRTYPE_WKS,
    DNS_RRTYPE_PTR,
    DNS_RRTYPE_HINFO,
    DNS_RRTYPE_MINFO,
    DNS_RRTYPE_MX,
    DNS_RRTYPE_TXT,
    DNS_RRTYPE_RP,
    DNS_RRTYPE_AFSDB,
    DNS_RRTYPE_X25,
    DNS_RRTYPE_ISDN,
    DNS_RRTYPE_RT,
    DNS_RRTYPE_NSAP,
    DNS_RRTYPE_NSAPPTR,
    DNS_RRTYPE_SIG,
    DNS_RRTYPE_KEY,
    DNS_RRTYPE_PX,
    DNS_RRTYPE_GPOS,
    DNS_RRTYPE_AAAA,
    DNS_RRTYPE_LOC,
    DNS_RRTYPE_NXT,
    DNS_RRTYPE_SRV,
    DNS_RRTYPE_ATMA,
    DNS_RRTYPE_NAPTR,
    DNS_RRTYPE_KX,
    DNS_RRTYPE_CERT,
    DNS_RRTYPE_A6,
    DNS_RRTYPE_DNAME,
    DNS_RRTYPE_OPT,
    DNS_RRTYPE_APL,
    DNS_RRTYPE_DS,
    DNS_RRTYPE_SSHFP,
    DNS_RRTYPE_IPSECKEY,
    DNS_RRTYPE_RRSIG,
    DNS_RRTYPE_NSEC,
    DNS_RRTYPE_DNSKEY,
    DNS_RRTYPE_DHCID,
    DNS_RRTYPE_NSEC3,
    DNS_RRTYPE_NSEC3PARAM,
    DNS_RRTYPE_TLSA,
    DNS_RRTYPE_HIP,
    DNS_RRTYPE_CDS,
    DNS_RRTYPE_CDNSKEY,
    DNS_RRTYPE_SPF,
    DNS_RRTYPE_TKEY,
    DNS_RRTYPE_TSIG,
    DNS_RRTYPE_MAILA,
    DNS_RRTYPE_ANY,
    DNS_RRTYPE_URI
} DnsRRTypes;

static struct {
    char *config_rrtype;
    uint64_t flags;
} dns_rrtype_fields[] = {
   { "a", LOG_A },
   { "ns", LOG_NS },
   { "md", LOG_MD },
   { "mf", LOG_MF },
   { "cname", LOG_CNAME },
   { "soa", LOG_SOA },
   { "mb", LOG_MB },
   { "mg", LOG_MG },
   { "mr", LOG_MR },
   { "null", LOG_NULL },
   { "wks", LOG_WKS },
   { "ptr", LOG_PTR },
   { "hinfo", LOG_HINFO },
   { "minfo", LOG_MINFO },
   { "mx", LOG_MX },
   { "txt", LOG_TXT },
   { "rp", LOG_RP },
   { "afsdb", LOG_AFSDB },
   { "x25", LOG_X25 },
   { "isdn", LOG_ISDN },
   { "rt", LOG_RT },
   { "nsap", LOG_NSAP },
   { "nsapptr", LOG_NSAPPTR },
   { "sig", LOG_SIG },
   { "key", LOG_KEY },
   { "px", LOG_PX },
   { "gpos", LOG_GPOS },
   { "aaaa", LOG_AAAA },
   { "loc", LOG_LOC },
   { "nxt", LOG_NXT },
   { "srv", LOG_SRV },
   { "atma", LOG_ATMA },
   { "naptr", LOG_NAPTR },
   { "kx", LOG_KX },
   { "cert", LOG_CERT },
   { "a6", LOG_A6 },
   { "dname", LOG_DNAME },
   { "opt", LOG_OPT },
   { "apl", LOG_APL },
   { "ds", LOG_DS },
   { "sshfp", LOG_SSHFP },
   { "ipseckey", LOG_IPSECKEY },
   { "rrsig", LOG_RRSIG },
   { "nsec", LOG_NSEC },
   { "dnskey", LOG_DNSKEY },
   { "dhcid", LOG_DHCID },
   { "nsec3", LOG_NSEC3 },
   { "nsec3param", LOG_NSEC3PARAM },
   { "tlsa", LOG_TLSA },
   { "hip", LOG_HIP },
   { "cds", LOG_CDS },
   { "cdnskey", LOG_CDNSKEY },
   { "spf", LOG_SPF },
   { "tkey", LOG_TKEY },
   { "tsig", LOG_TSIG },
   { "maila", LOG_MAILA },
   { "any", LOG_ANY },
   { "uri", LOG_URI }
};

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    DnsOutputMode mode;   /** output mode */
    uint64_t filter; /** filter bits */
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

static int DNSRRTypeEnabled(uint16_t type, uint64_t filters)
{
    if (likely(filters == ALL_FILTERS)) {
        return 1;
    }

    switch (type) {
        case DNS_RECORD_TYPE_A:
            return ((filters & LOG_A) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NS:
            return ((filters & LOG_NS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MD:
            return ((filters & LOG_MD) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MF:
            return ((filters & LOG_MF) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CNAME:
            return ((filters & LOG_CNAME) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SOA:
            return ((filters & LOG_SOA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MB:
            return ((filters & LOG_MB) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MG:
            return ((filters & LOG_MG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MR:
            return ((filters & LOG_MR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NULL:
            return ((filters & LOG_NULL) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_WKS:
            return ((filters & LOG_WKS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_PTR:
            return ((filters & LOG_PTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_HINFO:
            return ((filters & LOG_HINFO) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MINFO:
            return ((filters & LOG_MINFO) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MX:
            return ((filters & LOG_MX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TXT:
            return ((filters & LOG_TXT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RP:
            return ((filters & LOG_RP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_AFSDB:
            return ((filters & LOG_AFSDB) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_X25:
            return ((filters & LOG_X25) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ISDN:
            return ((filters & LOG_ISDN) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RT:
            return ((filters & LOG_RT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSAP:
            return ((filters & LOG_NSAP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSAPPTR:
            return ((filters & LOG_NSAPPTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SIG:
            return ((filters & LOG_SIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_KEY:
            return ((filters & LOG_KEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_PX:
            return ((filters & LOG_PX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_GPOS:
            return ((filters & LOG_GPOS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_AAAA:
            return ((filters & LOG_AAAA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_LOC:
            return ((filters & LOG_LOC) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NXT:
            return ((filters & LOG_NXT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SRV:
            return ((filters & LOG_SRV) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ATMA:
            return ((filters & LOG_ATMA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NAPTR:
            return ((filters & LOG_NAPTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_KX:
            return ((filters & LOG_KX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CERT:
            return ((filters & LOG_CERT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_A6:
            return ((filters & LOG_A6) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DNAME:
            return ((filters & LOG_DNAME) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_OPT:
            return ((filters & LOG_OPT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_APL:
            return ((filters & LOG_APL) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DS:
            return ((filters & LOG_DS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SSHFP:
            return ((filters & LOG_SSHFP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_IPSECKEY:
            return ((filters & LOG_IPSECKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RRSIG:
            return ((filters & LOG_RRSIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC:
            return ((filters & LOG_NSEC) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DNSKEY:
            return ((filters & LOG_DNSKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DHCID:
            return ((filters & LOG_DHCID) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC3:
            return ((filters & LOG_NSEC3) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC3PARAM:
            return ((filters & LOG_NSEC3PARAM) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TLSA:
            return ((filters & LOG_TLSA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_HIP:
            return ((filters & LOG_HIP) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CDS:
            return ((filters & LOG_CDS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CDNSKEY:
            return ((filters & LOG_CDNSKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SPF:
            return ((filters & LOG_SPF) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TKEY:
            return ((filters & LOG_TKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TSIG:
            return ((filters & LOG_TSIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MAILA:
            return ((filters & LOG_MAILA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_ANY:
            return ((filters & LOG_ANY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_URI:
            return ((filters & LOG_URI) != 0) ? 1 : 0;
        default:
            return 0;
    }
}

static json_t * QueryJson(DNSTransaction *tx, DNSQueryEntry *entry, DnsOutputMode style) __attribute__((nonnull));
static json_t * QueryJson(DNSTransaction *tx, DNSQueryEntry *entry, DnsOutputMode style)
{

    json_t *js = json_object();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    /* type */
    if (style != DNS_UNIFIED)
        json_object_set_new(js, "type", json_string("query"));


    /* query */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(js, "rrname", json_string(c));
        SCFree(c);
    }

    /* name */
    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(js, "rrtype", json_string(record));

    return js;
}

static json_t * AnswerJson(DNSTransaction *tx, DNSAnswerEntry *entry, DnsOutputMode style) __attribute__((nonnull));
static json_t * AnswerJson(DNSTransaction *tx, DNSAnswerEntry *entry, DnsOutputMode style)
{
   json_t *js = json_object();

    if (unlikely(js == NULL))
        return NULL;

    /* type */
    if (style == DNS_DISCRETE) {
        json_object_set_new(js, "type", json_string("answer"));
    }

    /* we are logging an answer RR */
    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
            if (c != NULL) {
                json_object_set_new(js, "rrname", json_string(c));
                SCFree(c);
            }
        }

        /* name */
        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(js, "rrtype", json_string(record));

        /* ttl */
        json_object_set_new(js, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "rdata", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "rdata", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(js, "rdata", json_string(""));
        } else if (entry->type == DNS_RECORD_TYPE_TXT || entry->type == DNS_RECORD_TYPE_CNAME ||
                   entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR ||
                   entry->type == DNS_RECORD_TYPE_NS || entry->type == DNS_RECORD_TYPE_SOA ) {
            if (entry->data_len != 0) {
                char buffer[256] = "";
                uint16_t copy_len = entry->data_len < (sizeof(buffer) - 1) ?
                    entry->data_len : sizeof(buffer) - 1;
                memcpy(buffer, ptr, copy_len);
                buffer[copy_len] = '\0';
                json_object_set_new(js, "rdata", json_string(buffer));
            } else {
                json_object_set_new(js, "rdata", json_string(""));
            }
        } else if (entry->type == DNS_RECORD_TYPE_SSHFP) {
            if (entry->data_len > 2) {
                /* get algo and type */
                uint8_t algo = *ptr;
                uint8_t fptype = *(ptr+1);

                /* turn fp raw buffer into a nice :-separate hex string */
                uint16_t fp_len = (entry->data_len - 2);
                uint8_t *dptr = ptr+2;

                /* c-string for ':' separated hex and trailing \0. */
                uint32_t output_len = fp_len * 3 + 1;
                char hexstring[output_len];
                memset(hexstring, 0x00, output_len);

                uint16_t x;
                for (x = 0; x < fp_len; x++) {
                    char one[4];
                    snprintf(one, sizeof(one), x == fp_len - 1 ? "%02x" : "%02x:", dptr[x]);
                    strlcat(hexstring, one, output_len);
                }

                /* wrap the whole thing in it's own structure */
                json_t *hjs = json_object();
                if (hjs != NULL) {
                    json_object_set_new(hjs, "fingerprint", json_string(hexstring));
                    json_object_set_new(hjs, "algo", json_integer(algo));
                    json_object_set_new(hjs, "type", json_integer(fptype));

                    json_object_set_new(js, "sshfp", hjs);
                }
            }
        }
    }

   return js;

}


static json_t *FailureJson(DNSTransaction *tx, DNSQueryEntry *entry, DnsOutputMode style) __attribute__((nonnull));
static json_t *FailureJson(DNSTransaction *tx, DNSQueryEntry *entry, DnsOutputMode style)
{
    json_t *js = json_object();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    /* type */
    if (style == DNS_DISCRETE) {
        json_object_set_new(js, "type", json_string("answer"));
    }

    /* no answer RRs, use query for rname */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(js, "rrname", json_string(c));
        SCFree(c);
    }

    return js;
}

/* Fills JSON object with DNS Transaction information */
void FillsDNSTransactionJSON(json_t * js,  DNSTransaction *tx, uint64_t flags, DnsOutputMode style)
{

    if (unlikely(js == NULL)) {
        return;
    }

    if (unlikely(tx == NULL)) {
        return;
    }

    if (tx->reply_lost) {
       json_object_set_new(js, "info", json_string("reply lost"));
    }

    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* tx_id */
    json_object_set_new(js, "tx_id", json_integer(tx->tx_id));

    if (tx->rcode) {

        if (likely(flags & LOG_QUERIES) != 0) {

            json_t *arrjs = json_array();

            DNSQueryEntry *query = NULL;
            TAILQ_FOREACH(query, &tx->query_list, next) {

               if (! likely(DNSRRTypeEnabled(query->type, flags))) {
                   continue;
               }

               json_t *entryjs = FailureJson(tx, query, style);
               if (entryjs) {
                   json_array_append_new(arrjs, entryjs);
               }
            }

            if (json_array_size(arrjs) > 0)
                json_object_set_new(js, "fail", arrjs);
        }

    }

   /* if answer */
   if (tx->replied) {
   

       if (likely(flags & LOG_ANSWERS) != 0) {
           if (TAILQ_EMPTY(&tx->answer_list)) {
               json_object_set_new(js, "info", json_string("empty answer"));
           }

           /* list of answers */
           json_t *ansarrjs = json_array();

           /* foreach answer */
           DNSAnswerEntry *entry = NULL;
           TAILQ_FOREACH(entry, &tx->answer_list, next) {

              if (! likely(DNSRRTypeEnabled(entry->type, flags)))
                  continue;

              json_t *entryjs = AnswerJson(tx, entry, style);
              if (entryjs) {
                  json_array_append_new(ansarrjs, entryjs);
              }
           }
           if (json_array_size(ansarrjs) > 0)
               json_object_set_new(js, "answers", ansarrjs);
       }

   }

   if (likely(flags & LOG_QUERIES) != 0) {
       /* list of queries */
       json_t *qarrjs = json_array();

       /* foreach query */
       DNSQueryEntry *entry = NULL;
       TAILQ_FOREACH(entry, &tx->query_list, next) {

           if (! likely(DNSRRTypeEnabled(entry->type, flags)))
	       continue;

           json_t *entryjs = QueryJson(tx, entry, style);
           if (entryjs) {
               json_array_append_new(qarrjs, entryjs);
           }
       }

       if (json_array_size(qarrjs) > 0)
           json_object_set_new(js, "queries",qarrjs);
    }

}

static OutputDoc * AllocOuputDoc(json_t *js) {

    if (js == NULL)
        return NULL;

    OutputDoc *doc = SCMalloc(sizeof(OutputDoc));

    if (unlikely(doc == NULL))
        return NULL;

    json_incref(js);
    doc->js = js;

    return doc;

}

static void FreeOuputDocList(OutputDocList * docs) {

    if (docs == NULL)
        return;

    OutputDoc *doc;
    TAILQ_FOREACH(doc, docs, next) {
        json_decref(doc->js);
        SCFree(doc);
    }

    SCFree(docs);
}

static OutputDocList *TransactionJSONList(json_t *js, DNSTransaction *tx, uint64_t flags, DnsOutputMode style) __attribute__((nonnull));

static OutputDocList *TransactionJSONList(json_t *js, DNSTransaction *tx, uint64_t flags, DnsOutputMode style)
{

    OutputDocList *docs = SCMalloc(sizeof(OutputDocList));
    if (unlikely(docs == NULL))
        return NULL;

    TAILQ_INIT(docs);

    json_t *tjs = json_object();
    if (unlikely(tjs == NULL)) {
        return docs;
    }

    /* Fill tjs with all parts of DNS transaction */
    FillsDNSTransactionJSON(tjs, tx, flags, style);

    /* Nothing to write */
    if (json_object_size(tjs) < 1 ) {
        json_decref(tjs);
        return docs;
    }

    /* Outputs a single event containing request and response */
    if (style == DNS_UNIFIED) {

        json_object_set_new(tjs, "type", json_string("unified"));
        /* dns node */
        json_object_set(js, "dns", tjs);

        /* Insert into docs list */
        OutputDoc *doc = AllocOuputDoc(js);
        if (doc != NULL) {
            TAILQ_INSERT_TAIL(docs, doc, next);
        }

        json_decref(tjs);
        return docs;
    }

    /* Not unified style */
    if (! tx->replied) {

        /* Queries output part */
        json_t *queries = json_object_get(tjs, "queries");

        if (queries && json_array_size(queries) >= 1 ) {
            json_object_set(js, "dns", json_array_get(queries, 0));

            /* Insert into docs list */
            OutputDoc *doc = AllocOuputDoc(js);
            if (doc != NULL) {
                TAILQ_INSERT_TAIL(docs, doc, next);
            }
        }

        json_decref(tjs);
        return docs;
    }

   /* Answers output part */
    json_t *answers = json_object_get(tjs, "answers");

    /* No answers to output */
    if (answers == NULL || json_array_size(answers) < 1 ) {
        json_decref(tjs);
        return docs;
    }

    /* Make a copy of event json for answers base */
    json_t * cloned = json_deep_copy(js);

    if (unlikely(cloned == NULL)) {
        json_decref(tjs);
        return docs;
    }

    /*  split: one event per request, one event per response */
    if (style == DNS_SPLIT && cloned) {
        json_t *ajs = json_object();
        if (unlikely(ajs == NULL)) {
            json_decref(tjs);
            return docs;
        }

        json_object_set(ajs, "answers", answers);

        json_t * rcode = json_object_get(tjs, "rcode");
        json_t * tx_id = json_object_get(tjs, "tx_id");

        if (rcode != NULL)
             json_object_set(ajs, "rcode", rcode);

        if (tx_id != NULL)
             json_object_set(ajs, "tx_id", tx_id);


        json_object_set(cloned, "dns", ajs);
        json_decref(tjs);

        /* Insert into docs list */
        OutputDoc *doc = AllocOuputDoc(cloned);
        if (doc != NULL) {
            TAILQ_INSERT_TAIL(docs, doc, next);
        }

        json_decref(ajs);
        return docs;
    }

    /* # discrete: the classic style of an event per question and answer */
    /* This is the historical log format */
    if (style == DNS_DISCRETE) {

        size_t sz = json_array_size(answers);
        json_t *value = NULL;
        json_t *copy = NULL;

        json_t * rcode = json_object_get(tjs, "rcode");
        json_t * tx_id = json_object_get(tjs, "tx_id");

        /* Log each answer separately */
        //json_array_foreach(answers, index, value) {
        for (size_t index = 0; index < sz; ++index) {

            value = json_array_get(answers, index);

            if ( ! value )
                continue;

            json_object_set(cloned, "dns", value);

            if (rcode != NULL)
                json_object_set_new(cloned, "rcode", rcode);

            if (tx_id != NULL)
                json_object_set_new(cloned, "tx_id", tx_id);


            /* Insert into docs list */
            OutputDoc *doc = AllocOuputDoc(cloned);
            if (doc != NULL) {
                TAILQ_INSERT_TAIL(docs, doc, next);
            }

            copy = json_deep_copy(js);
            cloned = copy;

        }
        json_decref(tjs);
        json_decref(copy);
    }

    return docs;
}

static void OutputLogTransactionJSON(LogFileCtx *file_ctx, MemBuffer *buffer, json_t *js, DNSTransaction *tx, uint64_t flags, DnsOutputMode style) __attribute__((nonnull));

/* Outputs to file log the DNS transaction with using configured output style */
static void OutputLogTransactionJSON(LogFileCtx *file_ctx, MemBuffer *buffer, json_t *js, DNSTransaction *tx, uint64_t flags, DnsOutputMode style) {

    OutputDocList * docs = TransactionJSONList(js, tx, flags, style);

    OutputDoc *doc = NULL;
    TAILQ_FOREACH(doc, docs, next) {

        /* reset */
        MemBufferReset(buffer);
        OutputJSONBuffer(doc->js, file_ctx, &buffer);
    }

    FreeOuputDocList(docs);
}

/* Makes the Json output for an alert */
void JsonDnsLogJSON(json_t * js,  DNSState *dns_state) {

    if (unlikely(js == NULL))
        return;

    if (unlikely(dns_state == NULL))
        return;


    FillsDNSTransactionJSON(js, dns_state->curr, ALL_FILTERS, DNS_UNIFIED);

}

/* Logs a DNS Event to Json to output log */
static void JsonDnsLogger(LogDnsLogThread *td, DNSTransaction *tx, const Packet *p, uint64_t filters)
{
    json_t *js = NULL;

    if (! td || ! td->dnslog_ctx)
       return;

    if (likely(td->dnslog_ctx->filter & filters) != 0) {
        js = CreateJSONHeader(p, 0, "dns");
        if (unlikely(js == NULL))
            return ;

        OutputLogTransactionJSON(td->dnslog_ctx->file_ctx,
                td->buffer, js, tx, td->dnslog_ctx->filter, td->dnslog_ctx->mode);

        json_decref(js);
    }

}

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id) __attribute__((nonnull));

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    JsonDnsLogger(
        (LogDnsLogThread *)thread_data,
        (DNSTransaction *) txptr,
        p,
        LOG_TO_SERVER
    );

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id) __attribute__((nonnull));
static int JsonDnsLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    JsonDnsLogger(
        (LogDnsLogThread *) thread_data,
        (DNSTransaction *) txptr,
        p,
        LOG_TO_CLIENT
    );

    SCReturnInt(TM_ECODE_OK);
}

#define OUTPUT_BUFFER_SIZE 65536
static TmEcode LogDnsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogDNS.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void LogDnsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void JsonDnsLogInitFilters(LogDnsFileCtx *dnslog_ctx, ConfNode *conf)
{
    dnslog_ctx->filter = ALL_FILTERS;
    dnslog_ctx->mode = DNS_DISCRETE;

    if (conf) {
        const char *query = ConfNodeLookupChildValue(conf, "query");
        if (query != NULL) {
            if (ConfValIsTrue(query)) {
                dnslog_ctx->filter |= LOG_QUERIES;
            } else {
                dnslog_ctx->filter &= ~LOG_QUERIES;
            }
        }
        const char *style = ConfNodeLookupChildValue(conf, "style");
        if (style != NULL) {
            if (strcasecmp(style, "unified")==0) {
                dnslog_ctx->mode = DNS_UNIFIED;
            } else if (strcasecmp(style, "split")==0) {
                dnslog_ctx->mode = DNS_SPLIT;
            } else if (strcasecmp(style, "discrete")==0) {
                dnslog_ctx->mode = DNS_DISCRETE;
            } else {
                SCLogError(SC_ERR_FATAL, "Invalid logging style for DNS Events.");
            }
        }
        const char *response = ConfNodeLookupChildValue(conf, "answer");
        if (response != NULL) {
            if (ConfValIsTrue(response)) {
                dnslog_ctx->filter |= LOG_ANSWERS;
            } else {
                dnslog_ctx->filter &= ~LOG_ANSWERS;
            }
        }
        ConfNode *custom;
        if ((custom = ConfNodeLookupChild(conf, "custom")) != NULL) {
            dnslog_ctx->filter &= ~LOG_ALL_RRTYPES;
            ConfNode *field;
            TAILQ_FOREACH(field, &custom->head, next)
            {
                if (field != NULL)
                {
                    DnsRRTypes f;
                    for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_TXT; f++)
                    {
                        if (strcasecmp(dns_rrtype_fields[f].config_rrtype,
                                       field->val) == 0)
                        {
                            dnslog_ctx->filter |= dns_rrtype_fields[f].flags;
                            break;
                        }
                    }
                }
            }
        }
    }
}

static OutputCtx *JsonDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = ojc->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}

#define DEFAULT_LOG_FILENAME "dns.json"
/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *JsonDnsLogInitCtx(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}


#define MODULE_NAME "JsonDnsLog"
void JsonDnsLogRegister (void)
{
    /* Logger for requests. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToServer,
        0, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Logger for replies. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToClient,
        1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for requests. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToServer, 0, 1, LogDnsLogThreadInit,
        LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for replies. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToClient, 1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit,
        NULL);
}

#else

void JsonDnsLogRegister (void)
{
    SCLogInfo("Can't register JSON output - JSON support was disabled during build.");
}

#endif

/************************************Unittests*******************************/

#ifdef UNITTESTS
#include "threads.h"

#include "flow-util.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "output-json-alert.h"

#define JSON_DNS_OUTPUT_UNITTEST_DUMP_ENABLE 0

#define JSON_DNS_OUTPUT_UNITTEST_DUMP(js)           \
{                                                   \
  if (JSON_DNS_OUTPUT_UNITTEST_DUMP_ENABLE) {       \
    printf("\n ---------------- \n");               \
    json_dumpf(js, stdout, JSON_INDENT(2));         \
    printf("\n ---------------- \n");               \
  }                                                 \
}


#define FAIL_IF_STR_DIFFERS(left, right)             \
{                                                    \
    const char * l = left;                           \
    const char * r = right;                          \
    FAIL_IF(l == NULL);                              \
    FAIL_IF(r == NULL);                              \
    int i = strncasecmp(l, r, strlen(l));            \
    FAIL_IF(i != 0 );                                \
}

#define JUMP_IF_STR_DIFFERS(left, right, label)      \
{                                                    \
    const char * l = left;                           \
    const char * r = right;                          \
    FAIL_IF(l == NULL);                              \
    FAIL_IF(r == NULL);                              \
    int i = strncasecmp(l, r, strlen(l));            \
    if (i != 0) goto label;                          \
}

/* google.com */
static uint8_t bufQuery[] = {
   0x10, 0x32, 0x01, 0x00, 0x00, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
   0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
   0x00, 0x10, 0x00, 0x01,
};

/* response google.com */
static uint8_t bufResponse[] = {
    0x10, 0x32,                             /* tx id */
    0x81, 0x80,                             /* flags: resp, recursion desired, recusion available */
    0x00, 0x01,                             /* 1 query */
    0x00, 0x01,                             /* 1 answer */
    0x00, 0x00, 0x00, 0x00,                 /* no auth rr, additional rr */
    /* query record */
    0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C,     /* name */
    0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,     /* name cont */
    0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
    /* answer */
    0xc0, 0x0c,                             /* ref to name in query above */
    0x00, 0x01, 0x00, 0x01,                 /* type a, class in */
    0x00, 0x01, 0x40, 0xef,                 /* ttl */
    0x00, 0x04,                             /* data len */
    0x01, 0x02, 0x03, 0x04 };               /* addr */

static DNSState *MakesDNSStateFromRequest(Flow *f, uint8_t *input, uint32_t input_len) {

    /* Create a DNS state */
    DNSState *dns_state = DNSStateAlloc();
    FAIL_IF(dns_state == NULL);

    /* Create App Layer Parser State */
    AppLayerParserState *pstate = AppLayerParserStateAlloc();
    FAIL_IF(pstate== NULL);

    /* Parses the DNS UDP Request */
    FAIL_IF ( DNSUDPRequestParse(f, dns_state, pstate, input, input_len, NULL) == -1 );

    AppLayerParserStateFree(pstate);

    return dns_state;
}

static DNSState *MakesDNSStateFromRequestAndResponse(Flow *f,
        uint8_t *request, uint32_t request_len, uint8_t *response, uint32_t response_len) {

    /* Create a DNS state */
    DNSState *dns_state = DNSStateAlloc();
    FAIL_IF(dns_state == NULL);

    /* Create App Layer Parser State */
    AppLayerParserState *pstate = AppLayerParserStateAlloc();
    FAIL_IF(pstate== NULL);

    /* Parses the DNS UDP Request */
    FAIL_IF ( DNSUDPRequestParse(f, dns_state, pstate, request, request_len, NULL) == -1 );
    FAIL_IF ( DNSUDPResponseParse(f, dns_state, pstate, response, response_len, NULL) == -1 );

    AppLayerParserStateFree(pstate);

    return dns_state;
}

/**
 *  \test Tests the JSON Output for a DNS Query with DNS_DISCRETE style
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int OutputJsonDnsQueryDiscreteTest01 (void)
{

    /* Create the file context */
    LogFileCtx *file_ctx = LogFileNewCtx();
    FAIL_IF(file_ctx == NULL);

    /* Create memory butffer */
    MemBuffer * buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    FAIL_IF(buffer == NULL);

    /* Create DNS file context */
    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    FAIL_IF(dnslog_ctx == NULL);

    /* Configure DNS file context configuration options */
    dnslog_ctx->mode = DNS_DISCRETE;
    dnslog_ctx->filter &= LOG_ALL_RRTYPES;

    /* Create a DNS packet for tests */
    Packet *p = UTHBuildPacketReal(bufQuery, sizeof(bufQuery), IPPROTO_UDP,
                          "192.168.1.5", "192.168.1.1", 41424, 53);
    FAIL_IF(p == NULL);

    /* Create flow */
    Flow f;
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_DNS;

    /* Create a DNS state from the flow and query */
    DNSState *dns_state = MakesDNSStateFromRequest(&f, bufQuery, sizeof(bufQuery));

    /* Create a JSON object for output */
    json_t *js = CreateJSONHeader(p, 0, "dns");
    FAIL_IF(js == NULL);

    FAIL_IF_STR_DIFFERS("dns",      json_string_value( json_object_get(js, "event_type") ));

    /* Outputs JSON */


    OutputDocList * docs = TransactionJSONList(js,  TAILQ_FIRST(&dns_state->tx_list) , ALL_FILTERS, DNS_DISCRETE);
    FAIL_IF(docs == NULL);

    OutputDoc *doc = TAILQ_FIRST(docs);
    FAIL_IF(doc == NULL);

    json_t *tjs = doc->js;
    FAIL_IF(tjs == NULL);

    JSON_DNS_OUTPUT_UNITTEST_DUMP(js);

    /* Check output format */
    json_t *dns = json_object_get(js, "dns");
    FAIL_IF (dns == NULL);

    /* Check string values */
    FAIL_IF_STR_DIFFERS("query",      json_string_value( json_object_get(dns, "type") ));
    FAIL_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(dns, "rrname") ));
    FAIL_IF_STR_DIFFERS("TXT",        json_string_value( json_object_get(dns, "rrtype")));

    /* Free some stuff */
    json_decref(tjs);
    json_decref(js);
    FreeOuputDocList(docs);
    DNSStateFree(dns_state);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    SCFree(dnslog_ctx);
    MemBufferFree(buffer);
    LogFileFreeCtx(file_ctx);

    PASS;
}

/**
 *  \test Tests the JSON Output for a DNS Response with DNS_UNIFIED style
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int OutputJsonDnsResponseUnifiedTest02 (void)
{

    /* Create the file context */
    LogFileCtx *file_ctx = LogFileNewCtx();
    FAIL_IF(file_ctx == NULL);

    /* Create memory butffer */
    MemBuffer * buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    FAIL_IF(buffer == NULL);

    /* Create DNS file context */
    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    FAIL_IF(dnslog_ctx == NULL);

    /* Configure DNS file context configuration options */
    dnslog_ctx->mode = DNS_UNIFIED;
    dnslog_ctx->filter &= LOG_ALL_RRTYPES;

    /* Create a DNS packets for tests */
    Packet *p1 = NULL, *p2 = NULL;
    p1 = UTHBuildPacketReal(bufQuery, sizeof(bufQuery), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1", 41424, 53);

    p2 = UTHBuildPacketReal(bufResponse, sizeof(bufResponse), IPPROTO_UDP,
                           "192.168.1.1", "192.168.1.5", 53, 41424);

    FAIL_IF(p1 == NULL);
    FAIL_IF(p2 == NULL);

    /* Create flow */
    Flow f;
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->pcap_cnt = 2;

    /* Create a DNS state from the flow and response */
    DNSState *dns_state =  MakesDNSStateFromRequestAndResponse(&f,
            bufQuery, sizeof(bufQuery), bufResponse, sizeof(bufResponse));

    /* Create a JSON object for output */
    json_t *js = CreateJSONHeader(p2, 0, "dns");
    FAIL_IF(js == NULL);

    /* Outputs JSON */
    OutputDocList * docs = TransactionJSONList(js,  TAILQ_FIRST(&dns_state->tx_list) , ALL_FILTERS, DNS_UNIFIED);
    FAIL_IF(docs == NULL);

    OutputDoc *doc = TAILQ_FIRST(docs);
    FAIL_IF(doc == NULL);

    json_t *tjs = doc->js;
    FAIL_IF(tjs == NULL);
    JSON_DNS_OUTPUT_UNITTEST_DUMP(tjs);
    FAIL_IF_STR_DIFFERS("dns",      json_string_value( json_object_get(js, "event_type") ));

    json_t *dns = json_object_get(js, "dns");
    FAIL_IF (dns == NULL);

    /* "type": "unified", */
    FAIL_IF_STR_DIFFERS("unified",      json_string_value( json_object_get(dns, "type") ));
    FAIL_IF_STR_DIFFERS("NOERROR",    json_string_value( json_object_get(dns, "rcode") ));
    FAIL_IF( 4146 !=                 json_integer_value( json_object_get(dns, "tx_id")));

    /* Check queries and answers arrays */
    json_t *queries = json_object_get(dns, "queries");
    json_t *answers = json_object_get(dns, "answers");

    FAIL_IF(queries == NULL);
    FAIL_IF(answers == NULL);
    FAIL_IF (! json_is_array(queries));
    FAIL_IF (! json_is_array(answers));
    FAIL_IF(json_array_size(queries) != 1);
    FAIL_IF(json_array_size(answers) != 1);

    json_t *query = json_array_get(queries, 0);
    json_t *answer = json_array_get(answers, 0);

    FAIL_IF(query == NULL);
    FAIL_IF(answer == NULL);

	JSON_DNS_OUTPUT_UNITTEST_DUMP(js);

/*
  {
	"rrname": "google.com",
	"rrtype": "TXT",
	"tx_id": 4146
  }

*/

    /* Check string values */
    FAIL_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(query, "rrname") ));
    FAIL_IF_STR_DIFFERS("TXT",        json_string_value( json_object_get(query, "rrtype")));

/*
 {
    "rrtype": "A",
    "rrname": "google.com",
    "ttl": 16623,
    "rdata": "1.2.3.4"
  }
*/

    /* Check string values */
    FAIL_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(answer, "rrname") ));
    FAIL_IF_STR_DIFFERS("A",          json_string_value( json_object_get(answer, "rrtype")));
    FAIL_IF_STR_DIFFERS("1.2.3.4",    json_string_value( json_object_get(answer, "rdata")));
    FAIL_IF( 16623 !=                json_integer_value( json_object_get(answer, "ttl")));

    /* Free some stuff */
    json_decref(tjs);
    json_decref(js);
    DNSStateFree(dns_state);
    FreeOuputDocList(docs);
    FLOW_DESTROY(&f);
    UTHFreePacket(p2);
    UTHFreePacket(p1);
    SCFree(dnslog_ctx);
    MemBufferFree(buffer);
    LogFileFreeCtx(file_ctx);

    PASS;
}
/**
 *  \test Tests the JSON Output for a DNS Alert with DNS_UNIFIED style
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int OutputJsonDnsResponseUnifiedAlertTest03 (void)
{

    int result = 0;
    Flow f;
    DNSState *dns_state = NULL;
    Packet *p1 = NULL, *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p1 = UTHBuildPacketReal(bufQuery, sizeof(bufQuery), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);
    p2 = UTHBuildPacketReal(bufResponse, sizeof(bufResponse), IPPROTO_UDP,
                           "192.168.1.1", "192.168.5.1",
                           53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_DNS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->pcap_cnt = 2;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = DEFAULT_MPM;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.com\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_query; content:\"google.net\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(&tv, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, bufQuery, sizeof(bufQuery));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    dns_state = f.alstate;
    if (dns_state == NULL) {
        printf("no dns state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("(p1) sig 1 didn't alert, but it should have: ");
        goto end;
    }
    if (PacketAlertCheck(p1, 2)) {
        printf("(p1) sig 2 did alert, but it should not have: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(&tv, alp_tctx, &f, ALPROTO_DNS, STREAM_TOCLIENT, bufResponse, sizeof(bufResponse));
    if (r != 0) {
        printf("toserver client 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("(p2) sig 1 alerted, but it should not have: ");
        goto end;
    }
    if (PacketAlertCheck(p2, 2)) {
        printf("(p2) sig 2 alerted, but it should not have: ");
        goto end;
    }

    json_t *js = CreateJSONHeader((Packet *)p2, 0, "alert");
    if (unlikely(js == NULL)) {
        goto end;
    }

    AlertJsonDns(&f, js);

    JSON_DNS_OUTPUT_UNITTEST_DUMP(js);

    JUMP_IF_STR_DIFFERS("alert",      json_string_value( json_object_get(js, "event_type") ), end);

    json_t *dns = json_object_get(js, "dns");
    FAIL_IF (dns == NULL);
    JUMP_IF_STR_DIFFERS("NOERROR",    json_string_value( json_object_get(dns, "rcode")), end);
    FAIL_IF( 4146 !=                 json_integer_value( json_object_get(dns, "tx_id")));

    /* Check queries and answers arrays */
    json_t *queries = json_object_get(dns, "queries");
    json_t *answers = json_object_get(dns, "answers");

    FAIL_IF(queries == NULL);
    FAIL_IF(answers == NULL);
    FAIL_IF (! json_is_array(queries));
    FAIL_IF (! json_is_array(answers));
    FAIL_IF(json_array_size(queries) != 1);
    FAIL_IF(json_array_size(answers) != 1);

    json_t *query = json_array_get(queries, 0);
    json_t *answer = json_array_get(answers, 0);

    FAIL_IF(query == NULL);
    FAIL_IF(answer == NULL);


/*
  {
	"rrname": "google.com",
	"rrtype": "TXT",
	"tx_id": 4146
  }

*/

    /* Check string values */
    JUMP_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(query, "rrname")), end);
    JUMP_IF_STR_DIFFERS("TXT",        json_string_value( json_object_get(query, "rrtype")), end);

/*
 {
    "rrtype": "A",
    "rrname": "google.com",
    "ttl": 16623,
    "rdata": "1.2.3.4"
  }
*/

    /* Check string values */
    JUMP_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(answer, "rrname")), end);
    JUMP_IF_STR_DIFFERS("A",          json_string_value( json_object_get(answer, "rrtype")), end);
    JUMP_IF_STR_DIFFERS("1.2.3.4",    json_string_value( json_object_get(answer, "rdata")), end);
    FAIL_IF( 16623 !=                json_integer_value( json_object_get(answer, "ttl")));


    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    json_decref(js);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    return result;

}
/**
 *  \test Tests the JSON Output for a DNS Query with DNS_STYLE style
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int OutputJsonDnsResponseSplitTest04 (void)
{
    /* Create the file context */
    LogFileCtx *file_ctx = LogFileNewCtx();
    FAIL_IF(file_ctx == NULL);

    /* Create memory butffer */
    MemBuffer * buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    FAIL_IF(buffer == NULL);

    /* Create DNS file context */
    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    FAIL_IF(dnslog_ctx == NULL);

    /* Configure DNS file context configuration options */
    dnslog_ctx->mode = DNS_UNIFIED;
    dnslog_ctx->filter &= LOG_ALL_RRTYPES;

    /* Create a DNS packets for tests */
    Packet *p1 = NULL, *p2 = NULL;
    p1 = UTHBuildPacketReal(bufQuery, sizeof(bufQuery), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1", 41424, 53);

    p2 = UTHBuildPacketReal(bufResponse, sizeof(bufResponse), IPPROTO_UDP,
                           "192.168.1.1", "192.168.1.5", 53, 41424);

    FAIL_IF(p1 == NULL);
    FAIL_IF(p2 == NULL);

    /* Create flow */
    Flow f;
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->pcap_cnt = 2;

    /* Create a DNS state from the flow and response */
    DNSState *dns_state =  MakesDNSStateFromRequest(&f, bufQuery, sizeof(bufQuery));

    /* Create a JSON object for output */
    json_t *js = CreateJSONHeader(p2, 0, "dns");
    FAIL_IF(js == NULL);


    /* Outputs JSON */
    OutputDocList * docs = TransactionJSONList(js,  TAILQ_FIRST(&dns_state->tx_list) , ALL_FILTERS, DNS_SPLIT);
    FAIL_IF(docs == NULL);

    OutputDoc *doc = TAILQ_FIRST(docs);
    FAIL_IF(doc == NULL);

    json_t *qjs = doc->js;
    FAIL_IF(qjs == NULL);

    FAIL_IF_STR_DIFFERS("dns",      json_string_value( json_object_get(qjs, "event_type") ));



    json_t *dns = json_object_get(qjs, "dns");
    FAIL_IF (dns == NULL);

    JSON_DNS_OUTPUT_UNITTEST_DUMP(qjs);

/*
  {
	"rrname": "google.com",
	"rrtype": "TXT",
	"tx_id": 4146
  }

*/

    /* Check string values */
    FAIL_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(dns, "rrname") ));
    FAIL_IF_STR_DIFFERS("TXT",        json_string_value( json_object_get(dns, "rrtype")));

    DNSStateFree(dns_state);
    FreeOuputDocList(docs);
    json_decref(js);

    /* Answer */

/*
 {
    "rrtype": "A",
    "rrname": "google.com",
    "ttl": 16623,
    "rdata": "1.2.3.4"
  }
*/


    /* Create a DNS state from the flow and response */
    dns_state =  MakesDNSStateFromRequestAndResponse(&f,
            bufQuery, sizeof(bufQuery), bufResponse, sizeof(bufResponse));

    /* Create a JSON object for output */
    js = CreateJSONHeader(p2, 0, "dns");
    FAIL_IF(js == NULL);

    /* Outputs JSON */
    docs = TransactionJSONList(js,  TAILQ_FIRST(&dns_state->tx_list) , ALL_FILTERS, DNS_SPLIT);
    FAIL_IF(docs == NULL);

    doc = TAILQ_FIRST(docs);
    FAIL_IF(doc == NULL);

    json_t *ajs = doc->js;
    FAIL_IF(ajs == NULL);

    JSON_DNS_OUTPUT_UNITTEST_DUMP(ajs);
    FAIL_IF_STR_DIFFERS("dns",      json_string_value( json_object_get(ajs, "event_type") ));

    dns = json_object_get(ajs, "dns");
    FAIL_IF (dns == NULL);

    json_t *answers = json_object_get(dns, "answers");

    FAIL_IF(answers == NULL);
    FAIL_IF (! json_is_array(answers));
    FAIL_IF(json_array_size(answers) != 1);

    json_t *answer = json_array_get(answers, 0);
    FAIL_IF(answer == NULL);

    /* Check string values */
    FAIL_IF_STR_DIFFERS("google.com", json_string_value( json_object_get(answer, "rrname") ));
    FAIL_IF_STR_DIFFERS("A",          json_string_value( json_object_get(answer, "rrtype")));
    FAIL_IF_STR_DIFFERS("1.2.3.4",    json_string_value( json_object_get(answer, "rdata")));
    FAIL_IF( 16623 !=                json_integer_value( json_object_get(answer, "ttl")));

    FAIL_IF_STR_DIFFERS("NOERROR",    json_string_value( json_object_get(dns, "rcode") ));
    FAIL_IF( 4146 !=                 json_integer_value( json_object_get(dns, "tx_id")));

    /* Free some stuff */
    json_decref(qjs);
    json_decref(ajs);
    json_decref(js);
    FreeOuputDocList(docs);
    DNSStateFree(dns_state);
    FLOW_DESTROY(&f);
    UTHFreePacket(p2);
    UTHFreePacket(p1);
    SCFree(dnslog_ctx);
    MemBufferFree(buffer);
    LogFileFreeCtx(file_ctx);

    PASS;

}


/**
 *  \brief   Function to register DNS output JSON Tests
 */
void OutputJsonDnsRegisterTests (void)
{
    UtRegisterTest("OutputJsonDnsQueryDiscreteTest01 -- Tests discrete query", OutputJsonDnsQueryDiscreteTest01);
    UtRegisterTest("OutputJsonDnsResponseUnifiedTest02 -- Tests unified response", OutputJsonDnsResponseUnifiedTest02);
    UtRegisterTest("OutputJsonDnsResponseUnifiedAlertTest03 -- Tests unified response", OutputJsonDnsResponseUnifiedAlertTest03);
    UtRegisterTest("OutputJsonDnsResponseSplitTest04 -- Tests split style", OutputJsonDnsResponseSplitTest04);

}
#endif /* UNITTESTS */
