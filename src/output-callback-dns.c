/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate DNS events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback-dns.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackDnsLog"


#define LOG_QUERIES    BIT_U64(0)
#define LOG_ANSWERS    BIT_U64(1)

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

#define LOG_FORMAT_GROUPED     BIT_U64(60)
#define LOG_FORMAT_DETAILED    BIT_U64(61)

#define LOG_FORMAT_ALL (LOG_FORMAT_GROUPED|LOG_FORMAT_DETAILED)
#define LOG_ALL_RRTYPES (~(uint64_t)(LOG_QUERIES|LOG_ANSWERS|LOG_FORMAT_DETAILED|LOG_FORMAT_GROUPED))

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
    DNS_RRTYPE_URI,
    DNS_RRTYPE_MAX,
} DnsRRTypes;

static struct {
    const char *config_rrtype;
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

typedef struct CallbackDnsCtx {
    uint64_t flags; /** Store mode */
} CallbackDnsCtx;

typedef struct CallbackDnsLogThread {
    CallbackDnsCtx *dnslog_ctx;
} CallbackDnsLogThread;

static int CallbackDnsLoggerToServer(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                                     void *alstate, void *txptr, uint64_t tx_id) {
    CallbackDnsLogThread *td = (CallbackDnsLogThread *)thread_data;
    CallbackDnsCtx *dnslog_ctx = td->dnslog_ctx;

    if (!tv->callbacks->nta || unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
        return TM_ECODE_OK;
    }

    for (uint16_t i = 0; i < 0xffff; i++) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, NULL);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        if (!rs_dns_log_json_query(txptr, i, dnslog_ctx->flags, jb)) {
            jb_free(jb);
            break;
        }
        jb_close(jb);
        jb_close(jb);

        /* Invoke NTA callback. */
        tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "dns", f->tenant_uuid, f->user_ctx);

        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int CallbackDnsLoggerToClient(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                                     void *alstate, void *txptr, uint64_t tx_id) {
    CallbackDnsLogThread *td = (CallbackDnsLogThread *)thread_data;
    CallbackDnsCtx *dnslog_ctx = td->dnslog_ctx;

    if (!tv->callbacks->nta || unlikely(dnslog_ctx->flags & LOG_ANSWERS) == 0) {
        return TM_ECODE_OK;
    }

    if (rs_dns_do_log_answer(txptr, dnslog_ctx->flags)) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, NULL);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        rs_dns_log_json_answer(txptr, dnslog_ctx->flags, jb);
        jb_close(jb);
        jb_close(jb);

        /* Invoke NTA callback. */
        tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "dns", f->tenant_uuid, f->user_ctx);

        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode CallbackDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackDnsLogThread *aft = SCCalloc(1, sizeof(CallbackDnsLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for CallbackLogDNS.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->dnslog_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackDnsLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackDnsLogThread *aft = (CallbackDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    memset(aft, 0, sizeof(CallbackDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackDnsLogParseConfig(CallbackDnsCtx *dnslog_ctx, ConfNode *conf,
                                      const char *query_key, const char *answer_key,
                                      const char *answer_types_key)
{
    const char *query = ConfNodeLookupChildValue(conf, query_key);
    dnslog_ctx->flags |= LOG_QUERIES;
    if (query != NULL) {
        if (ConfValIsTrue(query)) {
            dnslog_ctx->flags |= LOG_QUERIES;
        } else {
            dnslog_ctx->flags &= ~LOG_QUERIES;
        }
    }

    const char *response = ConfNodeLookupChildValue(conf, answer_key);
    dnslog_ctx->flags |= LOG_ANSWERS;
    if (response != NULL) {
        if (ConfValIsTrue(response)) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        } else {
            dnslog_ctx->flags &= ~LOG_ANSWERS;
        }
    }

    ConfNode *custom;
    dnslog_ctx->flags |= LOG_ALL_RRTYPES;
    if ((custom = ConfNodeLookupChild(conf, answer_types_key)) != NULL) {
        dnslog_ctx->flags &= ~LOG_ALL_RRTYPES;
        ConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next) {
            if (field != NULL) {
                DnsRRTypes f;
                for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_MAX; f++) {
                    if (strcasecmp(dns_rrtype_fields[f].config_rrtype, field->val) == 0) {
                        dnslog_ctx->flags |= dns_rrtype_fields[f].flags;
                        break;
                    }
                }
            }
        }
    }
}

static void CallbackDnsLogInitFilters(CallbackDnsCtx *dnslog_ctx, ConfNode *conf) {
    /* DNS flags (enable everything by default). */
    dnslog_ctx->flags = ~0ULL;

    if (conf) {
        CallbackDnsLogParseConfig(dnslog_ctx, conf, "requests", "responses", "types");

        if (dnslog_ctx->flags & LOG_ANSWERS) {
            dnslog_ctx->flags |= LOG_FORMAT_ALL;
            /* TODO: add `detailed`, `grouped` format if needed. */
        }
    }
}

static void CallbackDnsLogDeInitCtxSub(OutputCtx *output_ctx) {
    CallbackDnsCtx *dnslog_ctx = (CallbackDnsCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };

    CallbackDnsCtx *dnslog_ctx = SCMalloc(sizeof(CallbackDnsCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }
    memset(dnslog_ctx, 0x00, sizeof(CallbackDnsCtx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = CallbackDnsLogDeInitCtxSub;

    CallbackDnsLogInitFilters(dnslog_ctx, conf);

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static int CallbackDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *alstate, void *txptr, uint64_t tx_id) {
    if (rs_dns_tx_is_request(txptr)) {
        return CallbackDnsLoggerToServer(tv, thread_data, p, f, alstate, txptr, tx_id);
    } else if (rs_dns_tx_is_response(txptr)) {
        return CallbackDnsLoggerToClient(tv, thread_data, p, f, alstate, txptr, tx_id);
    }
    return TM_ECODE_OK;
}

void CallbackDnsLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.dns",
                              CallbackDnsLogInitCtxSub, ALPROTO_DNS, CallbackDnsLogger,
                              CallbackDnsLogThreadInit, CallbackDnsLogThreadDeinit, NULL);
}
