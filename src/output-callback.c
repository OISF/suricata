/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Common utilities for event callbacks.
 *
 */

#include "suricata-common.h"
#include "app-layer-ftp.h"
#include "app-layer-parser.h"
#include "output-callback.h"
#include "output-callback-http.h"
#include "output-json-alert.h"
#include "output-json-http.h"
#include "output-json-smb.h"
#include "output-json-smtp.h"
#include "app-layer-protos.h"
#include "rust.h"
#include "util-print.h"
#include "util-proto-name.h"

#define MODULE_NAME "OutputCallback"

static void EventFlowAddAppProto(const Flow *f, Common *common) {
    if (f->alproto) {
        common->app_proto = AppProtoToString(f->alproto);
    }
    if (f->alproto_ts && f->alproto_ts != f->alproto) {
        common->app_proto_ts = AppProtoToString(f->alproto_ts);
    }
    if (f->alproto_tc && f->alproto_tc != f->alproto) {
        common->app_proto_tc = AppProtoToString(f->alproto_tc);
    }
    if (f->alproto_orig != f->alproto && f->alproto_orig != ALPROTO_UNKNOWN) {
        common->app_proto_orig = AppProtoToString(f->alproto_orig);
    }
    if (f->alproto_expect != f->alproto && f->alproto_expect != ALPROTO_UNKNOWN) {
        common->app_proto_expected = AppProtoToString(f->alproto_expect);
    }
}

/* Add information common to all events. */
void EventAddCommonInfo(const Packet *p, enum OutputJsonLogDirection dir, Common *common,
                        JsonAddrInfo *addr) {

    /* First initialize the address info (5-tuple). */
    JsonAddrInfoInit(p, dir, addr);
    common->src_ip = addr->src_ip;
    common->dst_ip = addr->dst_ip;
    common->sp = addr->sp;
    common->dp = addr->dp;
    common->proto = addr->proto;

    /* Flow id. */
    const Flow *f = (const Flow *)p->flow;
    if (f != NULL) {
        int64_t flow_id = FlowGetId(f);
        common->flow_id = flow_id;
        if (f->parent_id) {
            common->parent_id = f->parent_id;
        }
    }

    /* Vlan */
    if (p->vlan_idx > 0) {
        common->vlan_id[0] = p->vlan_id[0];
        if (p->vlan_idx  > 1) {
            common->vlan_id[1] = p->vlan_id[1];
        }
    }

    /* Timestamp. */
    CreateIsoTimeString(p->ts, common->timestamp, sizeof(common->timestamp));

    /* Direction. */
    const char *direction = NULL;
    switch (dir) {
        case LOG_DIR_PACKET:
            if ((PKT_IS_TOCLIENT(p))) {
                direction = OUTPUT_DIR_PACKET_FLOW_TOCLIENT;
            } else {
                direction = OUTPUT_DIR_PACKET_FLOW_TOSERVER;
            }
            break;
        case LOG_DIR_FLOW:
        case LOG_DIR_FLOW_TOSERVER:
            direction = OUTPUT_DIR_PACKET_FLOW_TOSERVER;
            break;
        case LOG_DIR_FLOW_TOCLIENT:
            direction = OUTPUT_DIR_PACKET_FLOW_TOCLIENT;
            break;
        default:
            direction = "";
            break;
    }
    common->direction = direction;

    /* ICMP. */
    common->icmp_type = common->icmp_code = -1;
    common->icmp_response_code = common->icmp_response_type = -1;
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (p->icmpv4h) {
                common->icmp_type = p->icmpv4h->type;
                common->icmp_code = p->icmpv4h->code;
            }
            break;
        case IPPROTO_ICMPV6:
            if (p->icmpv6h) {
                common->icmp_type = p->icmpv6h->type;
                common->icmp_code = p->icmpv6h->code;
            }
            break;
    }

    /* App layer protocol, if any. */
    if (f != NULL) {
        EventFlowAddAppProto(f, common);
    }
}

/* Add common information from a flow object. */
void EventAddCommonInfoFromFlow(const Flow *f, Common *common, JsonAddrInfo *addr) {
    /* First initialize the address info (5-tuple). */
    JsonAddrInfoInitFlow(f, addr);
    common->src_ip = addr->src_ip;
    common->dst_ip = addr->dst_ip;
    common->sp = addr->sp;
    common->dp = addr->dp;
    common->proto = addr->proto;

    /* Flow id. */
    int64_t flow_id = FlowGetId(f);
    common->flow_id = flow_id;
    if (f->parent_id) {
        common->parent_id = f->parent_id;
    }

    /* Vlan. */
    if (f->vlan_idx > 0) {
        common->vlan_id[0] = f->vlan_id[0];
        if (f->vlan_idx > 1) {
            common->vlan_id[1] = f->vlan_id[1];
        }
    }

    SCTime_t ts = TimeGet();
    CreateIsoTimeString(ts, common->timestamp, sizeof(common->timestamp));

    common->icmp_type = common->icmp_code = -1;
    common->icmp_response_code = common->icmp_response_type = -1;
    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            common->icmp_type = f->icmp_s.type;
            common->icmp_code = f->icmp_s.code;
            if (f->tosrcpktcnt) {
                common->icmp_response_code = f->icmp_d.type;
                common->icmp_response_type = f->icmp_d.code;
            }
            break;
    }

    /* App layer protocol. */
    if (f->alproto) {
        EventFlowAddAppProto(f, common);
    }
}

/* Add app layer information (alert and fileinfo). */
void CallbackAddAppLayer(const Packet *p, const uint64_t tx_id, AppLayer *app_layer) {
    if (p->flow == NULL) {
        return;
    }

    const AppProto proto = FlowGetAppProtocol(p->flow);
    JsonBuilder *jb;

    switch (proto) {
        case ALPROTO_HTTP:
            ;
            const char *dir = NULL;
            if (PKT_IS_TOCLIENT(p)) {
                dir = LOG_HTTP_DIR_DOWNLOAD;
            } else {
                dir = LOG_HTTP_DIR_UPLOAD;
            }
            HttpInfo *http = SCCalloc(1, sizeof(HttpInfo));
            if (http && CallbackHttpAddMetadata(p->flow, tx_id, dir, http)) {
                app_layer->http = http;
            } else {
                SCFree(http);
            }
            break;
        case ALPROTO_SMB:
            ;
            jb = jb_new_object();
            if (EveSMBAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
                app_layer->nta = jb;
            } else {
                jb_free(jb);
            }
            break;
        case ALPROTO_FTPDATA:
            ;
            jb = jb_new_object();
            EveFTPDataAddMetadataDo(p->flow, jb);
            jb_close(jb);
            app_layer->nta = jb;
            break;
        case ALPROTO_SMTP:
            ;
            jb = jb_new_object();
            if (EveSMTPAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
                app_layer->nta = jb;
            } else {
                jb_free(jb);
            }
            break;
            /* TODO: Add email? */
        case ALPROTO_DNS:
            ;
            void *dns_state = (void *)FlowGetAppState(p->flow);
            if (dns_state) {
                void *tx_ptr = AppLayerParserGetTx(p->flow->proto, ALPROTO_DNS, dns_state, tx_id);
                if (tx_ptr) {
                    jb = jb_new_object();
                    AlertJsonDnsDo(tx_id, tx_ptr, jb);
                    jb_close(jb);
                    app_layer->nta = jb;
                }
            }
            break;
        case ALPROTO_RDP:
            ;
            void *rdp_state = (void *)FlowGetAppState(p->flow);
            if (rdp_state) {
                void *tx_ptr = AppLayerParserGetTx(p->flow->proto, ALPROTO_RDP, rdp_state, tx_id);
                if (tx_ptr) {
                    JsonBuilder *jb_tmp = jb_new_object();
                    if (rs_rdp_to_json(tx_ptr, jb_tmp)) {
                        /* We need to normalize to avoid logging twice the event_type. */
                        jb = jb_new_object();
                        size_t len = jb_len(jb_tmp) - 8;
                        char normalized[len + 1];

                        memset(normalized, 0, len + 1);
                        memcpy(normalized, jb_ptr(jb_tmp) + 8, len);
                        jb_set_formatted(jb, normalized);

                        app_layer->nta = jb;
                    }

                    jb_free(jb_tmp);
                }
            }
            break;
        default:
            break;
    }
}

/* Free any memory allocated for app layer information (alert and fileinfo). */
void CallbackCleanupAppLayer(const Packet *p, const uint64_t tx_id, AppLayer *app_layer) {
    if (p->flow == NULL) {
        return;
    }

    const AppProto proto = FlowGetAppProtocol(p->flow);
    switch (proto) {
        case ALPROTO_HTTP:
            if (app_layer->http) {
                SCFree(app_layer->http);
            }
            break;
        case ALPROTO_SMB:
        case ALPROTO_FTPDATA:
        case ALPROTO_SMTP:
        case ALPROTO_DNS:
        case ALPROTO_RDP:
            if (app_layer->nta) {
                jb_free(app_layer->nta);
            }
            break;
        default:
            break;
    }
}

static void OutputCallbackDeInitCtx(OutputCtx *output_ctx) {
    SCFree(output_ctx);
}


/**
 * \brief Create a new OutputCtx to be passed along to callbacks module.
 * \param conf The configuration node for this output.
 * \return An output context.
 */
static OutputInitResult OutputCallbackInitCtx(ConfNode *conf) {
    OutputInitResult result = { NULL, false };
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));

    if (unlikely(output_ctx == NULL)) {
        return result;
    }

    output_ctx->DeInit = OutputCallbackDeInitCtx;
    result.ctx = output_ctx;
    result.ok = true;

    return result;
}

void OutputCallbackRegister(void) {
    OutputRegisterModule(MODULE_NAME, "callback", OutputCallbackInitCtx);
}
