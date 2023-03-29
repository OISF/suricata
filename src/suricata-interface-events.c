/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  API to convert events to JSON.
 *
 *  Notice: all these methods transfer ownership of the generated JSON string to the caller. It is
 *          up to the caller to free the received string.
 */

#include "suricata-interface-events.h"

#include "rust.h"
#include "util-debug.h"

/* Log common information. */
static void logCommon(JsonBuilder *jb, Common *common) {
    jb_set_string(jb, "timestamp", common->timestamp);
    jb_set_string(jb, "src_ip", common->src_ip);
    jb_set_uint(jb, "src_port", common->sp);
    jb_set_string(jb, "dest_ip", common->dst_ip);
    jb_set_uint(jb, "dest_port", common->dp);
    jb_set_string(jb, "proto", common->proto);
    jb_set_string(jb, "direction", common->direction);

    jb_set_uint(jb, "flow_id", common->flow_id);

    if (common->vlan_id[0]) {
        jb_open_array(jb, "vlan");
        jb_append_uint(jb, common->vlan_id[0]);
        if (common->vlan_id[1]) {
            jb_append_uint(jb, common->vlan_id[1]);
        }
        jb_close(jb);
    }

    if (common->parent_id) {
        jb_set_uint(jb, "parent_id", common->parent_id);
    }

    if (common->app_proto) {
        jb_set_string(jb, "app_proto", common->app_proto);
    }

    if (common->app_proto_ts) {
        jb_set_string(jb, "app_proto_ts", common->app_proto_ts);
    }

    if (common->app_proto_tc) {
        jb_set_string(jb, "app_proto_tc", common->app_proto_tc);
    }

    if (common->app_proto_orig) {
        jb_set_string(jb, "app_proto_orig", common->app_proto_orig);
    }

    if (common->app_proto_expected) {
        jb_set_string(jb, "app_proto_expected", common->app_proto_expected);
    }

    if (common->icmp_type != -1) {
        jb_set_uint(jb, "icmp_type", common->icmp_type);
    }

    if (common->icmp_code != -1) {
        jb_set_uint(jb, "icmp_code", common->icmp_code);
    }

    if (common->icmp_response_type != -1) {
        jb_set_uint(jb, "response_icmp_type", common->icmp_response_type);
    }

    if (common->icmp_response_code != -1) {
        jb_set_uint(jb, "response_icmp_code", common->icmp_response_code);
    }

    if (common->xff) {
        jb_set_string(jb, "xff", common->xff);
    }
}

/* Log common HTTP info shared across events (alert, HTTP...). */
static void logHttpInfoCommon(JsonBuilder *jb, HttpInfo *http_info) {
    if (http_info->hostname) {
        jb_set_string_from_bytes(jb, "hostname", bstr_ptr(http_info->hostname),
                                 bstr_len(http_info->hostname));
    }

    if (http_info->http_method) {
        jb_set_string_from_bytes(jb, "http_method", bstr_ptr(http_info->http_method),
                                 bstr_len(http_info->http_method));
    }

    if (http_info->protocol) {
        jb_set_string_from_bytes(jb, "protocol", bstr_ptr(http_info->protocol),
                                 bstr_len(http_info->protocol));
    }

    if (http_info->http_port >= 0) {
        jb_set_uint(jb, "http_port", http_info->http_port);
    }

    if (http_info->uri) {
        jb_set_string_from_bytes(jb, "url", bstr_ptr(http_info->uri),
                                 bstr_len(http_info->uri));
    }

    if (http_info->user_agent) {
        jb_set_string_from_bytes(jb, "http_user_agent", bstr_ptr(http_info->user_agent),
                                 bstr_len(http_info->user_agent));
    }

    if (http_info->xff) {
        jb_set_string_from_bytes(jb, "xff", bstr_ptr(http_info->xff),
                                 bstr_len(http_info->xff));
    }

    if (http_info->content_type) {
        size_t len = bstr_len(http_info->content_type);
        char content_type[len + 1];

        memcpy(content_type, bstr_ptr(http_info->content_type), len);
        content_type[len] = 0;

        char *p = strchr(content_type, ';');
        if (p != NULL) {
            *p = '\0';
        }

        jb_set_string(jb, "http_content_type", content_type);
    }

    if (http_info->content_range_raw) {
        jb_open_object(jb, "content_range");
        jb_set_string_from_bytes(jb, "raw", bstr_ptr(http_info->content_range_raw),
                                 bstr_len(http_info->content_range_raw));
        if (http_info->content_range_start >= 0) {
            jb_set_uint(jb, "start", http_info->content_range_start);
        }
        if (http_info->content_range_end >= 0) {
            jb_set_uint(jb, "end", http_info->content_range_end);
        }
        if (http_info->content_range_size >= 0) {
            jb_set_uint(jb, "size", http_info->content_range_size);
        }
        jb_close(jb);
    }

    if (http_info->redirect) {
        jb_set_string_from_bytes(jb, "redirect", bstr_ptr(http_info->redirect),
                                 bstr_len(http_info->redirect));
    }

    if (http_info->referer) {
        jb_set_string_from_bytes(jb, "http_refer", bstr_ptr(http_info->referer),
                                 bstr_len(http_info->referer));
    }

    if (http_info->status) {
        jb_set_uint(jb, "status", http_info->status);
    }

    if (http_info->direction) {
        jb_set_string(jb, "direction", http_info->direction);
    }

    jb_set_uint(jb, "length", http_info->response_len);
}

/* Log common flow info shared across events. */
static void logFlowCommon(JsonBuilder *jb, FlowInfo *flow) {
    jb_open_object(jb, "flow");

    jb_set_uint(jb, "pkts_toserver", flow->pkts_toserver);
    jb_set_uint(jb, "pkts_toclient", flow->pkts_toclient);
    jb_set_uint(jb, "bytes_toserver", flow->bytes_toserver);
    jb_set_uint(jb, "bytes_toclient", flow->bytes_toclient);
    jb_set_string(jb, "start", flow->start);
}

/* Log extended flow info shared across events. */
static void logFlowExtended(JsonBuilder *jb, FlowInfo *flow, const char *proto) {
    if (flow->dev) {
        jb_set_string(jb, "in_iface", flow->dev);
    }

    if (flow->emergency) {
        jb_set_bool(jb, "emergency", flow->emergency);
    }

    jb_set_string(jb, "end", flow->end);
    jb_set_uint(jb, "age", flow->age);
    jb_set_string(jb, "state", flow->state);
    jb_set_string(jb, "reason", flow->reason);
    jb_set_bool(jb, "alerted", flow->alerted);
    jb_close(jb);

    /* TCP flags. */
    if (strncmp(proto, "TCP", 3) == 0) {
        jb_open_object(jb, "tcp");
        jb_set_string(jb, "tcp_flags", flow->tcp.tcp_flags);
        jb_set_string(jb, "tcp_flags_ts", flow->tcp.tcp_flags_ts);
        jb_set_string(jb, "tcp_flags_tc", flow->tcp.tcp_flags_tc);

        if (flow->tcp.syn) {
            jb_set_bool(jb, "syn", flow->tcp.syn);
        }
        if (flow->tcp.fin) {
            jb_set_bool(jb, "fin", flow->tcp.fin);
        }
        if (flow->tcp.rst) {
            jb_set_bool(jb, "rst", flow->tcp.rst);
        }
        if (flow->tcp.psh) {
            jb_set_bool(jb, "psh", flow->tcp.psh);
        }
        if (flow->tcp.ack) {
            jb_set_bool(jb, "ack", flow->tcp.ack);
        }
        if (flow->tcp.urg) {
            jb_set_bool(jb, "urg", flow->tcp.urg);
        }
        if (flow->tcp.ecn) {
            jb_set_bool(jb, "ecn", flow->tcp.ecn);
        }
        if (flow->tcp.cwr) {
            jb_set_bool(jb, "cwr", flow->tcp.cwr);
        }

        if (flow->tcp.state) {
            jb_set_string(jb, "state", flow->tcp.state);
        }

        jb_close(jb);
    }
}

/* Log common alert info shared across events. */
static void logAlertCommon(JsonBuilder *jb, Alert *alert) {
    jb_open_object(jb, "alert");

    jb_set_string(jb, "action", alert->action);
    jb_set_uint(jb, "gid", alert->gid);
    jb_set_uint(jb, "signature_id", alert->sid);
    jb_set_uint(jb, "rev", alert->rev);
    jb_set_string(jb, "signature", alert->msg);
    jb_set_string(jb, "category", alert->category);
    jb_set_uint(jb, "severity", alert->severity);

    if (alert->metadata) {
        jb_set_string(jb, "metadata", alert->metadata);
    }

    jb_close(jb);
}

/* Convert an Alert event to JSON. */
void suricata_alert_to_json(AlertEvent *event, char **data, size_t *len) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "alert");

    /* Set Transaction id for correlation with other events. */
    if (event->alert.tx_id != -1) {
        jb_set_uint(jb, "tx_id", event->alert.tx_id);
    }

    /* Log alert specific info. */
    logAlertCommon(jb, &event->alert);

    /* Log flow info only if we have seen some traffic. */
    if (event->flow.bytes_toserver || event->flow.bytes_toclient) {
        logFlowCommon(jb, &event->flow);
        jb_close(jb);
    }

    /* Handle app layer record if present. */
    if (event->common.app_proto && strcmp(event->common.app_proto, "http") == 0 &&
        event->app_layer.http) {
        jb_open_object(jb, "http");
        logHttpInfoCommon(jb, event->app_layer.http);
        jb_close(jb);
    } else if (event->app_layer.nta) {
        jb_set_object(jb, event->common.app_proto, (JsonBuilder *)event->app_layer.nta);
    }

    /* Copy JSON record and pass it to the caller. */
    jb_close(jb);
    *len = jb_len(jb);
    *data = malloc(*len * sizeof(char));
    if (*data == NULL) {
        SCLogError("Failed allocating buffer to convert event to JSON");
        return;
    }

    memcpy(*data, jb_ptr(jb), *len);
    jb_free(jb);
}

/* Convert a Fileinfo event to JSON. */
void suricata_fileinfo_to_json(FileinfoEvent *event, char **data, size_t *len) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "fileinfo");

    /* Log alert specific info. */
    jb_open_object(jb, "fileinfo");
    jb_set_string_from_bytes(jb, "filename", event->fileinfo.filename,
                             event->fileinfo.filename_len);

    jb_open_array(jb, "sid");
    for (uint32_t i = 0; event->fileinfo.sids != NULL && i < event->fileinfo.sid_cnt; i++) {
        jb_append_uint(jb, event->fileinfo.sids[i]);
    }
    jb_close(jb);

    if (event->fileinfo.magic) {
        jb_set_string(jb, "magic", event->fileinfo.magic);
    }

    jb_set_bool(jb, "gaps", event->fileinfo.gaps);
    jb_set_string(jb, "state", event->fileinfo.state);
    jb_set_uint(jb, "tx_id", event->fileinfo.tx_id);

    if (event->fileinfo.md5) {
        jb_set_string(jb, "md5", event->fileinfo.md5);
    }

    if (event->fileinfo.sha1) {
        jb_set_string(jb, "sha1", event->fileinfo.sha1);
    }

    if (event->fileinfo.sha256) {
        jb_set_string(jb, "sha256", event->fileinfo.sha256);
    }

    jb_set_bool(jb, "stored", event->fileinfo.stored);
    if (event->fileinfo.stored) {
        jb_set_uint(jb, "file_id", event->fileinfo.file_id);
    }

    jb_set_uint(jb, "size", event->fileinfo.size);
    if (event->fileinfo.end > 0) {
        jb_set_uint(jb, "start", event->fileinfo.start);
        jb_set_uint(jb, "end", event->fileinfo.end);
    }

    /* Close Fileinfo object. */
    jb_close(jb);

    /* Handle app layer record if present. */
    if (event->common.app_proto && strcmp(event->common.app_proto, "http") == 0 &&
        event->app_layer.http) {
        jb_open_object(jb, "http");
        logHttpInfoCommon(jb, event->app_layer.http);
        jb_close(jb);
    } else if (event->app_layer.nta) {
        jb_set_object(jb, event->common.app_proto, (JsonBuilder *)event->app_layer.nta);
    }

    jb_close(jb);

    /* Copy JSON record and pass it to the caller. */
    *len = jb_len(jb);
    *data = malloc(*len * sizeof(char));
    if (*data == NULL) {
        SCLogError("Failed allocating buffer to convert event to JSON");
        return;
    }

    memcpy(*data, jb_ptr(jb), *len);
    jb_free(jb);
}

/* Convert a Flow event to JSON. */
void suricata_flow_to_json(FlowEvent *event, char **data, size_t *len) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "flow");

    /* Log flow specific info. */
    logFlowCommon(jb, &event->flow);
    logFlowExtended(jb, &event->flow, event->common.proto);

    /* Copy JSON record and pass it to the caller. */
    jb_close(jb);
    *len = jb_len(jb);
    *data = malloc(*len * sizeof(char));
    if (*data == NULL) {
        SCLogError("Failed allocating buffer to convert event to JSON");
        return;
    }

    memcpy(*data, jb_ptr(jb), *len);
    jb_free(jb);
}

/* Convert a FlowSnip event to JSON. */
void suricata_flowsnip_to_json(FlowSnipEvent *event, char **data, size_t *len) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "flow-snip");

    /* Log flow specific info. */
    logFlowCommon(jb, &event->flow);
    logFlowExtended(jb, &event->flow, event->common.proto);

    /* Log flow snip specific info. */
    jb_open_object(jb, "flow-snip");
    jb_set_uint(jb, "snip_id", event->snip_id);
    jb_set_uint(jb, "num_packets", event->num_packets);
    jb_set_uint(jb, "pkt_cnt", event->pkt_cnt);
    jb_set_string(jb, "timestamp_first", event->timestamp_first);
    jb_set_string(jb, "timestamp_last", event->timestamp_last);

    /* Log alerts .*/
    if (event->alerts_size > 0) {
        JsonBuilder *alertsjb = jb_new_array();

        for (int i = 0; i < event->alerts_size; i++) {
            JsonBuilder *obj = jb_new_object();
            logAlertCommon(obj, &event->alerts[i]);
            jb_close(obj);
            jb_append_object(alertsjb, obj);
            jb_free(obj);
        }

        jb_close(alertsjb);
        jb_set_object(jb, "alerts", alertsjb);
        jb_free(alertsjb);
    }

    jb_close(jb);

    /* Copy JSON record and pass it to the caller. */
    jb_close(jb);
    *len = jb_len(jb);
    *data = malloc(*len * sizeof(char));
    if (*data == NULL) {
        SCLogError("Failed allocating buffer to convert event to JSON");
        return;
    }

    memcpy(*data, jb_ptr(jb), *len);
    jb_free(jb);
}

/* Convert a HTTP event to JSON. */
void suricata_http_to_json(HttpEvent *event, char **data, size_t *len) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "http");
    jb_set_uint(jb, "tx_id", event->http.tx_id);

    /* Log event specific info. */
    jb_open_object(jb, "http");
    logHttpInfoCommon(jb, &event->http);

    /* Log headers. */
    if (event->http.request_headers[0].name) {
        jb_open_array(jb, "request_headers");
    }

    for (int i = 0; i < MAX_NUM_HTTP_HEADERS && event->http.request_headers[i].name; i++) {
        jb_start_object(jb);
        /* Make sure we both log name and value even if empty. */
        if (bstr_len(event->http.request_headers[i].name) > 0) {
            jb_set_string_from_bytes(jb, "name", bstr_ptr(event->http.request_headers[i].name),
                                    bstr_len(event->http.request_headers[i].name));
        } else {
            jb_set_string(jb, "name", "");
        }

        if (bstr_len(event->http.request_headers[i].value) > 0) {
            jb_set_string_from_bytes(jb, "value", bstr_ptr(event->http.request_headers[i].value),
                                    bstr_len(event->http.request_headers[i].value));
        } else {
            jb_set_string(jb, "value", "");
        }
        jb_close(jb);
    }

    /* Close array. */
    if (event->http.request_headers[0].name) {
        jb_close(jb);
    }

    if (event->http.response_headers[0].name) {
        jb_open_array(jb, "response_headers");
    }

    for (int i = 0; i < MAX_NUM_HTTP_HEADERS && event->http.response_headers[i].name; i++) {
        jb_start_object(jb);
        /* Make sure we both log name and value even if empty. */
        if (bstr_len(event->http.response_headers[i].name) > 0) {
            jb_set_string_from_bytes(jb, "name", bstr_ptr(event->http.response_headers[i].name),
                                     bstr_len(event->http.response_headers[i].name));
        } else {
            jb_set_string(jb, "name", "");
        }

        if(bstr_len(event->http.response_headers[i].value) > 0) {
            jb_set_string_from_bytes(jb, "value", bstr_ptr(event->http.response_headers[i].value),
                                     bstr_len(event->http.response_headers[i].value));
        } else {
            jb_set_string(jb, "value", "");
        }

        jb_close(jb);
    }

    /* Close array. */
    if (event->http.response_headers[0].name) {
        jb_close(jb);
    }

    /* TODO: Add files. */

    /* Close HTTP object. */
    jb_close(jb);

    /* Copy JSON record and pass it to the caller. */
    jb_close(jb);
    *len = jb_len(jb);
    *data = malloc(*len * sizeof(char));
    if (*data == NULL) {
        SCLogError("Failed allocating buffer to convert event to JSON");
        return;
    }

    memcpy(*data, jb_ptr(jb), *len);
    jb_free(jb);
}
