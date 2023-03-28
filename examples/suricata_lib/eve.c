/* EVE output module. */

#include "suricata-common.h" /* Ordering matters here. */
#include "rust.h"

#include "eve.h"


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
    if (common->parent_id) {
        jb_set_uint(jb, "parent_id", common->parent_id);
    }

    if (common->app_proto) {
        jb_set_string(jb, "app_proto", common->app_proto);
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
                                 bstr_len(http_info->uri));
    }

    if (http_info->content_type) {
        jb_set_string_from_bytes(jb, "http_content_type", bstr_ptr(http_info->content_type),
                                 bstr_len(http_info->content_type));
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

    if (flow->dev) {
        jb_set_string(jb, "in_iface", flow->dev);
    }

    if (flow->vlan_id[0]) {
        jb_open_array(jb, "vlan");
        jb_append_uint(jb, flow->vlan_id[0]);
        if (flow->vlan_id[1]) {
            jb_append_uint(jb, flow->vlan_id[1]);
        }
        jb_close(jb);
    }

    jb_set_uint(jb, "pkts_toserver", flow->pkts_toserver);
    jb_set_uint(jb, "pkts_toclient", flow->pkts_toclient);
    jb_set_uint(jb, "bytes_toserver", flow->bytes_toserver);
    jb_set_uint(jb, "bytes_toclient", flow->bytes_toclient);
    jb_set_string(jb, "start", flow->start);
    jb_set_string(jb, "end", flow->end);
    jb_set_uint(jb, "age", flow->age);
    jb_set_bool(jb, "emergency", flow->emergency);
    jb_set_string(jb, "state", flow->state);
    jb_set_string(jb, "reason", flow->reason);
    jb_set_bool(jb, "alerted", flow->alerted);

    jb_close(jb);
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

/* Actual logging to file. */
static void logLine(FILE *fp, const void *data, size_t len) {
    char *line = malloc((len + 1) + sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "Failed allocating buffer for logging EVE event");
        return;
    }

    /* Copy buffer and append '\n'. */
    memcpy(line, data, len);
    line[len] = '\n';

    fwrite(line, 1, len + 1, fp);
    free((void *)line);
}

/* Log an Alert event. */
void logAlert(FILE *fp, AlertEvent *event) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "alert");

    /* Log alert specific info. */
    logAlertCommon(jb, &event->alert);

    /* Handle app layer record if present. */
    if (strcmp(event->common.app_proto, "http") == 0 && event->app_layer.http) {
        jb_open_object(jb, "http");
        logHttpInfoCommon(jb, event->app_layer.http);
        jb_close(jb);
    } else if (event->app_layer.nta) {
        jb_set_object(jb, event->common.app_proto, (JsonBuilder *)event->app_layer.nta);
    }

    /* Write JSON record. */
    jb_close(jb);
    logLine(fp, jb_ptr(jb), jb_len(jb));
    jb_free(jb);
}

/* Log an HTTP event. */
void logHttp(FILE *fp, HttpEvent *event) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "http");
    jb_set_uint(jb, "tx_id", event->http.tx_id);

    /* Log event specific info. */
    jb_open_object(jb, "http");
    logHttpInfoCommon(jb, &event->http);

    /* Log headers. */
    jb_open_array(jb, "request_headers");
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
    jb_close(jb);

    jb_open_array(jb, "response_headers");
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
    jb_close(jb);

    /* TODO: Add files. */

    /* Close HTTP object. */
    jb_close(jb);

    /* Write JSON record. */
    jb_close(jb);
    logLine(fp, jb_ptr(jb), jb_len(jb));
    jb_free(jb);
}

/* Log a Fileinfo event. */
void logFileinfo(FILE *fp, FileinfoEvent *event) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "fileinfo");

    /* Log alert specific info. */
    jb_open_object(jb, "fileinfo");
    jb_set_string_from_bytes(jb, "filename", event->fileinfo.filename,
                             event->fileinfo.filename_len);

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
    if (strcmp(event->common.app_proto, "http") == 0 && event->app_layer.http) {
        jb_open_object(jb, "http");
        logHttpInfoCommon(jb, event->app_layer.http);
        jb_close(jb);
    } else if (event->app_layer.nta) {
        jb_set_object(jb, event->common.app_proto, (JsonBuilder *)event->app_layer.nta);
    }

    /* Write JSON record. */
    jb_close(jb);
    logLine(fp, jb_ptr(jb), jb_len(jb));
    jb_free(jb);
}

/* Log a FlowSnip event. */
void logFlowSnip(FILE *fp, FlowSnipEvent *event) {
    JsonBuilder *jb = jb_new_object();

    /* Log common info. */
    logCommon(jb, &event->common);
    jb_set_string(jb, "event_type", "flow-snip");

    /* Log flow specific info. */
    logFlowCommon(jb, &event->flow);

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

    /* Write JSON record. */
    jb_close(jb);
    logLine(fp, jb_ptr(jb), jb_len(jb));
    jb_free(jb);
}

/* Log an NTA event. */
void logNta(FILE *fp, void *data, size_t len) {
    /* Write JSON record. */
    logLine(fp, data, len);
}