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
 * Logs detection and monitoring events in JSON format.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "app-layer-parser.h"
#include "util-classification-config.h"
#include "util-syslog.h"

#include "output.h"
#include "output-json.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "util-log-redis.h"
#include "util-device.h"

#include "flow-var.h"
#include "flow-bit.h"

#ifndef HAVE_LIBJANSSON

/** Handle the case where no JSON support is compiled in.
 *
 */

int OutputJsonOpenFileCtx(LogFileCtx *, char *);

void OutputJsonRegister (void)
{
    SCLogDebug("Can't register JSON output - JSON support was disabled during build.");
}

#else /* implied we do have JSON support */

#define DEFAULT_LOG_FILENAME "eve.json"
#define DEFAULT_ALERT_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_ALERT_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_ALERT_SYSLOG_LEVEL              LOG_INFO
#define MODULE_NAME "OutputJSON"

#define OUTPUT_BUFFER_SIZE 65536

static void OutputJsonDeInitCtx(OutputCtx *);

void OutputJsonRegister (void)
{
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);
}

json_t *SCJsonBool(int val)
{
    return (val ? json_true() : json_false());
}

/* Default Sensor ID value */
static int64_t sensor_id = -1; /* -1 = not defined */

static void JsonAddPacketvars(const Packet *p, json_t *js_vars)
{
    if (p == NULL || p->pktvar == NULL) {
        return;
    }
    json_t *js_pktvars = NULL;
    PktVar *pv = p->pktvar;
    while (pv != NULL) {
        if (pv->key || pv->id > 0) {
            if (js_pktvars == NULL) {
                js_pktvars = json_array();
                if (js_pktvars == NULL)
                    break;
            }
            json_t *js_pair = json_object();
            if (js_pair == NULL) {
                break;
            }

            if (pv->key != NULL) {
                uint32_t offset = 0;
                uint8_t keybuf[pv->key_len + 1];
                PrintStringsToBuffer(keybuf, &offset,
                        sizeof(keybuf),
                        pv->key, pv->key_len);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        pv->value, pv->value_len);
                json_object_set_new(js_pair, (char *)keybuf,
                        json_string((char *)printable_buf));
            } else {
                const char *varname = VarNameStoreLookupById(pv->id, VAR_TYPE_PKT_VAR);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        pv->value, pv->value_len);

                json_object_set_new(js_pair, varname,
                        json_string((char *)printable_buf));
            }
            json_array_append_new(js_pktvars, js_pair);
        }
        pv = pv->next;
    }
    if (js_pktvars) {
        json_object_set_new(js_vars, "pktvars", js_pktvars);
    }
}

static void JsonAddFlowvars(const Flow *f, json_t *js_vars)
{
    if (f == NULL || f->flowvar == NULL) {
        return;
    }
    json_t *js_flowvars = NULL;
    json_t *js_flowints = NULL;
    json_t *js_flowbits = NULL;
    GenericVar *gv = f->flowvar;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *)gv;
            if (fv->datatype == FLOWVAR_TYPE_STR && fv->key == NULL) {
                const char *varname = VarNameStoreLookupById(fv->idx, VAR_TYPE_FLOW_VAR);
                if (varname) {
                    if (js_flowvars == NULL) {
                        js_flowvars = json_object();
                        if (js_flowvars == NULL)
                            break;
                    }

                    uint32_t len = fv->data.fv_str.value_len;
                    uint8_t printable_buf[len + 1];
                    uint32_t offset = 0;
                    PrintStringsToBuffer(printable_buf, &offset,
                            sizeof(printable_buf),
                            fv->data.fv_str.value, fv->data.fv_str.value_len);

                    json_object_set_new(js_flowvars, varname,
                            json_string((char *)printable_buf));
                }
            } else if (fv->datatype == FLOWVAR_TYPE_STR && fv->key != NULL) {
                if (js_flowvars == NULL) {
                    js_flowvars = json_object();
                    if (js_flowvars == NULL)
                        break;
                }

                uint8_t keybuf[fv->keylen + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(keybuf, &offset,
                        sizeof(keybuf),
                        fv->key, fv->keylen);

                uint32_t len = fv->data.fv_str.value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        fv->data.fv_str.value, fv->data.fv_str.value_len);

                json_object_set_new(js_flowvars, (const char *)keybuf,
                        json_string((char *)printable_buf));

            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                const char *varname = VarNameStoreLookupById(fv->idx, VAR_TYPE_FLOW_INT);
                if (varname) {
                    if (js_flowints == NULL) {
                        js_flowints = json_object();
                        if (js_flowints == NULL)
                            break;
                    }

                    json_object_set_new(js_flowints, varname, json_integer(fv->data.fv_int.value));
                }

            }
        } else if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *)gv;
            const char *varname = VarNameStoreLookupById(fb->idx, VAR_TYPE_FLOW_BIT);
            if (varname) {
                if (js_flowbits == NULL) {
                    js_flowbits = json_object();
                    if (js_flowbits == NULL)
                        break;
                }
                json_object_set_new(js_flowbits, varname, json_boolean(1));
            }
        }
        gv = gv->next;
    }
    if (js_flowbits) {
        json_object_set_new(js_vars, "flowbits", js_flowbits);
    }
    if (js_flowints) {
        json_object_set_new(js_vars, "flowints", js_flowints);
    }
    if (js_flowvars) {
        json_object_set_new(js_vars, "flowvars", js_flowvars);
    }
}

void JsonAddVars(const Packet *p, const Flow *f, json_t *js)
{
    if ((p && p->pktvar) || (f && f->flowvar)) {
        json_t *js_vars = json_object();
        if (js_vars) {
            if (f && f->flowvar) {
                JsonAddFlowvars(f, js_vars);
            }
            if (p && p->pktvar) {
                JsonAddPacketvars(p, js_vars);
            }

            json_object_set_new(js, "vars", js_vars);
        }
    }
}

/** \brief jsonify tcp flags field
 *  Only add 'true' fields in an attempt to keep things reasonably compact.
 */
void JsonTcpFlags(uint8_t flags, json_t *js)
{
    if (flags & TH_SYN)
        json_object_set_new(js, "syn", json_true());
    if (flags & TH_FIN)
        json_object_set_new(js, "fin", json_true());
    if (flags & TH_RST)
        json_object_set_new(js, "rst", json_true());
    if (flags & TH_PUSH)
        json_object_set_new(js, "psh", json_true());
    if (flags & TH_ACK)
        json_object_set_new(js, "ack", json_true());
    if (flags & TH_URG)
        json_object_set_new(js, "urg", json_true());
    if (flags & TH_ECN)
        json_object_set_new(js, "ecn", json_true());
    if (flags & TH_CWR)
        json_object_set_new(js, "cwr", json_true());
}

/**
 * \brief Add five tuple from packet to JSON object
 *
 * \param p Packet
 * \param direction_sensitive Indicate direction sensitivity
 * \param js JSON object
 */
void JsonFiveTuple(const Packet *p, int direction_sensitive, json_t *js)
{
    char srcip[46], dstip[46];
    Port sp, dp;
    char proto[16];

    srcip[0] = '\0';
    dstip[0] = '\0';

    if (direction_sensitive) {
        if ((PKT_IS_TOSERVER(p))) {
            if (PKT_IS_IPV4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                          srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                          dstip, sizeof(dstip));
            } else if (PKT_IS_IPV6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                          srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                          dstip, sizeof(dstip));
            }
            sp = p->sp;
            dp = p->dp;
        } else {
            if (PKT_IS_IPV4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                          srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                          dstip, sizeof(dstip));
            } else if (PKT_IS_IPV6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                          srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                          dstip, sizeof(dstip));
            }
            sp = p->dp;
            dp = p->sp;
        }
    } else {
        if (PKT_IS_IPV4(p)) {
            PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                      srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                      dstip, sizeof(dstip));
        } else if (PKT_IS_IPV6(p)) {
            PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                      srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                      dstip, sizeof(dstip));
        }
        sp = p->sp;
        dp = p->dp;
    }

    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "%03" PRIu32, IP_GET_IPPROTO(p));
    }

    json_object_set_new(js, "src_ip", json_string(srcip));

    switch(p->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "src_port", json_integer(sp));
            break;
    }

    json_object_set_new(js, "dest_ip", json_string(dstip));

    switch(p->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "dest_port", json_integer(dp));
            break;
    }

    json_object_set_new(js, "proto", json_string(proto));
}

void CreateJSONFlowId(json_t *js, const Flow *f)
{
    if (f == NULL)
        return;
    int64_t flow_id = FlowGetId(f);
    json_object_set_new(js, "flow_id", json_integer(flow_id));
}

json_t *CreateJSONHeader(const Packet *p, int direction_sensitive,
                         const char *event_type)
{
    char timebuf[64];

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

    /* time & tx */
    json_object_set_new(js, "timestamp", json_string(timebuf));

    CreateJSONFlowId(js, (const Flow *)p->flow);

    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));

    /* input interface */
    if (p->livedev) {
        json_object_set_new(js, "in_iface", json_string(p->livedev->dev));
    }

    /* pcap_cnt */
    if (p->pcap_cnt != 0) {
        json_object_set_new(js, "pcap_cnt", json_integer(p->pcap_cnt));
    }

    if (event_type) {
        json_object_set_new(js, "event_type", json_string(event_type));
    }

    /* vlan */
    if (p->vlan_idx > 0) {
        json_t *js_vlan;
        switch (p->vlan_idx) {
            case 1:
                json_object_set_new(js, "vlan",
                                    json_integer(VLAN_GET_ID1(p)));
                break;
            case 2:
                js_vlan = json_array();
                if (unlikely(js != NULL)) {
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID1(p)));
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID2(p)));
                    json_object_set_new(js, "vlan", js_vlan);
                }
                break;
            default:
                /* shouldn't get here */
                break;
        }
    }

    /* 5-tuple */
    JsonFiveTuple(p, direction_sensitive, js);

    /* icmp */
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (p->icmpv4h) {
                json_object_set_new(js, "icmp_type",
                                    json_integer(p->icmpv4h->type));
                json_object_set_new(js, "icmp_code",
                                    json_integer(p->icmpv4h->code));
            }
            break;
        case IPPROTO_ICMPV6:
            if (p->icmpv6h) {
                json_object_set_new(js, "icmp_type",
                                    json_integer(p->icmpv6h->type));
                json_object_set_new(js, "icmp_code",
                                    json_integer(p->icmpv6h->code));
            }
            break;
    }

    return js;
}

json_t *CreateJSONHeaderWithTxId(const Packet *p, int direction_sensitive,
                                 const char *event_type, uint64_t tx_id)
{
    json_t *js = CreateJSONHeader(p, direction_sensitive, event_type);
    if (unlikely(js == NULL))
        return NULL;

    /* tx id for correlation with other events */
    json_object_set_new(js, "tx_id", json_integer(tx_id));

    return js;
}

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data)
{
    OutputJSONMemBufferWrapper *wrapper = data;
    MemBuffer **memb = wrapper->buffer;

    if (MEMBUFFER_OFFSET(*memb) + size >= MEMBUFFER_SIZE(*memb)) {
        MemBufferExpand(memb, wrapper->expand_by);
    }

    MemBufferWriteRaw((*memb), str, size);
    return 0;
}

int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer)
{
    if (file_ctx->sensor_name) {
        json_object_set_new(js, "host",
                            json_string(file_ctx->sensor_name));
    }

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
    }

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = buffer,
        .expand_by = OUTPUT_BUFFER_SIZE
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            file_ctx->json_flags);
    if (r != 0)
        return TM_ECODE_OK;

    LogFileWrite(file_ctx, *buffer);
    return 0;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *OutputJsonInitCtx(ConfNode *conf)
{
    OutputJsonCtx *json_ctx = SCCalloc(1, sizeof(OutputJsonCtx));;

    /* First lookup a sensor-name value in this outputs configuration
     * node (deprecated). If that fails, lookup the global one. */
    const char *sensor_name = ConfNodeLookupChildValue(conf, "sensor-name");
    if (sensor_name != NULL) {
        SCLogWarning(SC_ERR_DEPRECATED_CONF,
            "Found deprecated eve-log setting \"sensor-name\". "
            "Please set sensor-name globally.");
    }
    else {
        (void)ConfGet("sensor-name", &sensor_name);
    }

    if (unlikely(json_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        return NULL;
    }

    json_ctx->file_ctx = LogFileNewCtx();
    if (unlikely(json_ctx->file_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        SCFree(json_ctx);
        return NULL;
    }

    if (sensor_name) {
        json_ctx->file_ctx->sensor_name = SCStrdup(sensor_name);
        if (json_ctx->file_ctx->sensor_name  == NULL) {
            LogFileFreeCtx(json_ctx->file_ctx);
            SCFree(json_ctx);
            return NULL;
        }
    } else {
        json_ctx->file_ctx->sensor_name = NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(json_ctx->file_ctx);
        SCFree(json_ctx);
        return NULL;
    }

    output_ctx->data = json_ctx;
    output_ctx->DeInit = OutputJsonDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "filetype");

        // Backwards compatibility
        if (output_s == NULL) {
            output_s = ConfNodeLookupChildValue(conf, "type");
        }

        if (output_s != NULL) {
            if (strcmp(output_s, "file") == 0 ||
                strcmp(output_s, "regular") == 0) {
                json_ctx->json_out = LOGFILE_TYPE_FILE;
            } else if (strcmp(output_s, "syslog") == 0) {
                json_ctx->json_out = LOGFILE_TYPE_SYSLOG;
            } else if (strcmp(output_s, "unix_dgram") == 0) {
                json_ctx->json_out = LOGFILE_TYPE_UNIX_DGRAM;
            } else if (strcmp(output_s, "unix_stream") == 0) {
                json_ctx->json_out = LOGFILE_TYPE_UNIX_STREAM;
            } else if (strcmp(output_s, "redis") == 0) {
#ifdef HAVE_LIBHIREDIS
                SCLogRedisInit();
                json_ctx->json_out = LOGFILE_TYPE_REDIS;
#else
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "redis JSON output option is not compiled");
                exit(EXIT_FAILURE);
#endif
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Invalid JSON output option: %s", output_s);
                exit(EXIT_FAILURE);
            }
        }

        const char *prefix = ConfNodeLookupChildValue(conf, "prefix");
        if (prefix != NULL)
        {
            SCLogInfo("Using prefix '%s' for JSON messages", prefix);
            json_ctx->file_ctx->prefix = SCStrdup(prefix);
            if (json_ctx->file_ctx->prefix == NULL)
            {
                SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for eve-log.prefix setting.");
                exit(EXIT_FAILURE);
            }
            json_ctx->file_ctx->prefix_len = strlen(prefix);
        }

        if (json_ctx->json_out == LOGFILE_TYPE_FILE ||
            json_ctx->json_out == LOGFILE_TYPE_UNIX_DGRAM ||
            json_ctx->json_out == LOGFILE_TYPE_UNIX_STREAM)
        {
            if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
                LogFileFreeCtx(json_ctx->file_ctx);
                SCFree(json_ctx);
                SCFree(output_ctx);
                return NULL;
            }
            OutputRegisterFileRotationFlag(&json_ctx->file_ctx->rotation_flag);

            const char *format_s = ConfNodeLookupChildValue(conf, "format");
            if (format_s != NULL) {
                if (strcmp(format_s, "indent") == 0) {
                    json_ctx->format = INDENT;
                } else if (strcmp(format_s, "compact") == 0) {
                    json_ctx->format = COMPACT;
                } else {
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                               "Invalid JSON format option: %s", format_s);
                    exit(EXIT_FAILURE);
                }
            }
        } else if (json_ctx->json_out == LOGFILE_TYPE_SYSLOG) {
            const char *facility_s = ConfNodeLookupChildValue(conf, "facility");
            if (facility_s == NULL) {
                facility_s = DEFAULT_ALERT_SYSLOG_FACILITY_STR;
            }

            int facility = SCMapEnumNameToValue(facility_s, SCSyslogGetFacilityMap());
            if (facility == -1) {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid syslog facility: \"%s\","
                        " now using \"%s\" as syslog facility", facility_s,
                        DEFAULT_ALERT_SYSLOG_FACILITY_STR);
                facility = DEFAULT_ALERT_SYSLOG_FACILITY;
            }

            const char *level_s = ConfNodeLookupChildValue(conf, "level");
            if (level_s != NULL) {
                int level = SCMapEnumNameToValue(level_s, SCSyslogGetLogLevelMap());
                if (level != -1) {
                    json_ctx->file_ctx->syslog_setup.alert_syslog_level = level;
                }
            }

            const char *ident = ConfNodeLookupChildValue(conf, "identity");
            /* if null we just pass that to openlog, which will then
             * figure it out by itself. */

            openlog(ident, LOG_PID|LOG_NDELAY, facility);

        }
#ifdef HAVE_LIBHIREDIS
        else if (json_ctx->json_out == LOGFILE_TYPE_REDIS) {
            ConfNode *redis_node = ConfNodeLookupChild(conf, "redis");
            if (!json_ctx->file_ctx->sensor_name) {
                char hostname[1024];
                gethostname(hostname, 1023);
                json_ctx->file_ctx->sensor_name = SCStrdup(hostname);
            }
            if (json_ctx->file_ctx->sensor_name  == NULL) {
                LogFileFreeCtx(json_ctx->file_ctx);
                SCFree(json_ctx);
                SCFree(output_ctx);
                return NULL;
            }

            if (SCConfLogOpenRedis(redis_node, json_ctx->file_ctx) < 0) {
                LogFileFreeCtx(json_ctx->file_ctx);
                SCFree(json_ctx);
                SCFree(output_ctx);
                return NULL;
            }
        }
#endif

        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (ByteExtractStringUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Failed to initialize JSON output, "
                           "invalid sensor-is: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
        }

        json_ctx->file_ctx->type = json_ctx->json_out;
    }

    SCLogDebug("returning output_ctx %p", output_ctx);
    return output_ctx;
}

static void OutputJsonDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonCtx *json_ctx = (OutputJsonCtx *)output_ctx->data;
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    if (logfile_ctx->dropped) {
        SCLogWarning(SC_WARN_EVENT_DROPPED,
                "%"PRIu64" events were dropped due to slow or "
                "disconnected socket", logfile_ctx->dropped);
    }
    LogFileFreeCtx(logfile_ctx);
    SCFree(json_ctx);
    SCFree(output_ctx);
}

#endif
