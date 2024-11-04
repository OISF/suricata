/* Copyright (C) 2007-2023 Open Information Security Foundation
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
#include "flow.h"
#include "conf.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-var-name.h"
#include "util-macset.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-engine.h"
#include "util-classification-config.h"
#include "util-syslog.h"

/* Internal output plugins */
#include "output-eve-syslog.h"
#include "output-eve-null.h"

#include "output.h"
#include "output-json.h"

#include "util-byte.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "util-log-redis.h"
#include "util-device.h"
#include "util-validate.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "flow-storage.h"

#include "source-pcap-file-helper.h"

#define DEFAULT_LOG_FILENAME "eve.json"
#define MODULE_NAME "OutputJSON"

#define MAX_JSON_SIZE 2048

static void OutputJsonDeInitCtx(OutputCtx *);
static void CreateEveCommunityFlowId(JsonBuilder *js, const Flow *f, const uint16_t seed);
static int CreateJSONEther(
        JsonBuilder *parent, const Packet *p, const Flow *f, enum OutputJsonLogDirection dir);

static const char *TRAFFIC_ID_PREFIX = "traffic/id/";
static const char *TRAFFIC_LABEL_PREFIX = "traffic/label/";
static size_t traffic_id_prefix_len = 0;
static size_t traffic_label_prefix_len = 0;

const JsonAddrInfo json_addr_info_zero;

void OutputJsonRegister (void)
{
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);

    traffic_id_prefix_len = strlen(TRAFFIC_ID_PREFIX);
    traffic_label_prefix_len = strlen(TRAFFIC_LABEL_PREFIX);

    // Register output file types that use the new eve filetype registration
    // API.
    SyslogInitialize();
    NullLogInitialize();
}

json_t *SCJsonString(const char *val)
{
    if (val == NULL){
        return NULL;
    }
    json_t * retval = json_string(val);
    char retbuf[MAX_JSON_SIZE] = {0};
    if (retval == NULL) {
        uint32_t u = 0;
        uint32_t offset = 0;
        for (u = 0; u < strlen(val); u++) {
            if (isprint(val[u])) {
                PrintBufferData(retbuf, &offset, MAX_JSON_SIZE-1, "%c",
                        val[u]);
            } else {
                PrintBufferData(retbuf, &offset, MAX_JSON_SIZE-1,
                        "\\x%02X", val[u]);
            }
        }
        retbuf[offset] = '\0';
        retval = json_string(retbuf);
    }
    return retval;
}

/* Default Sensor ID value */
static int64_t sensor_id = -1; /* -1 = not defined */

void EveFileInfo(JsonBuilder *jb, const File *ff, const uint64_t tx_id, const uint16_t flags)
{
    jb_set_string_from_bytes(jb, "filename", ff->name, ff->name_len);

    if (ff->sid_cnt > 0) {
        jb_open_array(jb, "sid");
        for (uint32_t i = 0; ff->sid != NULL && i < ff->sid_cnt; i++) {
            jb_append_uint(jb, ff->sid[i]);
        }
        jb_close(jb);
    }

#ifdef HAVE_MAGIC
    if (ff->magic)
        jb_set_string(jb, "magic", (char *)ff->magic);
#endif
    jb_set_bool(jb, "gaps", ff->flags & FILE_HAS_GAPS);
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            JB_SET_STRING(jb, "state", "CLOSED");
            if (ff->flags & FILE_MD5) {
                jb_set_hex(jb, "md5", (uint8_t *)ff->md5, (uint32_t)sizeof(ff->md5));
            }
            if (ff->flags & FILE_SHA1) {
                jb_set_hex(jb, "sha1", (uint8_t *)ff->sha1, (uint32_t)sizeof(ff->sha1));
            }
            break;
        case FILE_STATE_TRUNCATED:
            JB_SET_STRING(jb, "state", "TRUNCATED");
            break;
        case FILE_STATE_ERROR:
            JB_SET_STRING(jb, "state", "ERROR");
            break;
        default:
            JB_SET_STRING(jb, "state", "UNKNOWN");
            break;
    }

    if (ff->flags & FILE_SHA256) {
        jb_set_hex(jb, "sha256", (uint8_t *)ff->sha256, (uint32_t)sizeof(ff->sha256));
    }

    if (flags & FILE_STORED) {
        JB_SET_TRUE(jb, "stored");
        jb_set_uint(jb, "file_id", ff->file_store_id);
    } else {
        JB_SET_FALSE(jb, "stored");
        if (flags & FILE_STORE) {
            JB_SET_TRUE(jb, "storing");
        }
    }

    jb_set_uint(jb, "size", FileTrackedSize(ff));
    if (ff->end > 0) {
        jb_set_uint(jb, "start", ff->start);
        jb_set_uint(jb, "end", ff->end);
    }
    jb_set_uint(jb, "tx_id", tx_id);
}

static void EveAddPacketVars(const Packet *p, JsonBuilder *js_vars)
{
    if (p == NULL || p->pktvar == NULL) {
        return;
    }
    PktVar *pv = p->pktvar;
    bool open = false;
    while (pv != NULL) {
        if (pv->key || pv->id > 0) {
            if (!open) {
                jb_open_array(js_vars, "pktvars");
                open = true;
            }
            jb_start_object(js_vars);

            if (pv->key != NULL) {
                uint32_t offset = 0;
                uint8_t keybuf[pv->key_len + 1];
                PrintStringsToBuffer(keybuf, &offset, pv->key_len + 1, pv->key, pv->key_len);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset, len + 1, pv->value, pv->value_len);
                jb_set_string(js_vars, (char *)keybuf, (char *)printable_buf);
            } else {
                const char *varname = VarNameStoreLookupById(pv->id, VAR_TYPE_PKT_VAR);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(printable_buf, &offset, len + 1, pv->value, pv->value_len);
                jb_set_string(js_vars, varname, (char *)printable_buf);
            }
            jb_close(js_vars);
        }
        pv = pv->next;
    }
    if (open) {
        jb_close(js_vars);
    }
}

/**
 * \brief Check if string s has prefix prefix.
 *
 * \retval true if string has prefix
 * \retval false if string does not have prefix
 *
 * TODO: Move to file with other string handling functions.
 */
static bool SCStringHasPrefix(const char *s, const char *prefix)
{
    if (strncmp(s, prefix, strlen(prefix)) == 0) {
        return true;
    }
    return false;
}

static void EveAddFlowVars(const Flow *f, JsonBuilder *js_root, JsonBuilder **js_traffic)
{
    if (f == NULL || f->flowvar == NULL) {
        return;
    }
    JsonBuilder *js_flowvars = NULL;
    JsonBuilder *js_traffic_id = NULL;
    JsonBuilder *js_traffic_label = NULL;
    JsonBuilder *js_flowints = NULL;
    JsonBuilder *js_flowbits = NULL;
    GenericVar *gv = f->flowvar;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *)gv;
            if (fv->datatype == FLOWVAR_TYPE_STR && fv->key == NULL) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_VAR);
                if (varname) {
                    if (js_flowvars == NULL) {
                        js_flowvars = jb_new_array();
                        if (js_flowvars == NULL)
                            break;
                    }

                    uint32_t len = fv->data.fv_str.value_len;
                    uint8_t printable_buf[len + 1];
                    uint32_t offset = 0;
                    PrintStringsToBuffer(printable_buf, &offset, len + 1, fv->data.fv_str.value,
                            fv->data.fv_str.value_len);

                    jb_start_object(js_flowvars);
                    jb_set_string(js_flowvars, varname, (char *)printable_buf);
                    jb_close(js_flowvars);
                }
            } else if (fv->datatype == FLOWVAR_TYPE_STR && fv->key != NULL) {
                if (js_flowvars == NULL) {
                    js_flowvars = jb_new_array();
                    if (js_flowvars == NULL)
                        break;
                }

                uint8_t keybuf[fv->keylen + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(keybuf, &offset, fv->keylen + 1, fv->key, fv->keylen);

                uint32_t len = fv->data.fv_str.value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset, len + 1, fv->data.fv_str.value,
                        fv->data.fv_str.value_len);

                jb_start_object(js_flowvars);
                jb_set_string(js_flowvars, (const char *)keybuf, (char *)printable_buf);
                jb_close(js_flowvars);
            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_INT);
                if (varname) {
                    if (js_flowints == NULL) {
                        js_flowints = jb_new_object();
                        if (js_flowints == NULL)
                            break;
                    }
                    jb_set_uint(js_flowints, varname, fv->data.fv_int.value);
                }

            }
        } else if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *)gv;
            const char *varname = VarNameStoreLookupById(fb->idx,
                    VAR_TYPE_FLOW_BIT);
            if (varname) {
                if (SCStringHasPrefix(varname, TRAFFIC_ID_PREFIX)) {
                    if (js_traffic_id == NULL) {
                        js_traffic_id = jb_new_array();
                        if (unlikely(js_traffic_id == NULL)) {
                            break;
                        }
                    }
                    jb_append_string(js_traffic_id, &varname[traffic_id_prefix_len]);
                } else if (SCStringHasPrefix(varname, TRAFFIC_LABEL_PREFIX)) {
                    if (js_traffic_label == NULL) {
                        js_traffic_label = jb_new_array();
                        if (unlikely(js_traffic_label == NULL)) {
                            break;
                        }
                    }
                    jb_append_string(js_traffic_label, &varname[traffic_label_prefix_len]);
                } else {
                    if (js_flowbits == NULL) {
                        js_flowbits = jb_new_array();
                        if (unlikely(js_flowbits == NULL))
                            break;
                    }
                    jb_append_string(js_flowbits, varname);
                }
            }
        }
        gv = gv->next;
    }
    if (js_flowbits) {
        jb_close(js_flowbits);
        jb_set_object(js_root, "flowbits", js_flowbits);
        jb_free(js_flowbits);
    }
    if (js_flowints) {
        jb_close(js_flowints);
        jb_set_object(js_root, "flowints", js_flowints);
        jb_free(js_flowints);
    }
    if (js_flowvars) {
        jb_close(js_flowvars);
        jb_set_object(js_root, "flowvars", js_flowvars);
        jb_free(js_flowvars);
    }

    if (js_traffic_id != NULL || js_traffic_label != NULL) {
        *js_traffic = jb_new_object();
        if (likely(*js_traffic != NULL)) {
            if (js_traffic_id != NULL) {
                jb_close(js_traffic_id);
                jb_set_object(*js_traffic, "id", js_traffic_id);
                jb_free(js_traffic_id);
            }
            if (js_traffic_label != NULL) {
                jb_close(js_traffic_label);
                jb_set_object(*js_traffic, "label", js_traffic_label);
                jb_free(js_traffic_label);
            }
            jb_close(*js_traffic);
        }
    }
}

void EveAddMetadata(const Packet *p, const Flow *f, JsonBuilder *js)
{
    if ((p && p->pktvar) || (f && f->flowvar)) {
        JsonBuilder *js_vars = jb_new_object();
        if (js_vars) {
            if (f && f->flowvar) {
                JsonBuilder *js_traffic = NULL;
                EveAddFlowVars(f, js_vars, &js_traffic);
                if (js_traffic != NULL) {
                    jb_set_object(js, "traffic", js_traffic);
                    jb_free(js_traffic);
                }
            }
            if (p && p->pktvar) {
                EveAddPacketVars(p, js_vars);
            }
            jb_close(js_vars);
            jb_set_object(js, "metadata", js_vars);
            jb_free(js_vars);
        }
    }
}

void EveAddCommonOptions(const OutputJsonCommonSettings *cfg, const Packet *p, const Flow *f,
        JsonBuilder *js, enum OutputJsonLogDirection dir)
{
    if (cfg->include_metadata) {
        EveAddMetadata(p, f, js);
    }
    if (cfg->include_ethernet) {
        CreateJSONEther(js, p, f, dir);
    }
    if (cfg->include_community_id && f != NULL) {
        CreateEveCommunityFlowId(js, f, cfg->community_id_seed);
    }
    if (f != NULL && f->tenant_id > 0) {
        jb_set_uint(js, "tenant_id", f->tenant_id);
    }
}

/**
 * \brief Jsonify a packet
 *
 * \param p Packet
 * \param js JSON object
 * \param max_length If non-zero, restricts the number of packet data bytes handled.
 */
void EvePacket(const Packet *p, JsonBuilder *js, uint32_t max_length)
{
    uint32_t max_len = max_length == 0 ? GET_PKT_LEN(p) : max_length;
    jb_set_base64(js, "packet", GET_PKT_DATA(p), max_len);

    if (!jb_open_object(js, "packet_info")) {
        return;
    }
    if (!jb_set_uint(js, "linktype", p->datalink)) {
        return;
    }
    jb_close(js);
}

/** \brief jsonify tcp flags field
 *  Only add 'true' fields in an attempt to keep things reasonably compact.
 */
void EveTcpFlags(const uint8_t flags, JsonBuilder *js)
{
    if (flags & TH_SYN)
        JB_SET_TRUE(js, "syn");
    if (flags & TH_FIN)
        JB_SET_TRUE(js, "fin");
    if (flags & TH_RST)
        JB_SET_TRUE(js, "rst");
    if (flags & TH_PUSH)
        JB_SET_TRUE(js, "psh");
    if (flags & TH_ACK)
        JB_SET_TRUE(js, "ack");
    if (flags & TH_URG)
        JB_SET_TRUE(js, "urg");
    if (flags & TH_ECN)
        JB_SET_TRUE(js, "ecn");
    if (flags & TH_CWR)
        JB_SET_TRUE(js, "cwr");
}

void JsonAddrInfoInit(const Packet *p, enum OutputJsonLogDirection dir, JsonAddrInfo *addr)
{
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    switch (dir) {
        case LOG_DIR_PACKET:
            if (PacketIsIPv4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                        srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                        dstip, sizeof(dstip));
            } else if (PacketIsIPv6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                        srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                        dstip, sizeof(dstip));
            } else {
                /* Not an IP packet so don't do anything */
                return;
            }
            sp = p->sp;
            dp = p->dp;
            break;
        case LOG_DIR_FLOW:
        case LOG_DIR_FLOW_TOSERVER:
            if ((PKT_IS_TOSERVER(p))) {
                if (PacketIsIPv4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PacketIsIPv6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->sp;
                dp = p->dp;
            } else {
                if (PacketIsIPv4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PacketIsIPv6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->dp;
                dp = p->sp;
            }
            break;
        case LOG_DIR_FLOW_TOCLIENT:
            if ((PKT_IS_TOCLIENT(p))) {
                if (PacketIsIPv4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PacketIsIPv6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->sp;
                dp = p->dp;
            } else {
                if (PacketIsIPv4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PacketIsIPv6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->dp;
                dp = p->sp;
            }
            break;
        default:
            DEBUG_VALIDATE_BUG_ON(1);
            return;
    }

    strlcpy(addr->src_ip, srcip, JSON_ADDR_LEN);
    strlcpy(addr->dst_ip, dstip, JSON_ADDR_LEN);

    switch (p->proto) {
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            addr->sp = sp;
            addr->dp = dp;
            addr->log_port = true;
            break;
        default:
            addr->log_port = false;
            break;
    }

    if (SCProtoNameValid(PacketGetIPProto(p))) {
        strlcpy(addr->proto, known_proto[PacketGetIPProto(p)], sizeof(addr->proto));
    } else {
        snprintf(addr->proto, sizeof(addr->proto), "%" PRIu32, PacketGetIPProto(p));
    }
}

#define COMMUNITY_ID_BUF_SIZE 64

static bool CalculateCommunityFlowIdv4(const Flow *f,
        const uint16_t seed, unsigned char *base64buf)
{
    struct {
        uint16_t seed;
        uint32_t src;
        uint32_t dst;
        uint8_t proto;
        uint8_t pad0;
        uint16_t sp;
        uint16_t dp;
    } __attribute__((__packed__)) ipv4;

    uint32_t src = f->src.addr_data32[0];
    uint32_t dst = f->dst.addr_data32[0];
    uint16_t sp = f->sp;
    if (f->proto == IPPROTO_ICMP)
        sp = f->icmp_s.type;
    sp = htons(sp);
    uint16_t dp = f->dp;
    if (f->proto == IPPROTO_ICMP)
        dp = f->icmp_d.type;
    dp = htons(dp);

    ipv4.seed = htons(seed);
    if (ntohl(src) < ntohl(dst) || (src == dst && sp < dp)) {
        ipv4.src = src;
        ipv4.dst = dst;
        ipv4.sp = sp;
        ipv4.dp = dp;
    } else {
        ipv4.src = dst;
        ipv4.dst = src;
        ipv4.sp = dp;
        ipv4.dp = sp;
    }
    ipv4.proto = f->proto;
    ipv4.pad0 = 0;

    uint8_t hash[20];
    if (SCSha1HashBuffer((const uint8_t *)&ipv4, sizeof(ipv4), hash, sizeof(hash)) == 1) {
        strlcpy((char *)base64buf, "1:", COMMUNITY_ID_BUF_SIZE);
        unsigned long out_len = COMMUNITY_ID_BUF_SIZE - 2;
        if (Base64Encode(hash, sizeof(hash), base64buf+2, &out_len) == SC_BASE64_OK) {
            return true;
        }
    }
    return false;
}

static bool CalculateCommunityFlowIdv6(const Flow *f,
        const uint16_t seed, unsigned char *base64buf)
{
    struct {
        uint16_t seed;
        uint32_t src[4];
        uint32_t dst[4];
        uint8_t proto;
        uint8_t pad0;
        uint16_t sp;
        uint16_t dp;
    } __attribute__((__packed__)) ipv6;

    uint16_t sp = f->sp;
    if (f->proto == IPPROTO_ICMPV6)
        sp = f->icmp_s.type;
    sp = htons(sp);
    uint16_t dp = f->dp;
    if (f->proto == IPPROTO_ICMPV6)
        dp = f->icmp_d.type;
    dp = htons(dp);

    ipv6.seed = htons(seed);
    int cmp_r = memcmp(&f->src, &f->dst, sizeof(f->src));
    if ((cmp_r < 0) || (cmp_r == 0 && sp < dp)) {
        memcpy(&ipv6.src, &f->src.addr_data32, 16);
        memcpy(&ipv6.dst, &f->dst.addr_data32, 16);
        ipv6.sp = sp;
        ipv6.dp = dp;
    } else {
        memcpy(&ipv6.src, &f->dst.addr_data32, 16);
        memcpy(&ipv6.dst, &f->src.addr_data32, 16);
        ipv6.sp = dp;
        ipv6.dp = sp;
    }
    ipv6.proto = f->proto;
    ipv6.pad0 = 0;

    uint8_t hash[20];
    if (SCSha1HashBuffer((const uint8_t *)&ipv6, sizeof(ipv6), hash, sizeof(hash)) == 1) {
        strlcpy((char *)base64buf, "1:", COMMUNITY_ID_BUF_SIZE);
        unsigned long out_len = COMMUNITY_ID_BUF_SIZE - 2;
        if (Base64Encode(hash, sizeof(hash), base64buf+2, &out_len) == SC_BASE64_OK) {
            return true;
        }
    }
    return false;
}

static void CreateEveCommunityFlowId(JsonBuilder *js, const Flow *f, const uint16_t seed)
{
    unsigned char buf[COMMUNITY_ID_BUF_SIZE];
    if (f->flags & FLOW_IPV4) {
        if (CalculateCommunityFlowIdv4(f, seed, buf)) {
            jb_set_string(js, "community_id", (const char *)buf);
        }
    } else if (f->flags & FLOW_IPV6) {
        if (CalculateCommunityFlowIdv6(f, seed, buf)) {
            jb_set_string(js, "community_id", (const char *)buf);
        }
    }
}

void CreateEveFlowId(JsonBuilder *js, const Flow *f)
{
    if (f == NULL) {
        return;
    }
    int64_t flow_id = FlowGetId(f);
    jb_set_uint(js, "flow_id", flow_id);
    if (f->parent_id) {
        jb_set_uint(js, "parent_id", f->parent_id);
    }
}

void JSONFormatAndAddMACAddr(JsonBuilder *js, const char *key, const uint8_t *val, bool is_array)
{
    char eth_addr[19];
    (void) snprintf(eth_addr, 19, "%02x:%02x:%02x:%02x:%02x:%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);
    if (is_array) {
        jb_append_string(js, eth_addr);
    } else {
        jb_set_string(js, key, eth_addr);
    }
}

/* only required to traverse the MAC address set */
typedef struct JSONMACAddrInfo {
    JsonBuilder *src, *dst;
} JSONMACAddrInfo;

static int MacSetIterateToJSON(uint8_t *val, MacSetSide side, void *data)
{
    JSONMACAddrInfo *info = (JSONMACAddrInfo*) data;
    if (side == MAC_SET_DST) {
        JSONFormatAndAddMACAddr(info->dst, NULL, val, true);
    } else {
        JSONFormatAndAddMACAddr(info->src, NULL, val, true);
    }
    return 0;
}

static int CreateJSONEther(
        JsonBuilder *js, const Packet *p, const Flow *f, enum OutputJsonLogDirection dir)
{
    if (p != NULL) {
        /* this is a packet context, so we need to add scalar fields */
        if (PacketIsEthernet(p)) {
            const EthernetHdr *ethh = PacketGetEthernet(p);
            jb_open_object(js, "ether");
            const uint8_t *src;
            const uint8_t *dst;
            switch (dir) {
                case LOG_DIR_FLOW_TOSERVER:
                    // fallthrough
                case LOG_DIR_FLOW:
                    if (PKT_IS_TOCLIENT(p)) {
                        src = ethh->eth_dst;
                        dst = ethh->eth_src;
                    } else {
                        src = ethh->eth_src;
                        dst = ethh->eth_dst;
                    }
                    break;
                case LOG_DIR_FLOW_TOCLIENT:
                    if (PKT_IS_TOSERVER(p)) {
                        src = ethh->eth_dst;
                        dst = ethh->eth_src;
                    } else {
                        src = ethh->eth_src;
                        dst = ethh->eth_dst;
                    }
                    break;
                case LOG_DIR_PACKET:
                default:
                    src = ethh->eth_src;
                    dst = ethh->eth_dst;
                    break;
            }
            JSONFormatAndAddMACAddr(js, "src_mac", src, false);
            JSONFormatAndAddMACAddr(js, "dest_mac", dst, false);
            jb_close(js);
        }
    } else if (f != NULL) {
        /* we are creating an ether object in a flow context, so we need to
           append to arrays */
        MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
        if (ms != NULL && MacSetSize(ms) > 0) {
            jb_open_object(js, "ether");
            JSONMACAddrInfo info;
            info.dst = jb_new_array();
            info.src = jb_new_array();
            int ret = MacSetForEach(ms, MacSetIterateToJSON, &info);
            if (unlikely(ret != 0)) {
                /* should not happen, JSONFlowAppendMACAddrs is sane */
                jb_free(info.dst);
                jb_free(info.src);
                jb_close(js);
                return ret;
            }
            jb_close(info.dst);
            jb_close(info.src);
            /* case is handling netflow too so may need to revert */
            if (dir == LOG_DIR_FLOW_TOCLIENT) {
                jb_set_object(js, "dest_macs", info.src);
                jb_set_object(js, "src_macs", info.dst);
            } else {
                DEBUG_VALIDATE_BUG_ON(dir != LOG_DIR_FLOW_TOSERVER && dir != LOG_DIR_FLOW);
                jb_set_object(js, "dest_macs", info.dst);
                jb_set_object(js, "src_macs", info.src);
            }
            jb_free(info.dst);
            jb_free(info.src);
            jb_close(js);
        }
    }
    return 0;
}

JsonBuilder *CreateEveHeader(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx)
{
    char timebuf[64];
    const Flow *f = (const Flow *)p->flow;

    JsonBuilder *js = jb_new_object();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf));

    jb_set_string(js, "timestamp", timebuf);

    CreateEveFlowId(js, f);

    /* sensor id */
    if (sensor_id >= 0) {
        jb_set_uint(js, "sensor_id", sensor_id);
    }

    /* input interface */
    if (p->livedev) {
        jb_set_string(js, "in_iface", p->livedev->dev);
    }

    /* pcap_cnt */
    if (p->pcap_cnt != 0) {
        jb_set_uint(js, "pcap_cnt", p->pcap_cnt);
    }

    if (event_type) {
        jb_set_string(js, "event_type", event_type);
    }

    /* vlan */
    if (p->vlan_idx > 0) {
        jb_open_array(js, "vlan");
        jb_append_uint(js, p->vlan_id[0]);
        if (p->vlan_idx > 1) {
            jb_append_uint(js, p->vlan_id[1]);
        }
        if (p->vlan_idx > 2) {
            jb_append_uint(js, p->vlan_id[2]);
        }
        jb_close(js);
    }

    /* 5-tuple */
    JsonAddrInfo addr_info = json_addr_info_zero;
    if (addr == NULL) {
        JsonAddrInfoInit(p, dir, &addr_info);
        addr = &addr_info;
    }
    if (addr->src_ip[0] != '\0') {
        jb_set_string(js, "src_ip", addr->src_ip);
    }
    if (addr->log_port) {
        jb_set_uint(js, "src_port", addr->sp);
    }
    if (addr->dst_ip[0] != '\0') {
        jb_set_string(js, "dest_ip", addr->dst_ip);
    }
    if (addr->log_port) {
        jb_set_uint(js, "dest_port", addr->dp);
    }
    if (addr->proto[0] != '\0') {
        jb_set_string(js, "proto", addr->proto);
    }

    /* icmp */
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (PacketIsICMPv4(p)) {
                jb_set_uint(js, "icmp_type", p->icmp_s.type);
                jb_set_uint(js, "icmp_code", p->icmp_s.code);
            }
            break;
        case IPPROTO_ICMPV6:
            if (PacketIsICMPv6(p)) {
                jb_set_uint(js, "icmp_type", PacketGetICMPv6(p)->type);
                jb_set_uint(js, "icmp_code", PacketGetICMPv6(p)->code);
            }
            break;
    }

    jb_set_string(js, "pkt_src", PktSrcToString(p->pkt_src));

    if (eve_ctx != NULL) {
        EveAddCommonOptions(&eve_ctx->cfg, p, f, js, dir);
    }

    return js;
}

JsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx)
{
    JsonBuilder *js = CreateEveHeader(p, dir, event_type, addr, eve_ctx);
    if (unlikely(js == NULL))
        return NULL;

    /* tx id for correlation with other events */
    jb_set_uint(js, "tx_id", tx_id);

    return js;
}

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data)
{
    OutputJSONMemBufferWrapper *wrapper = data;
    MemBuffer **memb = wrapper->buffer;

    if (MEMBUFFER_OFFSET(*memb) + size >= MEMBUFFER_SIZE(*memb)) {
        MemBufferExpand(memb, wrapper->expand_by);
    }

    DEBUG_VALIDATE_BUG_ON(size > UINT32_MAX);
    MemBufferWriteRaw((*memb), (const uint8_t *)str, (uint32_t)size);
    return 0;
}

int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer)
{
    if (file_ctx->sensor_name) {
        json_object_set_new(js, "host",
                            json_string(file_ctx->sensor_name));
    }

    if (file_ctx->is_pcap_offline) {
        json_object_set_new(js, "pcap_filename", json_string(PcapFileGetFilename()));
    }

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), (const uint8_t *)file_ctx->prefix, file_ctx->prefix_len);
    }

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = buffer,
        .expand_by = JSON_OUTPUT_BUFFER_SIZE
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            file_ctx->json_flags);
    if (r != 0)
        return TM_ECODE_OK;

    LogFileWrite(file_ctx, *buffer);
    return 0;
}

int OutputJsonBuilderBuffer(JsonBuilder *js, OutputJsonThreadCtx *ctx)
{
    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;
    if (file_ctx->sensor_name) {
        jb_set_string(js, "host", file_ctx->sensor_name);
    }

    if (file_ctx->is_pcap_offline) {
        jb_set_string(js, "pcap_filename", PcapFileGetFilename());
    }

    jb_close(js);

    MemBufferReset(*buffer);

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), (const uint8_t *)file_ctx->prefix, file_ctx->prefix_len);
    }

    size_t jslen = jb_len(js);
    DEBUG_VALIDATE_BUG_ON(jb_len(js) > UINT32_MAX);
    if (MEMBUFFER_OFFSET(*buffer) + jslen >= MEMBUFFER_SIZE(*buffer)) {
        MemBufferExpand(buffer, (uint32_t)jslen);
    }

    MemBufferWriteRaw((*buffer), jb_ptr(js), (uint32_t)jslen);
    LogFileWrite(file_ctx, *buffer);

    return 0;
}

static inline enum LogFileType FileTypeFromConf(const char *typestr)
{
    enum LogFileType log_filetype = LOGFILE_TYPE_NOTSET;

    if (typestr == NULL) {
        log_filetype = LOGFILE_TYPE_FILE;
    } else if (strcmp(typestr, "file") == 0 || strcmp(typestr, "regular") == 0) {
        log_filetype = LOGFILE_TYPE_FILE;
    } else if (strcmp(typestr, "unix_dgram") == 0) {
        log_filetype = LOGFILE_TYPE_UNIX_DGRAM;
    } else if (strcmp(typestr, "unix_stream") == 0) {
        log_filetype = LOGFILE_TYPE_UNIX_STREAM;
    } else if (strcmp(typestr, "redis") == 0) {
#ifdef HAVE_LIBHIREDIS
        log_filetype = LOGFILE_TYPE_REDIS;
#else
        FatalError("redis JSON output option is not compiled");
#endif
    }
    SCLogDebug("type %s, file type value %d", typestr, log_filetype);
    return log_filetype;
}

static int LogFileTypePrepare(
        OutputJsonCtx *json_ctx, enum LogFileType log_filetype, ConfNode *conf)
{

    if (log_filetype == LOGFILE_TYPE_FILE || log_filetype == LOGFILE_TYPE_UNIX_DGRAM ||
            log_filetype == LOGFILE_TYPE_UNIX_STREAM) {
        if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
            return -1;
        }
        OutputRegisterFileRotationFlag(&json_ctx->file_ctx->rotation_flag);
    }
#ifdef HAVE_LIBHIREDIS
    else if (log_filetype == LOGFILE_TYPE_REDIS) {
        SCLogRedisInit();
        ConfNode *redis_node = ConfNodeLookupChild(conf, "redis");
        if (!json_ctx->file_ctx->sensor_name) {
            char hostname[1024];
            gethostname(hostname, 1023);
            json_ctx->file_ctx->sensor_name = SCStrdup(hostname);
        }
        if (json_ctx->file_ctx->sensor_name == NULL) {
            return -1;
        }

        if (SCConfLogOpenRedis(redis_node, json_ctx->file_ctx) < 0) {
            return -1;
        }
    }
#endif
    else if (log_filetype == LOGFILE_TYPE_FILETYPE) {
        if (json_ctx->file_ctx->threaded) {
            /* Prepare for threaded log output. */
            if (!SCLogOpenThreadedFile(NULL, NULL, json_ctx->file_ctx)) {
                return -1;
            }
        }
        if (json_ctx->filetype->Init(conf, json_ctx->file_ctx->threaded,
                    &json_ctx->file_ctx->filetype.init_data) < 0) {
            return -1;
        }
        if (json_ctx->filetype->ThreadInit) {
            if (json_ctx->filetype->ThreadInit(json_ctx->file_ctx->filetype.init_data, 0,
                        &json_ctx->file_ctx->filetype.thread_data) < 0) {
                return -1;
            }
        }
        json_ctx->file_ctx->filetype.filetype = json_ctx->filetype;
    }

    return 0;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputInitResult OutputJsonInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    OutputCtx *output_ctx = NULL;

    OutputJsonCtx *json_ctx = SCCalloc(1, sizeof(OutputJsonCtx));
    if (unlikely(json_ctx == NULL)) {
        SCLogDebug("could not create new OutputJsonCtx");
        return result;
    }

    /* First lookup a sensor-name value in this outputs configuration
     * node (deprecated). If that fails, lookup the global one. */
    const char *sensor_name = ConfNodeLookupChildValue(conf, "sensor-name");
    if (sensor_name != NULL) {
        SCLogWarning("Found deprecated eve-log setting \"sensor-name\". "
                     "Please set sensor-name globally.");
    }
    else {
        (void)ConfGet("sensor-name", &sensor_name);
    }

    json_ctx->file_ctx = LogFileNewCtx();
    if (unlikely(json_ctx->file_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        goto error_exit;
    }

    if (sensor_name) {
        json_ctx->file_ctx->sensor_name = SCStrdup(sensor_name);
        if (json_ctx->file_ctx->sensor_name == NULL) {
            goto error_exit;
        }
    } else {
        json_ctx->file_ctx->sensor_name = NULL;
    }

    output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto error_exit;
    }

    output_ctx->data = json_ctx;
    output_ctx->DeInit = OutputJsonDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "filetype");
        // Backwards compatibility
        if (output_s == NULL) {
            output_s = ConfNodeLookupChildValue(conf, "type");
        }

        enum LogFileType log_filetype = FileTypeFromConf(output_s);
        if (log_filetype == LOGFILE_TYPE_NOTSET) {
            SCEveFileType *filetype = SCEveFindFileType(output_s);
            if (filetype != NULL) {
                log_filetype = LOGFILE_TYPE_FILETYPE;
                json_ctx->filetype = filetype;
            } else
                FatalError("Invalid JSON output option: %s", output_s);
        }

        const char *prefix = ConfNodeLookupChildValue(conf, "prefix");
        if (prefix != NULL)
        {
            SCLogInfo("Using prefix '%s' for JSON messages", prefix);
            json_ctx->file_ctx->prefix = SCStrdup(prefix);
            if (json_ctx->file_ctx->prefix == NULL)
            {
                FatalError("Failed to allocate memory for eve-log.prefix setting.");
            }
            json_ctx->file_ctx->prefix_len = (uint32_t)strlen(prefix);
        }

        /* Threaded file output */
        const ConfNode *threaded = ConfNodeLookupChild(conf, "threaded");
        if (threaded && threaded->val && ConfValIsTrue(threaded->val)) {
            SCLogConfig("Threaded EVE logging configured");
            json_ctx->file_ctx->threaded = true;
        } else {
            json_ctx->file_ctx->threaded = false;
        }
        if (LogFileTypePrepare(json_ctx, log_filetype, conf) < 0) {
            goto error_exit;
        }

        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (StringParseUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) < 0) {
                FatalError("Failed to initialize JSON output, "
                           "invalid sensor-id: %s",
                        sensor_id_s);
            }
        }

        /* Check if top-level metadata should be logged. */
        const ConfNode *metadata = ConfNodeLookupChild(conf, "metadata");
        if (metadata && metadata->val && ConfValIsFalse(metadata->val)) {
            SCLogConfig("Disabling eve metadata logging.");
            json_ctx->cfg.include_metadata = false;
        } else {
            json_ctx->cfg.include_metadata = true;
        }

        /* Check if ethernet information should be logged. */
        const ConfNode *ethernet = ConfNodeLookupChild(conf, "ethernet");
        if (ethernet && ethernet->val && ConfValIsTrue(ethernet->val)) {
            SCLogConfig("Enabling Ethernet MAC address logging.");
            json_ctx->cfg.include_ethernet = true;
        } else {
            json_ctx->cfg.include_ethernet = false;
        }

        /* See if we want to enable the community id */
        const ConfNode *community_id = ConfNodeLookupChild(conf, "community-id");
        if (community_id && community_id->val && ConfValIsTrue(community_id->val)) {
            SCLogConfig("Enabling eve community_id logging.");
            json_ctx->cfg.include_community_id = true;
        } else {
            json_ctx->cfg.include_community_id = false;
        }
        const char *cid_seed = ConfNodeLookupChildValue(conf, "community-id-seed");
        if (cid_seed != NULL) {
            if (StringParseUint16(&json_ctx->cfg.community_id_seed,
                        10, 0, cid_seed) < 0)
            {
                FatalError("Failed to initialize JSON output, "
                           "invalid community-id-seed: %s",
                        cid_seed);
            }
        }

        /* Do we have a global eve xff configuration? */
        const ConfNode *xff = ConfNodeLookupChild(conf, "xff");
        if (xff != NULL) {
            json_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
            if (likely(json_ctx->xff_cfg != NULL)) {
                HttpXFFGetCfg(conf, json_ctx->xff_cfg);
            }
        }

        const char *pcapfile_s = ConfNodeLookupChildValue(conf, "pcap-file");
        if (pcapfile_s != NULL && ConfValIsTrue(pcapfile_s)) {
            json_ctx->file_ctx->is_pcap_offline =
                    (SCRunmodeGet() == RUNMODE_PCAP_FILE || SCRunmodeGet() == RUNMODE_UNIX_SOCKET);
        }
        json_ctx->file_ctx->type = log_filetype;
    }

    SCLogDebug("returning output_ctx %p", output_ctx);

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error_exit:
    if (json_ctx->file_ctx) {
        if (json_ctx->file_ctx->prefix) {
            SCFree(json_ctx->file_ctx->prefix);
        }
        LogFileFreeCtx(json_ctx->file_ctx);
    }
    SCFree(json_ctx);

    if (output_ctx) {
        SCFree(output_ctx);
    }
    return result;
}

static void OutputJsonDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonCtx *json_ctx = (OutputJsonCtx *)output_ctx->data;
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    if (logfile_ctx->dropped) {
        SCLogWarning("%" PRIu64 " events were dropped due to slow or "
                     "disconnected socket",
                logfile_ctx->dropped);
    }
    if (json_ctx->xff_cfg != NULL) {
        SCFree(json_ctx->xff_cfg);
    }
    LogFileFreeCtx(logfile_ctx);
    SCFree(json_ctx);
    SCFree(output_ctx);
}
