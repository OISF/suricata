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
#include "util-device-private.h"
#include "util-validate.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "flow-storage.h"

#include "source-pcap-file-helper.h"

#define DEFAULT_LOG_FILENAME "eve.json"
#define MODULE_NAME "OutputJSON"

#define MAX_JSON_SIZE 2048

static void OutputJsonDeInitCtx(OutputCtx *);
static void CreateEveCommunityFlowId(SCJsonBuilder *js, const Flow *f, const uint16_t seed);
static int CreateJSONEther(
        SCJsonBuilder *parent, const Packet *p, const Flow *f, enum SCOutputJsonLogDirection dir);

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

void EveFileInfo(SCJsonBuilder *jb, const File *ff, const uint64_t tx_id, const uint16_t flags)
{
    SCJbSetStringFromBytes(jb, "filename", ff->name, ff->name_len);

    if (ff->sid_cnt > 0) {
        SCJbOpenArray(jb, "sid");
        for (uint32_t i = 0; ff->sid != NULL && i < ff->sid_cnt; i++) {
            SCJbAppendUint(jb, ff->sid[i]);
        }
        SCJbClose(jb);
    }

#ifdef HAVE_MAGIC
    if (ff->magic)
        SCJbSetString(jb, "magic", (char *)ff->magic);
#endif
    SCJbSetBool(jb, "gaps", ff->flags & FILE_HAS_GAPS);
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            JB_SET_STRING(jb, "state", "CLOSED");
            if (ff->flags & FILE_MD5) {
                SCJbSetHex(jb, "md5", (uint8_t *)ff->md5, (uint32_t)sizeof(ff->md5));
            }
            if (ff->flags & FILE_SHA1) {
                SCJbSetHex(jb, "sha1", (uint8_t *)ff->sha1, (uint32_t)sizeof(ff->sha1));
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
        SCJbSetHex(jb, "sha256", (uint8_t *)ff->sha256, (uint32_t)sizeof(ff->sha256));
    }

    if (flags & FILE_STORED) {
        JB_SET_TRUE(jb, "stored");
        SCJbSetUint(jb, "file_id", ff->file_store_id);
    } else {
        JB_SET_FALSE(jb, "stored");
        if (flags & FILE_STORE) {
            JB_SET_TRUE(jb, "storing");
        }
    }

    SCJbSetUint(jb, "size", FileTrackedSize(ff));
    if (ff->end > 0) {
        SCJbSetUint(jb, "start", ff->start);
        SCJbSetUint(jb, "end", ff->end);
    }
    SCJbSetUint(jb, "tx_id", tx_id);
}

static void EveAddPacketVars(const Packet *p, SCJsonBuilder *js_vars)
{
    if (p == NULL || p->pktvar == NULL) {
        return;
    }
    PktVar *pv = p->pktvar;
    bool open = false;
    while (pv != NULL) {
        if (pv->key || pv->id > 0) {
            if (!open) {
                SCJbOpenArray(js_vars, "pktvars");
                open = true;
            }
            SCJbStartObject(js_vars);

            if (pv->key != NULL) {
                uint32_t offset = 0;
                uint8_t keybuf[pv->key_len + 1];
                PrintStringsToBuffer(keybuf, &offset, pv->key_len + 1, pv->key, pv->key_len);
                SCJbSetPrintAsciiString(js_vars, (char *)keybuf, pv->value, pv->value_len);
            } else {
                const char *varname = VarNameStoreLookupById(pv->id, VAR_TYPE_PKT_VAR);
                SCJbSetPrintAsciiString(js_vars, varname, pv->value, pv->value_len);
            }
            SCJbClose(js_vars);
        }
        pv = pv->next;
    }
    if (open) {
        SCJbClose(js_vars);
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

static void EveAddFlowVars(const Flow *f, SCJsonBuilder *js_root, SCJsonBuilder **js_traffic)
{
    if (f == NULL || f->flowvar == NULL) {
        return;
    }
    SCJsonBuilder *js_flowvars = NULL;
    SCJsonBuilder *js_traffic_id = NULL;
    SCJsonBuilder *js_traffic_label = NULL;
    SCJsonBuilder *js_flowints = NULL;
    SCJsonBuilder *js_entropyvals = NULL;
    SCJsonBuilder *js_flowbits = NULL;
    GenericVar *gv = f->flowvar;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *)gv;
            if (fv->datatype == FLOWVAR_TYPE_STR && fv->key == NULL) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_VAR);
                if (varname) {
                    if (js_flowvars == NULL) {
                        js_flowvars = SCJbNewArray();
                        if (js_flowvars == NULL)
                            break;
                    }

                    SCJbStartObject(js_flowvars);
                    SCJbSetPrintAsciiString(
                            js_flowvars, varname, fv->data.fv_str.value, fv->data.fv_str.value_len);
                    SCJbClose(js_flowvars);
                }
            } else if (fv->datatype == FLOWVAR_TYPE_STR && fv->key != NULL) {
                if (js_flowvars == NULL) {
                    js_flowvars = SCJbNewArray();
                    if (js_flowvars == NULL)
                        break;
                }

                uint8_t keybuf[fv->keylen + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(keybuf, &offset, fv->keylen + 1, fv->key, fv->keylen);

                SCJbStartObject(js_flowvars);
                SCJbSetPrintAsciiString(js_flowvars, (const char *)keybuf, fv->data.fv_str.value,
                        fv->data.fv_str.value_len);
                SCJbClose(js_flowvars);
            } else if (fv->datatype == FLOWVAR_TYPE_FLOAT) {
                const char *varname = VarNameStoreLookupById(fv->idx, VAR_TYPE_FLOW_FLOAT);
                if (varname) {
                    if (js_entropyvals == NULL) {
                        js_entropyvals = SCJbNewObject();
                        if (js_entropyvals == NULL)
                            break;
                    }
                    SCJbSetFloat(js_entropyvals, varname, fv->data.fv_float.value);
                }

            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_INT);
                if (varname) {
                    if (js_flowints == NULL) {
                        js_flowints = SCJbNewObject();
                        if (js_flowints == NULL)
                            break;
                    }
                    SCJbSetUint(js_flowints, varname, fv->data.fv_int.value);
                }
            }
        } else if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *)gv;
            const char *varname = VarNameStoreLookupById(fb->idx,
                    VAR_TYPE_FLOW_BIT);
            if (varname) {
                if (SCStringHasPrefix(varname, TRAFFIC_ID_PREFIX)) {
                    if (js_traffic_id == NULL) {
                        js_traffic_id = SCJbNewArray();
                        if (unlikely(js_traffic_id == NULL)) {
                            break;
                        }
                    }
                    SCJbAppendString(js_traffic_id, &varname[traffic_id_prefix_len]);
                } else if (SCStringHasPrefix(varname, TRAFFIC_LABEL_PREFIX)) {
                    if (js_traffic_label == NULL) {
                        js_traffic_label = SCJbNewArray();
                        if (unlikely(js_traffic_label == NULL)) {
                            break;
                        }
                    }
                    SCJbAppendString(js_traffic_label, &varname[traffic_label_prefix_len]);
                } else {
                    if (js_flowbits == NULL) {
                        js_flowbits = SCJbNewArray();
                        if (unlikely(js_flowbits == NULL))
                            break;
                    }
                    SCJbAppendString(js_flowbits, varname);
                }
            }
        }
        gv = gv->next;
    }
    if (js_flowbits) {
        SCJbClose(js_flowbits);
        SCJbSetObject(js_root, "flowbits", js_flowbits);
        SCJbFree(js_flowbits);
    }
    if (js_flowints) {
        SCJbClose(js_flowints);
        SCJbSetObject(js_root, "flowints", js_flowints);
        SCJbFree(js_flowints);
    }
    if (js_entropyvals) {
        SCJbClose(js_entropyvals);
        SCJbSetObject(js_root, "entropy", js_entropyvals);
        SCJbFree(js_entropyvals);
    }
    if (js_flowvars) {
        SCJbClose(js_flowvars);
        SCJbSetObject(js_root, "flowvars", js_flowvars);
        SCJbFree(js_flowvars);
    }

    if (js_traffic_id != NULL || js_traffic_label != NULL) {
        *js_traffic = SCJbNewObject();
        if (likely(*js_traffic != NULL)) {
            if (js_traffic_id != NULL) {
                SCJbClose(js_traffic_id);
                SCJbSetObject(*js_traffic, "id", js_traffic_id);
                SCJbFree(js_traffic_id);
            }
            if (js_traffic_label != NULL) {
                SCJbClose(js_traffic_label);
                SCJbSetObject(*js_traffic, "label", js_traffic_label);
                SCJbFree(js_traffic_label);
            }
            SCJbClose(*js_traffic);
        }
    }
}

void EveAddMetadata(const Packet *p, const Flow *f, SCJsonBuilder *js)
{
    if ((p && p->pktvar) || (f && f->flowvar)) {
        SCJsonBuilder *js_vars = SCJbNewObject();
        if (js_vars) {
            if (f && f->flowvar) {
                SCJsonBuilder *js_traffic = NULL;
                EveAddFlowVars(f, js_vars, &js_traffic);
                if (js_traffic != NULL) {
                    SCJbSetObject(js, "traffic", js_traffic);
                    SCJbFree(js_traffic);
                }
            }
            if (p && p->pktvar) {
                EveAddPacketVars(p, js_vars);
            }
            SCJbClose(js_vars);
            SCJbSetObject(js, "metadata", js_vars);
            SCJbFree(js_vars);
        }
    }
}

void EveAddCommonOptions(const OutputJsonCommonSettings *cfg, const Packet *p, const Flow *f,
        SCJsonBuilder *js, enum SCOutputJsonLogDirection dir)
{
    if (cfg->include_suricata_version) {
        SCJbSetString(js, "suricata_version", PROG_VER);
    }
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
        SCJbSetUint(js, "tenant_id", f->tenant_id);
    }
}

/**
 * \brief Jsonify a packet
 *
 * \param p Packet
 * \param js JSON object
 * \param max_length If non-zero, restricts the number of packet data bytes handled.
 */
void EvePacket(const Packet *p, SCJsonBuilder *js, uint32_t max_length)
{
    uint32_t max_len = max_length == 0 ? GET_PKT_LEN(p) : max_length;
    SCJbSetBase64(js, "packet", GET_PKT_DATA(p), max_len);

    if (!SCJbOpenObject(js, "packet_info")) {
        return;
    }
    if (!SCJbSetUint(js, "linktype", p->datalink)) {
        SCJbClose(js);
        return;
    }

    const char *dl_name = DatalinkValueToName(p->datalink);

    // Intentionally ignore the return value from SCJbSetString and proceed
    // so the jb object is closed
    (void)SCJbSetString(js, "linktype_name", dl_name == NULL ? "n/a" : dl_name);

    SCJbClose(js);
}

/** \brief jsonify tcp flags field
 *  Only add 'true' fields in an attempt to keep things reasonably compact.
 */
void EveTcpFlags(const uint8_t flags, SCJsonBuilder *js)
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

void JsonAddrInfoInit(const Packet *p, enum SCOutputJsonLogDirection dir, JsonAddrInfo *addr)
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
    if (ntohl(src) < ntohl(dst) || (src == dst && ntohs(sp) < ntohs(dp))) {
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
        if (SCBase64Encode(hash, sizeof(hash), base64buf + 2, &out_len) == SC_BASE64_OK) {
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
    if ((cmp_r < 0) || (cmp_r == 0 && ntohs(sp) < ntohs(dp))) {
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
        if (SCBase64Encode(hash, sizeof(hash), base64buf + 2, &out_len) == SC_BASE64_OK) {
            return true;
        }
    }
    return false;
}

static void CreateEveCommunityFlowId(SCJsonBuilder *js, const Flow *f, const uint16_t seed)
{
    unsigned char buf[COMMUNITY_ID_BUF_SIZE];
    if (f->flags & FLOW_IPV4) {
        if (CalculateCommunityFlowIdv4(f, seed, buf)) {
            SCJbSetString(js, "community_id", (const char *)buf);
        }
    } else if (f->flags & FLOW_IPV6) {
        if (CalculateCommunityFlowIdv6(f, seed, buf)) {
            SCJbSetString(js, "community_id", (const char *)buf);
        }
    }
}

void CreateEveFlowId(SCJsonBuilder *js, const Flow *f)
{
    if (f == NULL) {
        return;
    }
    uint64_t flow_id = FlowGetId(f);
    SCJbSetUint(js, "flow_id", flow_id);
    if (f->parent_id) {
        SCJbSetUint(js, "parent_id", f->parent_id);
    }
}

void JSONFormatAndAddMACAddr(SCJsonBuilder *js, const char *key, const uint8_t *val, bool is_array)
{
    char eth_addr[19];
    (void) snprintf(eth_addr, 19, "%02x:%02x:%02x:%02x:%02x:%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);
    if (is_array) {
        SCJbAppendString(js, eth_addr);
    } else {
        SCJbSetString(js, key, eth_addr);
    }
}

/* only required to traverse the MAC address set */
typedef struct JSONMACAddrInfo {
    SCJsonBuilder *src, *dst;
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
        SCJsonBuilder *js, const Packet *p, const Flow *f, enum SCOutputJsonLogDirection dir)
{
    if (p != NULL) {
        /* this is a packet context, so we need to add scalar fields */
        if (PacketIsEthernet(p)) {
            const EthernetHdr *ethh = PacketGetEthernet(p);
            SCJbOpenObject(js, "ether");
            SCJbSetUint(js, "ether_type", SCNtohs(ethh->eth_type));
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
            SCJbClose(js);
        } else if (f != NULL) {
            /* When pseudopackets do not have associated ethernet metadata,
               use the first set of mac addresses stored with their flow.
               The first set of macs should come from the flow's first packet,
               providing the most fitting representation of the event's ethernet. */
            MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
            if (ms != NULL && MacSetSize(ms) > 0) {
                uint8_t *src = MacSetGetFirst(ms, MAC_SET_SRC);
                uint8_t *dst = MacSetGetFirst(ms, MAC_SET_DST);
                if (dst != NULL && src != NULL) {
                    SCJbOpenObject(js, "ether");
                    JSONFormatAndAddMACAddr(js, "src_mac", src, false);
                    JSONFormatAndAddMACAddr(js, "dest_mac", dst, false);
                    SCJbClose(js);
                }
            }
        }
    } else if (f != NULL) {
        /* we are creating an ether object in a flow context, so we need to
           append to arrays */
        MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
        if (ms != NULL && MacSetSize(ms) > 0) {
            SCJbOpenObject(js, "ether");
            JSONMACAddrInfo info;
            info.dst = SCJbNewArray();
            info.src = SCJbNewArray();
            int ret = MacSetForEach(ms, MacSetIterateToJSON, &info);
            if (unlikely(ret != 0)) {
                /* should not happen, JSONFlowAppendMACAddrs is sane */
                SCJbFree(info.dst);
                SCJbFree(info.src);
                SCJbClose(js);
                return ret;
            }
            SCJbClose(info.dst);
            SCJbClose(info.src);
            /* case is handling netflow too so may need to revert */
            if (dir == LOG_DIR_FLOW_TOCLIENT) {
                SCJbSetObject(js, "dest_macs", info.src);
                SCJbSetObject(js, "src_macs", info.dst);
            } else {
                DEBUG_VALIDATE_BUG_ON(dir != LOG_DIR_FLOW_TOSERVER && dir != LOG_DIR_FLOW);
                SCJbSetObject(js, "dest_macs", info.dst);
                SCJbSetObject(js, "src_macs", info.src);
            }
            SCJbFree(info.dst);
            SCJbFree(info.src);
            SCJbClose(js);
        }
    }
    return 0;
}

SCJsonBuilder *CreateEveHeader(const Packet *p, enum SCOutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx)
{
    char timebuf[64];
    const Flow *f = (const Flow *)p->flow;

    SCJsonBuilder *js = SCJbNewObject();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf));

    SCJbSetString(js, "timestamp", timebuf);

    CreateEveFlowId(js, f);

    /* sensor id */
    if (sensor_id >= 0) {
        SCJbSetUint(js, "sensor_id", sensor_id);
    }

    /* input interface */
    if (p->livedev) {
        SCJbSetString(js, "in_iface", p->livedev->dev);
    }

    /* pcap_cnt */
    if (p->pcap_cnt != 0) {
        SCJbSetUint(js, "pcap_cnt", p->pcap_cnt);
    }

    if (event_type) {
        SCJbSetString(js, "event_type", event_type);
    }

    /* vlan */
    if (p->vlan_idx > 0) {
        SCJbOpenArray(js, "vlan");
        SCJbAppendUint(js, p->vlan_id[0]);
        if (p->vlan_idx > 1) {
            SCJbAppendUint(js, p->vlan_id[1]);
        }
        if (p->vlan_idx > 2) {
            SCJbAppendUint(js, p->vlan_id[2]);
        }
        SCJbClose(js);
    }

    /* 5-tuple */
    JsonAddrInfo addr_info = json_addr_info_zero;
    if (addr == NULL) {
        JsonAddrInfoInit(p, dir, &addr_info);
        addr = &addr_info;
    }
    if (addr->src_ip[0] != '\0') {
        SCJbSetString(js, "src_ip", addr->src_ip);
    }
    if (addr->log_port) {
        SCJbSetUint(js, "src_port", addr->sp);
    }
    if (addr->dst_ip[0] != '\0') {
        SCJbSetString(js, "dest_ip", addr->dst_ip);
    }
    if (addr->log_port) {
        SCJbSetUint(js, "dest_port", addr->dp);
    }
    if (addr->proto[0] != '\0') {
        SCJbSetString(js, "proto", addr->proto);
    }

    /* ip version */
    if (PacketIsIPv4(p)) {
        SCJbSetUint(js, "ip_v", 4);
    } else if (PacketIsIPv6(p)) {
        SCJbSetUint(js, "ip_v", 6);
    }

    /* icmp */
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (PacketIsICMPv4(p)) {
                SCJbSetUint(js, "icmp_type", p->icmp_s.type);
                SCJbSetUint(js, "icmp_code", p->icmp_s.code);
            }
            break;
        case IPPROTO_ICMPV6:
            if (PacketIsICMPv6(p)) {
                SCJbSetUint(js, "icmp_type", PacketGetICMPv6(p)->type);
                SCJbSetUint(js, "icmp_code", PacketGetICMPv6(p)->code);
            }
            break;
    }

    SCJbSetString(js, "pkt_src", PktSrcToString(p->pkt_src));

    if (eve_ctx != NULL) {
        EveAddCommonOptions(&eve_ctx->cfg, p, f, js, dir);
    }

    return js;
}

SCJsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum SCOutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx)
{
    SCJsonBuilder *js = CreateEveHeader(p, dir, event_type, addr, eve_ctx);
    if (unlikely(js == NULL))
        return NULL;

    /* tx id for correlation with other events */
    SCJbSetUint(js, "tx_id", tx_id);

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

void OutputJsonFlush(OutputJsonThreadCtx *ctx)
{
    LogFileCtx *file_ctx = ctx->file_ctx;
    LogFileFlush(file_ctx);
}

void OutputJsonBuilderBuffer(
        ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *js, OutputJsonThreadCtx *ctx)
{
    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;
    if (file_ctx->sensor_name) {
        SCJbSetString(js, "host", file_ctx->sensor_name);
    }

    if (file_ctx->is_pcap_offline) {
        SCJbSetString(js, "pcap_filename", PcapFileGetFilename());
    }

    SCEveRunCallbacks(tv, p, f, js);

    SCJbClose(js);

    MemBufferReset(*buffer);

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), (const uint8_t *)file_ctx->prefix, file_ctx->prefix_len);
    }

    size_t jslen = SCJbLen(js);
    DEBUG_VALIDATE_BUG_ON(SCJbLen(js) > UINT32_MAX);
    size_t remaining = MEMBUFFER_SIZE(*buffer) - MEMBUFFER_OFFSET(*buffer);
    if (jslen >= remaining) {
        size_t expand_by = jslen + 1 - remaining;
        if (MemBufferExpand(buffer, (uint32_t)expand_by) < 0) {
            if (!ctx->too_large_warning) {
                /* Log a warning once, and include enough of the log
                 * message to hopefully identify the event_type. */
                char partial[120];
                size_t partial_len = MIN(sizeof(partial), jslen);
                memcpy(partial, SCJbPtr(js), partial_len - 1);
                partial[partial_len - 1] = '\0';
                SCLogWarning("Formatted JSON EVE record too large, will be dropped: %s", partial);
                ctx->too_large_warning = true;
            }
            return;
        }
    }

    MemBufferWriteRaw((*buffer), SCJbPtr(js), (uint32_t)jslen);
    LogFileWrite(file_ctx, *buffer);
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
        OutputJsonCtx *json_ctx, enum LogFileType log_filetype, SCConfNode *conf)
{

    if (log_filetype == LOGFILE_TYPE_FILE || log_filetype == LOGFILE_TYPE_UNIX_DGRAM ||
            log_filetype == LOGFILE_TYPE_UNIX_STREAM) {
        if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
            return -1;
        }
    }
#ifdef HAVE_LIBHIREDIS
    else if (log_filetype == LOGFILE_TYPE_REDIS) {
        SCLogRedisInit();
        SCConfNode *redis_node = SCConfNodeLookupChild(conf, "redis");
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
OutputInitResult OutputJsonInitCtx(SCConfNode *conf)
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
    const char *sensor_name = SCConfNodeLookupChildValue(conf, "sensor-name");
    if (sensor_name != NULL) {
        SCLogWarning("Found deprecated eve-log setting \"sensor-name\". "
                     "Please set sensor-name globally.");
    }
    else {
        (void)SCConfGet("sensor-name", &sensor_name);
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
        const char *output_s = SCConfNodeLookupChildValue(conf, "filetype");
        // Backwards compatibility
        if (output_s == NULL) {
            output_s = SCConfNodeLookupChildValue(conf, "type");
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

        const char *prefix = SCConfNodeLookupChildValue(conf, "prefix");
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
        const SCConfNode *threaded = SCConfNodeLookupChild(conf, "threaded");
        if (threaded && threaded->val && SCConfValIsTrue(threaded->val)) {
            SCLogConfig("Threaded EVE logging configured");
            json_ctx->file_ctx->threaded = true;
        } else {
            json_ctx->file_ctx->threaded = false;
        }
        if (LogFileTypePrepare(json_ctx, log_filetype, conf) < 0) {
            goto error_exit;
        }

        const char *sensor_id_s = SCConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (StringParseUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) < 0) {
                FatalError("Failed to initialize JSON output, "
                           "invalid sensor-id: %s",
                        sensor_id_s);
            }
        }

        /* Check if top-level metadata should be logged. */
        const SCConfNode *metadata = SCConfNodeLookupChild(conf, "metadata");
        if (metadata && metadata->val && SCConfValIsFalse(metadata->val)) {
            SCLogConfig("Disabling eve metadata logging.");
            json_ctx->cfg.include_metadata = false;
        } else {
            json_ctx->cfg.include_metadata = true;
        }

        /* Check if ethernet information should be logged. */
        const SCConfNode *ethernet = SCConfNodeLookupChild(conf, "ethernet");
        if (ethernet && ethernet->val && SCConfValIsTrue(ethernet->val)) {
            SCLogConfig("Enabling Ethernet MAC address logging.");
            json_ctx->cfg.include_ethernet = true;
        } else {
            json_ctx->cfg.include_ethernet = false;
        }

        const SCConfNode *suriver = SCConfNodeLookupChild(conf, "suricata-version");
        if (suriver && suriver->val && SCConfValIsTrue(suriver->val)) {
            SCLogConfig("Enabling Suricata version logging.");
            json_ctx->cfg.include_suricata_version = true;
        } else {
            json_ctx->cfg.include_suricata_version = false;
        }

        /* See if we want to enable the community id */
        const SCConfNode *community_id = SCConfNodeLookupChild(conf, "community-id");
        if (community_id && community_id->val && SCConfValIsTrue(community_id->val)) {
            SCLogConfig("Enabling eve community_id logging.");
            json_ctx->cfg.include_community_id = true;
        } else {
            json_ctx->cfg.include_community_id = false;
        }
        const char *cid_seed = SCConfNodeLookupChildValue(conf, "community-id-seed");
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
        const SCConfNode *xff = SCConfNodeLookupChild(conf, "xff");
        if (xff != NULL) {
            json_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
            if (likely(json_ctx->xff_cfg != NULL)) {
                HttpXFFGetCfg(conf, json_ctx->xff_cfg);
            }
        }

        const char *pcapfile_s = SCConfNodeLookupChildValue(conf, "pcap-file");
        if (pcapfile_s != NULL && SCConfValIsTrue(pcapfile_s)) {
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
