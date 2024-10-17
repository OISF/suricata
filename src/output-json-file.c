/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * Log files we track.
 *
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "app-layer-parser.h"

#include "detect-filemagic.h"

#include "stream.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-atomic.h"
#include "util-file.h"
#include "util-time.h"
#include "util-buffer.h"
#include "util-byte.h"
#include "util-validate.h"

#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-file.h"
#include "output-json-http.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"

#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

typedef struct OutputFileCtx_ {
    uint32_t file_cnt;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} OutputFileCtx;

typedef struct JsonFileLogThread_ {
    OutputFileCtx *filelog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonFileLogThread;

#ifdef HAVE_NDPI

static void ndpiJsonBuilderTLSQUIC(Flow *f, JsonBuilder *js, ThreadVars *tv)
{
    char buf[64];
    char notBefore[32], notAfter[32];
    struct tm a, b, *before = NULL, *after = NULL;
    u_int i, off;
    u_int8_t unknown_tls_version;
    char version[16], unknown_cipher[8];

    if (!f->ndpi_flow->protos.tls_quic.ssl_version) {
        return;
    }

    ndpi_ssl_version2str(version, sizeof(version), f->ndpi_flow->protos.tls_quic.ssl_version,
            &unknown_tls_version);

    if (f->ndpi_flow->protos.tls_quic.notBefore)
        before = ndpi_gmtime_r((const time_t *)&f->ndpi_flow->protos.tls_quic.notBefore, &a);

    if (f->ndpi_flow->protos.tls_quic.notAfter)
        after = ndpi_gmtime_r((const time_t *)&f->ndpi_flow->protos.tls_quic.notAfter, &b);

    if (!unknown_tls_version) {
        jb_open_object(js, "tls");
        jb_set_string(js, "version", version);

        if (f->ndpi_flow->protos.tls_quic.server_names)
            jb_set_string(js, "server_names", f->ndpi_flow->protos.tls_quic.server_names);

        if (before) {
            strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
            jb_set_string(js, "notbefore", notBefore);
        }

        if (after) {
            strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
            jb_set_string(js, "notafter", notAfter);
        }

        /* Note: ja3, ja3s, ja4 are not serialized as as Suricata already supports them */

        jb_set_uint(js, "unsafe_cipher", f->ndpi_flow->protos.tls_quic.server_unsafe_cipher);
        jb_set_string(js, "cipher",
                ndpi_cipher2str(f->ndpi_flow->protos.tls_quic.server_cipher, unknown_cipher));

        if (f->ndpi_flow->protos.tls_quic.issuerDN)
            jb_set_string(js, "issuerDN", f->ndpi_flow->protos.tls_quic.issuerDN);

        if (f->ndpi_flow->protos.tls_quic.subjectDN)
            jb_set_string(js, "subjectDN", f->ndpi_flow->protos.tls_quic.subjectDN);

        if (f->ndpi_flow->protos.tls_quic.advertised_alpns)
            jb_set_string(js, "advertised_alpns", f->ndpi_flow->protos.tls_quic.advertised_alpns);

        if (f->ndpi_flow->protos.tls_quic.negotiated_alpn)
            jb_set_string(js, "negotiated_alpn", f->ndpi_flow->protos.tls_quic.negotiated_alpn);

        if (f->ndpi_flow->protos.tls_quic.tls_supported_versions)
            jb_set_string(js, "tls_supported_versions",
                    f->ndpi_flow->protos.tls_quic.tls_supported_versions);

        if (f->ndpi_flow->protos.tls_quic.sha1_certificate_fingerprint[0] != '\0') {
            for (i = 0, off = 0; i < 20; i++) {
                int rc = ndpi_snprintf(&buf[off], sizeof(buf) - off, "%s%02X", (i > 0) ? ":" : "",
                        f->ndpi_flow->protos.tls_quic.sha1_certificate_fingerprint[i] & 0xFF);
                if (rc <= 0)
                    break;
                else
                    off += rc;
            }
            jb_set_string(js, "fingerprint", buf);
        }

        jb_set_uint(js, "blocks", f->ndpi_flow->l4.tcp.tls.num_tls_blocks);

        jb_close(js);
    }
}

/* Suricata backport of ndpi_dpi2json */
void ndpiJsonBuilder(Flow *f, JsonBuilder *js, ThreadVars *tv)
{
    char buf[64];
    char const *host_server_name;
    char quic_version[16];
    ndpi_protocol l7_protocol;

    if (f == NULL)
        return;

    jb_open_object(js, "ndpi");
    jb_set_string(js, "app_protocol",
            ndpi_get_proto_name(tv->ndpi_struct, f->detected_l7_protocol.proto.app_protocol));
    jb_set_string(js, "master_protocol",
            ndpi_get_proto_name(tv->ndpi_struct, f->detected_l7_protocol.proto.master_protocol));
    jb_set_string(js, "category",
            ndpi_category_get_name(tv->ndpi_struct, f->detected_l7_protocol.category));

    if (f->ndpi_flow->risk) {
        u_int risk_id;

        jb_open_array(js, "risks");

        for (risk_id = 0; risk_id < NDPI_MAX_RISK; risk_id++)
            if (NDPI_ISSET_BIT(f->ndpi_flow->risk, risk_id)) {
                char str[256];
                snprintf(str, sizeof(str), "%s (%s)", ndpi_risk2code(risk_id),
                        ndpi_risk2str(risk_id));
                jb_append_string(js, str);
            }

        jb_close(js);
    } /* risk */

    host_server_name = ndpi_get_flow_info(f->ndpi_flow, &l7_protocol);
    if (host_server_name != NULL) {
        jb_set_string(js, "hostname", host_server_name);
    }

    switch (l7_protocol.proto.master_protocol ? l7_protocol.proto.master_protocol
                                              : l7_protocol.proto.app_protocol) {
        case NDPI_PROTOCOL_IP_ICMP:
            if (f->ndpi_flow->entropy > 0.0f) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%.6f", f->ndpi_flow->entropy);
                jb_set_string(js, "entropy", buf);
            }
            break;
        case NDPI_PROTOCOL_DHCP:
            jb_open_object(js, "dhcp");
            jb_set_string(js, "fingerprint", f->ndpi_flow->protos.dhcp.fingerprint);
            jb_set_string(js, "class_ident", f->ndpi_flow->protos.dhcp.class_ident);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_BITTORRENT: {
            u_int i, j, n = 0;
            char bittorent_hash[sizeof(f->ndpi_flow->protos.bittorrent.hash) * 2 + 1];
            for (i = 0, j = 0; j < sizeof(bittorent_hash) - 1; i++) {
                snprintf(&bittorent_hash[j], sizeof(bittorent_hash) - j, "%02x",
                        f->ndpi_flow->protos.bittorrent.hash[i]);

                j += 2;
                n += f->ndpi_flow->protos.bittorrent.hash[i];
            }
            if (n == 0)
                bittorent_hash[0] = '\0';
            jb_open_object(js, "bittorrent");
            jb_set_string(js, "hash", bittorent_hash);
            jb_close(js);
        } break;
        case NDPI_PROTOCOL_COLLECTD:
            jb_open_object(js, "collectd");
            jb_set_string(js, "client_username", f->ndpi_flow->protos.collectd.client_username);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_DNS:
            jb_open_object(js, "dns");
            jb_set_uint(js, "num_queries", f->ndpi_flow->protos.dns.num_queries);
            jb_set_uint(js, "num_answers", f->ndpi_flow->protos.dns.num_answers);
            jb_set_uint(js, "reply_code", f->ndpi_flow->protos.dns.reply_code);
            jb_set_uint(js, "query_type", f->ndpi_flow->protos.dns.query_type);
            jb_set_uint(js, "rsp_type", f->ndpi_flow->protos.dns.rsp_type);
            inet_ntop(AF_INET, &f->ndpi_flow->protos.dns.rsp_addr, buf, sizeof(buf));
            jb_set_string(js, "rsp_addr", buf);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_NTP:
            jb_open_object(js, "ntp");
            jb_set_uint(js, "request_code", f->ndpi_flow->protos.ntp.request_code);
            jb_set_uint(js, "version", f->ndpi_flow->protos.ntp.request_code);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_MDNS:
            jb_open_object(js, "mdns");
            jb_close(js);
            break;
        case NDPI_PROTOCOL_UBNTAC2:
            jb_open_object(js, "ubntac2");
            jb_set_string(js, "version", f->ndpi_flow->protos.ubntac2.version);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_KERBEROS:
            jb_open_object(js, "kerberos");
            jb_set_string(js, "hostname", f->ndpi_flow->protos.kerberos.hostname);
            jb_set_string(js, "domain", f->ndpi_flow->protos.kerberos.domain);
            jb_set_string(js, "username", f->ndpi_flow->protos.kerberos.username);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_SOFTETHER:
            jb_open_object(js, "softether");
            jb_set_string(js, "client_ip", f->ndpi_flow->protos.softether.ip);
            jb_set_string(js, "client_port", f->ndpi_flow->protos.softether.port);
            jb_set_string(js, "hostname", f->ndpi_flow->protos.softether.hostname);
            jb_set_string(js, "fqdn", f->ndpi_flow->protos.softether.fqdn);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_NATPMP:
            jb_open_object(js, "natpmp");
            jb_set_uint(js, "result", f->ndpi_flow->protos.natpmp.result_code);
            jb_set_uint(js, "internal_port", f->ndpi_flow->protos.natpmp.internal_port);
            jb_set_uint(js, "external_port", f->ndpi_flow->protos.natpmp.external_port);
            inet_ntop(
                    AF_INET, &f->ndpi_flow->protos.natpmp.external_address.ipv4, buf, sizeof(buf));
            jb_set_string(js, "external_address", buf);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_RSH:
            jb_open_object(js, "rsh");
            jb_set_string(js, "client_username", f->ndpi_flow->protos.rsh.client_username);
            jb_set_string(js, "server_username", f->ndpi_flow->protos.rsh.server_username);
            jb_set_string(js, "command", f->ndpi_flow->protos.rsh.command);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_SNMP:
            jb_open_object(js, "snmp");
            jb_set_uint(js, "version", f->ndpi_flow->protos.snmp.version);
            jb_set_uint(js, "primitive", f->ndpi_flow->protos.snmp.primitive);
            jb_set_uint(js, "error_status", f->ndpi_flow->protos.snmp.error_status);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_TELNET:
            jb_open_object(js, "telnet");
            jb_set_string(js, "username", f->ndpi_flow->protos.telnet.username);
            jb_set_string(js, "password", f->ndpi_flow->protos.telnet.password);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_TFTP:
            jb_open_object(js, "tftp");
            jb_set_string(js, "filename", f->ndpi_flow->protos.tftp.filename);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_TIVOCONNECT:
            jb_open_object(js, "tivoconnect");
            jb_set_string(js, "identity_uuid", f->ndpi_flow->protos.tivoconnect.identity_uuid);
            jb_set_string(js, "machine", f->ndpi_flow->protos.tivoconnect.machine);
            jb_set_string(js, "platform", f->ndpi_flow->protos.tivoconnect.platform);
            jb_set_string(js, "services", f->ndpi_flow->protos.tivoconnect.services);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_HTTP:
        case NDPI_PROTOCOL_HTTP_CONNECT:
        case NDPI_PROTOCOL_HTTP_PROXY:
            jb_open_object(js, "http");
            if (f->ndpi_flow->http.url != NULL) {
                jb_set_string(js, "url", f->ndpi_flow->http.url);
                jb_set_uint(js, "code", f->ndpi_flow->http.response_status_code);
                jb_set_string(js, "content_type", f->ndpi_flow->http.content_type);
                jb_set_string(js, "user_agent", f->ndpi_flow->http.user_agent);
            }
            if (f->ndpi_flow->http.request_content_type != NULL) {
                jb_set_string(js, "request_content_type", f->ndpi_flow->http.request_content_type);
            }
            if (f->ndpi_flow->http.detected_os != NULL) {
                jb_set_string(js, "detected_os", f->ndpi_flow->http.detected_os);
            }
            if (f->ndpi_flow->http.nat_ip != NULL) {
                jb_set_string(js, "nat_ip", f->ndpi_flow->http.nat_ip);
            }
            jb_close(js);
            break;
        case NDPI_PROTOCOL_QUIC:
            jb_open_object(js, "quic");
            if (f->ndpi_flow->http.user_agent) {
                jb_set_string(js, "user_agent", f->ndpi_flow->http.user_agent);
            }
            ndpi_quic_version2str(
                    quic_version, sizeof(quic_version), f->ndpi_flow->protos.tls_quic.quic_version);
            jb_set_string(js, "quic_version", quic_version);
            ndpiJsonBuilderTLSQUIC(f, js, tv);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_MAIL_IMAP:
            jb_open_object(js, "imap");
            jb_set_string(js, "user", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
            jb_set_string(js, "password", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
            jb_set_uint(js, "auth_failed", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_MAIL_POP:
            jb_open_object(js, "pop");
            jb_set_string(js, "user", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
            jb_set_string(js, "password", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
            jb_set_uint(js, "auth_failed", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_MAIL_SMTP:
            jb_open_object(js, "smtp");
            jb_set_string(js, "user", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
            jb_set_string(js, "password", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
            jb_set_uint(js, "auth_failed", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_FTP_CONTROL:
            jb_open_object(js, "ftp");
            jb_set_string(js, "user", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
            jb_set_string(js, "password", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
            jb_set_uint(js, "auth_failed", f->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_DISCORD:
            if (l7_protocol.proto.master_protocol != NDPI_PROTOCOL_TLS) {
                jb_open_object(js, "discord");
                jb_set_string(js, "client_ip", f->ndpi_flow->protos.discord.client_ip);
                jb_close(js);
            }
            break;
        case NDPI_PROTOCOL_SSH:
            jb_open_object(js, "ssh");
            jb_set_string(js, "client_signature", f->ndpi_flow->protos.ssh.client_signature);
            jb_set_string(js, "server_signature", f->ndpi_flow->protos.ssh.server_signature);
            jb_set_string(js, "hassh_client", f->ndpi_flow->protos.ssh.hassh_client);
            jb_set_string(js, "hassh_server", f->ndpi_flow->protos.ssh.hassh_server);
            jb_close(js);
            break;
        case NDPI_PROTOCOL_STUN:
            jb_open_object(js, "stun");
            if (f->ndpi_flow->stun.mapped_address.port) {
                jb_set_string(js, "mapped_address",
                        print_ndpi_address_port(
                                &f->ndpi_flow->stun.mapped_address, buf, sizeof(buf)));
            }
            if (f->ndpi_flow->stun.peer_address.port) {
                jb_set_string(js, "peer_address",
                        print_ndpi_address_port(
                                &f->ndpi_flow->stun.peer_address, buf, sizeof(buf)));
            }
            if (f->ndpi_flow->stun.relayed_address.port) {
                jb_set_string(js, "relayed_address",
                        print_ndpi_address_port(
                                &f->ndpi_flow->stun.relayed_address, buf, sizeof(buf)));
            }
            if (f->ndpi_flow->stun.response_origin.port) {
                jb_set_string(js, "response_origin",
                        print_ndpi_address_port(
                                &f->ndpi_flow->stun.response_origin, buf, sizeof(buf)));
            }
            if (f->ndpi_flow->stun.other_address.port) {
                jb_set_string(js, "other_address",
                        print_ndpi_address_port(
                                &f->ndpi_flow->stun.other_address, buf, sizeof(buf)));
            }
            jb_close(js);
            break;
        case NDPI_PROTOCOL_TLS:
        case NDPI_PROTOCOL_DTLS:
            ndpiJsonBuilderTLSQUIC(f, js, tv);
            break;
    } /* switch */

    jb_close(js); // "ndpi"
}

#endif

JsonBuilder *JsonBuildFileInfoRecord(
        const Packet *p, const File *ff, void *tx, const uint64_t tx_id, const bool stored,
        uint8_t dir, HttpXFFCfg *xff_cfg, OutputJsonCtx *eve_ctx
#ifdef HAVE_NDPI
        ,
        ThreadVars *tv
#endif
)
{
    enum OutputJsonLogDirection fdir = LOG_DIR_FLOW;

    switch(dir) {
        case STREAM_TOCLIENT:
            fdir = LOG_DIR_FLOW_TOCLIENT;
            break;
        case STREAM_TOSERVER:
            fdir = LOG_DIR_FLOW_TOSERVER;
            break;
        default:
            DEBUG_VALIDATE_BUG_ON(1);
            break;
    }

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, fdir, &addr);

    /* Overwrite address info with XFF if needed. */
    int have_xff_ip = 0;
    char xff_buffer[XFF_MAXLEN];
    if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED)) {
        if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP1) {
            have_xff_ip = HttpXFFGetIPFromTx(p->flow, tx_id, xff_cfg, xff_buffer, XFF_MAXLEN);
        }
        if (have_xff_ip && xff_cfg->flags & XFF_OVERWRITE) {
            if (p->flowflags & FLOW_PKT_TOCLIENT) {
                strlcpy(addr.dst_ip, xff_buffer, JSON_ADDR_LEN);
            } else {
                strlcpy(addr.src_ip, xff_buffer, JSON_ADDR_LEN);
            }
            have_xff_ip = 0;
        }
    }

    JsonBuilder *js = CreateEveHeader(p, fdir, "fileinfo", &addr, eve_ctx);
    if (unlikely(js == NULL))
        return NULL;

    JsonBuilderMark mark = { 0, 0, 0 };
    EveJsonSimpleAppLayerLogger *al;
    switch (p->flow->alproto) {
        case ALPROTO_HTTP1:
            jb_open_object(js, "http");
            EveHttpAddMetadata(p->flow, tx_id, js);
            jb_close(js);
            break;
        case ALPROTO_SMTP:
            jb_get_mark(js, &mark);
            jb_open_object(js, "smtp");
            if (EveSMTPAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            jb_get_mark(js, &mark);
            jb_open_object(js, "email");
            if (EveEmailAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_NFS:
            /* rpc */
            jb_get_mark(js, &mark);
            jb_open_object(js, "rpc");
            if (EveNFSAddMetadataRPC(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            /* nfs */
            jb_get_mark(js, &mark);
            jb_open_object(js, "nfs");
            if (EveNFSAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_SMB:
            jb_get_mark(js, &mark);
            jb_open_object(js, "smb");
            if (EveSMBAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        default:
            al = SCEveJsonSimpleGetLogger(p->flow->alproto);
            if (al && al->LogTx) {
                void *state = FlowGetAppState(p->flow);
                if (state) {
                    tx = AppLayerParserGetTx(p->flow->proto, p->flow->alproto, state, tx_id);
                    if (tx) {
                        jb_get_mark(js, &mark);
                        if (!al->LogTx(tx, js)) {
                            jb_restore_mark(js, &mark);
                        }
                    }
                }
            }
            break;
    }

    jb_set_string(js, "app_proto", AppProtoToString(p->flow->alproto));

#ifdef HAVE_NDPI
    ndpiJsonBuilder(p->flow, js, tv);
#endif

    jb_open_object(js, "fileinfo");
    if (stored) {
        // the file has just been stored on disk cf OUTPUT_FILEDATA_FLAG_CLOSE
        // but the flag is not set until the loggers have been called
        EveFileInfo(js, ff, tx_id, ff->flags | FILE_STORED);
    } else {
        EveFileInfo(js, ff, tx_id, ff->flags);
    }
    jb_close(js);

    /* xff header */
    if (have_xff_ip && xff_cfg->flags & XFF_EXTRADATA) {
        jb_set_string(js, "xff", xff_buffer);
    }

    return js;
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void FileWriteJsonRecord(JsonFileLogThread *aft, const Packet *p, const File *ff, void *tx,
        const uint64_t tx_id, uint8_t dir, OutputJsonCtx *eve_ctx
#ifdef HAVE_NDPI
        ,
        ThreadVars *tv
#endif
)
{
    HttpXFFCfg *xff_cfg = aft->filelog_ctx->xff_cfg != NULL ? aft->filelog_ctx->xff_cfg
                                                            : aft->filelog_ctx->parent_xff_cfg;
    JsonBuilder *js = JsonBuildFileInfoRecord(p, ff, tx, tx_id, false, dir, xff_cfg, eve_ctx
#ifdef HAVE_NDPI
            ,
            tv
#endif
    );

    if (unlikely(js == NULL)) {
        return;
    }

    OutputJsonBuilderBuffer(js, aft->ctx);
    jb_free(js);
}

static int JsonFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff,
        void *tx, const uint64_t tx_id, uint8_t dir)
{
    SCEnter();
    JsonFileLogThread *aft = (JsonFileLogThread *)thread_data;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    FileWriteJsonRecord(aft, p, ff, tx, tx_id, dir, aft->filelog_ctx->eve_ctx
#ifdef HAVE_NDPI
            ,
            tv
#endif
    );

    return 0;
}


static TmEcode JsonFileLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFileLogThread *aft = SCCalloc(1, sizeof(JsonFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogFile.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->filelog_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->filelog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonFileLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFileLogThread *aft = (JsonFileLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonFileLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputFileLogDeinitSub(OutputCtx *output_ctx)
{
    OutputFileCtx *ff_ctx = output_ctx->data;
    if (ff_ctx->xff_cfg != NULL) {
        SCFree(ff_ctx->xff_cfg);
    }
    SCFree(ff_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputInitResult OutputFileLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputFileCtx *output_file_ctx = SCCalloc(1, sizeof(OutputFileCtx));
    if (unlikely(output_file_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(output_file_ctx);
        return result;
    }

    if (conf) {
        const char *force_filestore = ConfNodeLookupChildValue(conf, "force-filestore");
        if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
            FileForceFilestoreEnable();
            SCLogConfig("forcing filestore of all files");
        }

        const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
        if (force_magic != NULL && ConfValIsTrue(force_magic)) {
            FileForceMagicEnable();
            SCLogConfig("forcing magic lookup for logged files");
        }

        FileForceHashParseCfg(conf);
    }

    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
        output_file_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (output_file_ctx->xff_cfg != NULL) {
            HttpXFFGetCfg(conf, output_file_ctx->xff_cfg);
        }
    } else if (ojc->xff_cfg) {
        output_file_ctx->parent_xff_cfg = ojc->xff_cfg;
    }

    output_file_ctx->eve_ctx = ojc;
    output_ctx->data = output_file_ctx;
    output_ctx->DeInit = OutputFileLogDeinitSub;

    FileForceTrackingEnable();
    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonFileLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterFileSubModule(LOGGER_JSON_FILE, "eve-log", "JsonFileLog", "eve-log.files",
            OutputFileLogInitSub, JsonFileLogger, JsonFileLogThreadInit, JsonFileLogThreadDeinit);
}
