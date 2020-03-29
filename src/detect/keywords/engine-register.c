/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "flow-private.h"
#include "flow-bit.h"

#include "detect-parse.h"
#include "detect/keywords/engine.h"
#include "detect-engine-profile.h"

#include "detect/keywords/engine-alert.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect/keywords/engine-mpm.h"
#include "detect/keywords/engine-iponly.h"
#include "detect-engine-threshold.h"
#include "detect/keywords/engine-prefilter.h"

#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect/keywords/dns-opcode.h"
#include "detect/keywords/dns-query.h"
#include "detect/keywords/tls-sni.h"
#include "detect/keywords/tls-certs.h"
#include "detect/keywords/tls-cert-fingerprint.h"
#include "detect/keywords/tls-cert-issuer.h"
#include "detect/keywords/tls-cert-subject.h"
#include "detect/keywords/tls-cert-serial.h"
#include "detect/keywords/tls-ja3-hash.h"
#include "detect/keywords/tls-ja3-string.h"
#include "detect/keywords/tls-ja3s-hash.h"
#include "detect/keywords/tls-ja3s-string.h"
#include "detect-engine-state.h"
#include "detect/keywords/engine-analyzer.h"

#include "detect/keywords/http-cookie.h"
#include "detect/keywords/http-method.h"
#include "detect/keywords/http-ua.h"
#include "detect/keywords/http-host.h"

#include "detect/keywords/nfs-procedure.h"
#include "detect/keywords/nfs-version.h"

#include "detect/keywords/engine-event.h"
#include "decode.h"

#include "detect/keywords/smb-share.h"

#include "detect/keywords/base64-decode.h"
#include "detect/keywords/base64-data.h"
#include "detect/keywords/ipopts.h"
#include "detect/keywords/tcp-flags.h"
#include "detect/keywords/fragbits.h"
#include "detect/keywords/fragoffset.h"
#include "detect/keywords/gid.h"
#include "detect/keywords/tcp-ack.h"
#include "detect/keywords/tcp-seq.h"
#include "detect/keywords/content.h"
#include "detect/keywords/uricontent.h"
#include "detect/keywords/pcre.h"
#include "detect/keywords/depth.h"
#include "detect/keywords/nocase.h"
#include "detect/keywords/rawbytes.h"
#include "detect/keywords/bytetest.h"
#include "detect/keywords/bytejump.h"
#include "detect/keywords/sameip.h"
#include "detect/keywords/l3proto.h"
#include "detect/keywords/ipproto.h"
#include "detect/keywords/within.h"
#include "detect/keywords/distance.h"
#include "detect/keywords/offset.h"
#include "detect/keywords/sid.h"
#include "detect/keywords/prefilter.h"
#include "detect/keywords/priority.h"
#include "detect/keywords/classtype.h"
#include "detect/keywords/reference.h"
#include "detect/keywords/tag.h"
#include "detect/keywords/threshold.h"
#include "detect/keywords/metadata.h"
#include "detect/keywords/msg.h"
#include "detect/keywords/rev.h"
#include "detect/keywords/flow.h"
#include "detect/keywords/tcp-window.h"
#include "detect/keywords/ftpbounce.h"
#include "detect/keywords/isdataat.h"
#include "detect/keywords/id.h"
#include "detect/keywords/rpc.h"
#include "detect/keywords/asn1.h"
#include "detect/keywords/filename.h"
#include "detect/keywords/fileext.h"
#include "detect/keywords/filestore.h"
#include "detect/keywords/filemagic.h"
#include "detect/keywords/filemd5.h"
#include "detect/keywords/filesha1.h"
#include "detect/keywords/filesha256.h"
#include "detect/keywords/filesize.h"
#include "detect/keywords/dataset.h"
#include "detect/keywords/datarep.h"
#include "detect/keywords/dsize.h"
#include "detect/keywords/flowvar.h"
#include "detect/keywords/flowint.h"
#include "detect/keywords/pktvar.h"
#include "detect/keywords/noalert.h"
#include "detect/keywords/flowbits.h"
#include "detect/keywords/hostbits.h"
#include "detect/keywords/xbits.h"
#include "detect/keywords/csum.h"
#include "detect/keywords/stream_size.h"
#include "detect-engine-sigorder.h"
#include "detect/keywords/ttl.h"
#include "detect/keywords/fast-pattern.h"
#include "detect/keywords/itype.h"
#include "detect/keywords/icode.h"
#include "detect/keywords/icmp-id.h"
#include "detect/keywords/icmp-seq.h"
#include "detect/keywords/dce-iface.h"
#include "detect/keywords/dce-opnum.h"
#include "detect/keywords/dce-stub-data.h"
#include "detect/keywords/urilen.h"
#include "detect/keywords/bsize.h"
#include "detect/keywords/detection-filter.h"
#include "detect/keywords/http-client-body.h"
#include "detect/keywords/http-server-body.h"
#include "detect/keywords/http-header.h"
#include "detect/keywords/http-header-names.h"
#include "detect-http-headers.h"
#include "detect/keywords/http-raw-header.h"
#include "detect/keywords/http-uri.h"
#include "detect/keywords/http-protocol.h"
#include "detect/keywords/http-start.h"
#include "detect/keywords/http-stat-msg.h"
#include "detect/keywords/http-request-line.h"
#include "detect/keywords/http-response-line.h"
#include "detect/keywords/byte-extract.h"
#include "detect/keywords/file-data.h"
#include "detect/keywords/pkt-data.h"
#include "detect/keywords/replace.h"
#include "detect/keywords/tos.h"
#include "detect/keywords/app-layer-event.h"
#include "detect/keywords/lua.h"
#include "detect/keywords/iprep.h"
#include "detect/keywords/geoip.h"
#include "detect/keywords/app-layer-protocol.h"
#include "detect/keywords/template.h"
#include "detect/keywords/template2.h"
#include "detect/keywords/tcphdr.h"
#include "detect/keywords/tcpmss.h"
#include "detect/keywords/udphdr.h"
#include "detect/keywords/icmpv6hdr.h"
#include "detect/keywords/icmpv6-mtu.h"
#include "detect/keywords/ipv4hdr.h"
#include "detect/keywords/ipv6hdr.h"
#include "detect/keywords/krb5-cname.h"
#include "detect/keywords/krb5-errcode.h"
#include "detect/keywords/krb5-msgtype.h"
#include "detect/keywords/krb5-sname.h"
#include "detect/keywords/sip-method.h"
#include "detect/keywords/sip-uri.h"
#include "detect/keywords/sip-protocol.h"
#include "detect/keywords/sip-stat-code.h"
#include "detect/keywords/sip-stat-msg.h"
#include "detect/keywords/sip-request-line.h"
#include "detect/keywords/sip-response-line.h"
#include "detect/keywords/rfb-secresult.h"
#include "detect/keywords/rfb-sectype.h"
#include "detect/keywords/rfb-name.h"
#include "detect/keywords/target.h"
#include "detect/keywords/template-rust-buffer.h"
#include "detect/keywords/snmp-version.h"
#include "detect/keywords/snmp-community.h"
#include "detect/keywords/snmp-pdu_type.h"
#include "detect/keywords/template-buffer.h"
#include "detect/keywords/bypass.h"
#include "detect/keywords/ftpdata.h"
#include "detect-engine-content-inspection.h"

#include "detect/keywords/transform-compress-whitespace.h"
#include "detect/keywords/transform-strip-whitespace.h"
#include "detect/keywords/transform-md5.h"
#include "detect/keywords/transform-sha1.h"
#include "detect/keywords/transform-sha256.h"
#include "detect/keywords/transform-dotprefix.h"

#include "util/rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "app-layer-template.h"
#include "detect/keywords/tls.h"
#include "detect/keywords/tls-cert-validity.h"
#include "detect/keywords/tls-version.h"
#include "detect/keywords/ssh-proto.h"
#include "detect/keywords/ssh-proto-version.h"
#include "detect/keywords/ssh-software.h"
#include "detect/keywords/ssh-software-version.h"
#include "detect/keywords/http-stat-code.h"
#include "detect/keywords/ssl-version.h"
#include "detect/keywords/ssl-state.h"
#include "detect/keywords/modbus.h"
#include "detect/keywords/cipservice.h"
#include "detect/keywords/dnp3.h"

#include "action-globals.h"
#include "tm-threads.h"

#include "pkt-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"
#include "stream-tcp-inline.h"

#include "util/lua.h"
#include "util/var-name.h"
#include "util/classification-config.h"
#include "util/threshold-config.h"
#include "util/print.h"
#include "util/unittest.h"
#include "util/unittest-helper.h"
#include "util/debug.h"
#include "util/hashlist.h"
#include "util/privs.h"
#include "util/profiling.h"
#include "util-validate.h"
#include "util-optimize.h"
#include "util/path.h"
#include "util/mpm-ac.h"
#include "runmodes.h"

static void PrintFeatureList(const SigTableElmt *e, char sep)
{
    const uint16_t flags = e->flags;

    int prev = 0;
    if (flags & SIGMATCH_NOOPT) {
        printf("No option");
        prev = 1;
    }
    if (flags & SIGMATCH_IPONLY_COMPAT) {
        if (prev == 1)
            printf("%c", sep);
        printf("compatible with IP only rule");
        prev = 1;
    }
    if (flags & SIGMATCH_DEONLY_COMPAT) {
        if (prev == 1)
            printf("%c", sep);
        printf("compatible with decoder event only rule");
        prev = 1;
    }
    if (flags & SIGMATCH_INFO_CONTENT_MODIFIER) {
        if (prev == 1)
            printf("%c", sep);
        printf("content modifier");
        prev = 1;
    }
    if (flags & SIGMATCH_INFO_STICKY_BUFFER) {
        if (prev == 1)
            printf("%c", sep);
        printf("sticky buffer");
        prev = 1;
    }
    if (e->Transform) {
        if (prev == 1)
            printf("%c", sep);
        printf("transform");
        prev = 1;
    }
    if (e->SupportsPrefilter) {
        if (prev == 1)
            printf("%c", sep);
        printf("prefilter");
        prev = 1;
    }
    if (prev == 0) {
        printf("none");
    }
}

static void SigMultilinePrint(int i, const char *prefix)
{
    if (sigmatch_table[i].desc) {
        printf("%sDescription: %s\n", prefix, sigmatch_table[i].desc);
    }
    printf("%sFeatures: ", prefix);
    PrintFeatureList(&sigmatch_table[i], ',');
    if (sigmatch_table[i].url) {
        printf("\n%sDocumentation: %s", prefix, sigmatch_table[i].url);
    }
    if (sigmatch_table[i].alternative) {
        printf("\n%sReplaced by: %s", prefix, sigmatch_table[sigmatch_table[i].alternative].name);
    }
    printf("\n");
}

void SigTableList(const char *keyword)
{
    size_t size = sizeof(sigmatch_table) / sizeof(SigTableElmt);
    size_t i;

    if (keyword == NULL) {
        printf("=====Supported keywords=====\n");
        for (i = 0; i < size; i++) {
            const char *name = sigmatch_table[i].name;
            if (name != NULL && strlen(name) > 0) {
                if (name[0] == '_' || strcmp(name, "template") == 0)
                    continue;

                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    printf("- %s (not built-in)\n", name);
                } else {
                    printf("- %s\n", name);
                }
            }
        }
    } else if (strcmp("csv", keyword) == 0) {
        printf("name;description;app layer;features;documentation\n");
        for (i = 0; i < size; i++) {
            const char *name = sigmatch_table[i].name;
            if (name != NULL && strlen(name) > 0) {
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    continue;
                }
                if (name[0] == '_' || strcmp(name, "template") == 0)
                    continue;

                printf("%s;", name);
                if (sigmatch_table[i].desc) {
                    printf("%s", sigmatch_table[i].desc);
                }
                /* Build feature */
                printf(";Unset;"); // this used to be alproto
                PrintFeatureList(&sigmatch_table[i], ':');
                printf(";");
                if (sigmatch_table[i].url) {
                    printf("%s", sigmatch_table[i].url);
                }
                printf(";");
                printf("\n");
            }
        }
    } else if (strcmp("all", keyword) == 0) {
        for (i = 0; i < size; i++) {
            const char *name = sigmatch_table[i].name;
            if (name != NULL && strlen(name) > 0) {
                if (name[0] == '_' || strcmp(name, "template") == 0)
                    continue;
                printf("%s:\n", sigmatch_table[i].name);
                SigMultilinePrint(i, "\t");
            }
        }
    } else {
        for (i = 0; i < size; i++) {
            if ((sigmatch_table[i].name != NULL) &&
                strcmp(sigmatch_table[i].name, keyword) == 0) {
                printf("= %s =\n", sigmatch_table[i].name);
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    printf("Not built-in\n");
                    return;
                }
                SigMultilinePrint(i, "");
                return;
            }
        }
    }
    return;
}

void SigTableSetup(void)
{
    memset(sigmatch_table, 0, sizeof(sigmatch_table));

    DetectSidRegister();
    DetectPriorityRegister();
    DetectPrefilterRegister();
    DetectRevRegister();
    DetectClasstypeRegister();
    DetectReferenceRegister();
    DetectTagRegister();
    DetectThresholdRegister();
    DetectMetadataRegister();
    DetectMsgRegister();
    DetectAckRegister();
    DetectSeqRegister();
    DetectContentRegister();
    DetectUricontentRegister();

    /* NOTE: the order of these currently affects inspect
     * engine registration order and ultimately the order
     * of inspect engines in the rule. Which in turn affects
     * state keeping */
    DetectHttpUriRegister();
    DetectHttpRequestLineRegister();
    DetectHttpClientBodyRegister();
    DetectHttpResponseLineRegister();
    DetectHttpServerBodyRegister();
    DetectHttpHeaderRegister();
    DetectHttpHeaderNamesRegister();
    DetectHttpHeadersRegister();
    DetectHttpProtocolRegister();
    DetectHttpStartRegister();
    DetectHttpRawHeaderRegister();
    DetectHttpMethodRegister();
    DetectHttpCookieRegister();

    DetectFilenameRegister();
    DetectFileextRegister();
    DetectFilestoreRegister();
    DetectFilemagicRegister();
    DetectFileMd5Register();
    DetectFileSha1Register();
    DetectFileSha256Register();
    DetectFilesizeRegister();

    DetectHttpUARegister();
    DetectHttpHHRegister();

    DetectHttpStatMsgRegister();
    DetectHttpStatCodeRegister();

    DetectDnsQueryRegister();
    DetectDnsOpcodeRegister();
    DetectModbusRegister();
    DetectCipServiceRegister();
    DetectEnipCommandRegister();
    DetectDNP3Register();

    DetectTlsSniRegister();
    DetectTlsIssuerRegister();
    DetectTlsSubjectRegister();
    DetectTlsSerialRegister();
    DetectTlsFingerprintRegister();
    DetectTlsCertsRegister();

    DetectTlsJa3HashRegister();
    DetectTlsJa3StringRegister();
    DetectTlsJa3SHashRegister();
    DetectTlsJa3SStringRegister();

    DetectAppLayerEventRegister();
    /* end of order dependent regs */

    DetectPcreRegister();
    DetectDepthRegister();
    DetectNocaseRegister();
    DetectRawbytesRegister();
    DetectBytetestRegister();
    DetectBytejumpRegister();
    DetectSameipRegister();
    DetectGeoipRegister();
    DetectL3ProtoRegister();
    DetectIPProtoRegister();
    DetectWithinRegister();
    DetectDistanceRegister();
    DetectOffsetRegister();
    DetectReplaceRegister();
    DetectFlowRegister();
    DetectWindowRegister();
    DetectRpcRegister();
    DetectFtpbounceRegister();
    DetectFtpdataRegister();
    DetectIsdataatRegister();
    DetectIdRegister();
    DetectDsizeRegister();
    DetectDatasetRegister();
    DetectDatarepRegister();
    DetectFlowvarRegister();
    DetectFlowintRegister();
    DetectPktvarRegister();
    DetectNoalertRegister();
    DetectFlowbitsRegister();
    DetectHostbitsRegister();
    DetectXbitsRegister();
    DetectEngineEventRegister();
    DetectIpOptsRegister();
    DetectFlagsRegister();
    DetectFragBitsRegister();
    DetectFragOffsetRegister();
    DetectGidRegister();
    DetectMarkRegister();
    DetectCsumRegister();
    DetectStreamSizeRegister();
    DetectTtlRegister();
    DetectTosRegister();
    DetectFastPatternRegister();
    DetectITypeRegister();
    DetectICodeRegister();
    DetectIcmpIdRegister();
    DetectIcmpSeqRegister();
    DetectDceIfaceRegister();
    DetectDceOpnumRegister();
    DetectDceStubDataRegister();
    DetectSmbNamedPipeRegister();
    DetectSmbShareRegister();
    DetectTlsRegister();
    DetectTlsValidityRegister();
    DetectTlsVersionRegister();
    DetectNfsProcedureRegister();
    DetectNfsVersionRegister();
    DetectUrilenRegister();
    DetectBsizeRegister();
    DetectDetectionFilterRegister();
    DetectAsn1Register();
    DetectSshProtocolRegister();
    DetectSshVersionRegister();
    DetectSshSoftwareRegister();
    DetectSshSoftwareVersionRegister();
    DetectSslStateRegister();
    DetectSslVersionRegister();
    DetectByteExtractRegister();
    DetectFiledataRegister();
    DetectPktDataRegister();
    DetectLuaRegister();
    DetectIPRepRegister();
    DetectAppLayerProtocolRegister();
    DetectBase64DecodeRegister();
    DetectBase64DataRegister();
    DetectTemplateRegister();
    DetectTemplate2Register();
    DetectTcphdrRegister();
    DetectUdphdrRegister();
    DetectTcpmssRegister();
    DetectICMPv6hdrRegister();
    DetectICMPv6mtuRegister();
    DetectIpv4hdrRegister();
    DetectIpv6hdrRegister();
    DetectKrb5CNameRegister();
    DetectKrb5ErrCodeRegister();
    DetectKrb5MsgTypeRegister();
    DetectKrb5SNameRegister();
    DetectSipMethodRegister();
    DetectSipUriRegister();
    DetectSipProtocolRegister();
    DetectSipStatCodeRegister();
    DetectSipStatMsgRegister();
    DetectSipRequestLineRegister();
    DetectSipResponseLineRegister();
    DetectRfbSecresultRegister();
    DetectRfbSectypeRegister();
    DetectRfbNameRegister();
    DetectTargetRegister();
    DetectTemplateRustBufferRegister();
    DetectSNMPVersionRegister();
    DetectSNMPCommunityRegister();
    DetectSNMPPduTypeRegister();
    DetectTemplateBufferRegister();
    DetectBypassRegister();

    DetectTransformCompressWhitespaceRegister();
    DetectTransformStripWhitespaceRegister();
    DetectTransformMd5Register();
    DetectTransformSha1Register();
    DetectTransformSha256Register();
    DetectTransformDotPrefixRegister();

    /* close keyword registration */
    DetectBufferTypeCloseRegistration();
}

void SigTableRegisterTests(void)
{
    /* register the tests */
    int i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        g_ut_modules++;
        if (sigmatch_table[i].RegisterTests != NULL) {
            sigmatch_table[i].RegisterTests();
            g_ut_covered++;
        } else {
            SCLogDebug("detection plugin %s has no unittest "
                   "registration function.", sigmatch_table[i].name);

            if (coverage_unittests)
                SCLogWarning(SC_WARN_NO_UNITTESTS, "detection plugin %s has no unittest "
                        "registration function.", sigmatch_table[i].name);
        }
    }
}
