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
#include "detect-engine.h"
#include "detect-engine-profile.h"

#include "detect-engine-alert.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-engine-threshold.h"
#include "detect-engine-prefilter.h"

#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-dns-query.h"
#include "detect-tls-sni.h"
#include "detect-tls-certs.h"
#include "detect-tls-cert-fingerprint.h"
#include "detect-tls-cert-issuer.h"
#include "detect-tls-cert-subject.h"
#include "detect-tls-cert-serial.h"
#include "detect-tls-ja3-hash.h"
#include "detect-tls-ja3-string.h"
#include "detect-tls-ja3s-hash.h"
#include "detect-tls-ja3s-string.h"
#include "detect-engine-state.h"
#include "detect-engine-analyzer.h"

#include "detect-http-cookie.h"
#include "detect-http-method.h"
#include "detect-http-ua.h"
#include "detect-http-host.h"

#include "detect-nfs-procedure.h"
#include "detect-nfs-version.h"

#include "detect-engine-event.h"
#include "decode.h"

#include "detect-smb-share.h"

#include "detect-base64-decode.h"
#include "detect-base64-data.h"
#include "detect-ipopts.h"
#include "detect-tcp-flags.h"
#include "detect-fragbits.h"
#include "detect-fragoffset.h"
#include "detect-gid.h"
#include "detect-tcp-ack.h"
#include "detect-tcp-seq.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-depth.h"
#include "detect-nocase.h"
#include "detect-rawbytes.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-sameip.h"
#include "detect-l3proto.h"
#include "detect-ipproto.h"
#include "detect-within.h"
#include "detect-distance.h"
#include "detect-offset.h"
#include "detect-sid.h"
#include "detect-prefilter.h"
#include "detect-priority.h"
#include "detect-classtype.h"
#include "detect-reference.h"
#include "detect-tag.h"
#include "detect-threshold.h"
#include "detect-metadata.h"
#include "detect-msg.h"
#include "detect-rev.h"
#include "detect-flow.h"
#include "detect-tcp-window.h"
#include "detect-ftpbounce.h"
#include "detect-isdataat.h"
#include "detect-id.h"
#include "detect-rpc.h"
#include "detect-asn1.h"
#include "detect-filename.h"
#include "detect-fileext.h"
#include "detect-filestore.h"
#include "detect-filemagic.h"
#include "detect-filemd5.h"
#include "detect-filesha1.h"
#include "detect-filesha256.h"
#include "detect-filesize.h"
#include "detect-dsize.h"
#include "detect-flowvar.h"
#include "detect-flowint.h"
#include "detect-pktvar.h"
#include "detect-noalert.h"
#include "detect-flowbits.h"
#include "detect-hostbits.h"
#include "detect-xbits.h"
#include "detect-csum.h"
#include "detect-stream_size.h"
#include "detect-engine-sigorder.h"
#include "detect-ttl.h"
#include "detect-fast-pattern.h"
#include "detect-itype.h"
#include "detect-icode.h"
#include "detect-icmp-id.h"
#include "detect-icmp-seq.h"
#include "detect-dce-iface.h"
#include "detect-dce-opnum.h"
#include "detect-dce-stub-data.h"
#include "detect-urilen.h"
#include "detect-bsize.h"
#include "detect-detection-filter.h"
#include "detect-http-client-body.h"
#include "detect-http-server-body.h"
#include "detect-http-header.h"
#include "detect-http-header-names.h"
#include "detect-http-headers.h"
#include "detect-http-raw-header.h"
#include "detect-http-uri.h"
#include "detect-http-protocol.h"
#include "detect-http-start.h"
#include "detect-http-stat-msg.h"
#include "detect-http-request-line.h"
#include "detect-http-response-line.h"
#include "detect-byte-extract.h"
#include "detect-file-data.h"
#include "detect-pkt-data.h"
#include "detect-replace.h"
#include "detect-tos.h"
#include "detect-app-layer-event.h"
#include "detect-lua.h"
#include "detect-iprep.h"
#include "detect-geoip.h"
#include "detect-app-layer-protocol.h"
#include "detect-template.h"
#include "detect-template2.h"
#include "detect-tcphdr.h"
#include "detect-tcpmss.h"
#include "detect-udphdr.h"
#include "detect-krb5-cname.h"
#include "detect-krb5-errcode.h"
#include "detect-krb5-msgtype.h"
#include "detect-krb5-sname.h"
#include "detect-target.h"
#include "detect-template-rust-buffer.h"
#include "detect-snmp-version.h"
#include "detect-snmp-community.h"
#include "detect-snmp-pdu_type.h"
#include "detect-template-buffer.h"
#include "detect-bypass.h"
#include "detect-ftpdata.h"
#include "detect-engine-content-inspection.h"

#include "detect-transform-compress-whitespace.h"
#include "detect-transform-strip-whitespace.h"
#include "detect-transform-md5.h"
#include "detect-transform-sha1.h"
#include "detect-transform-sha256.h"

#include "util-rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "app-layer-template.h"
#include "detect-tls.h"
#include "detect-tls-cert-validity.h"
#include "detect-tls-version.h"
#include "detect-ssh-proto.h"
#include "detect-ssh-proto-version.h"
#include "detect-ssh-software.h"
#include "detect-ssh-software-version.h"
#include "detect-http-stat-code.h"
#include "detect-ssl-version.h"
#include "detect-ssl-state.h"
#include "detect-modbus.h"
#include "detect-cipservice.h"
#include "detect-dnp3.h"

#include "action-globals.h"
#include "tm-threads.h"

#include "pkt-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"
#include "stream-tcp-inline.h"

#include "util-lua.h"
#include "util-var-name.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-print.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "util-hashlist.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-optimize.h"
#include "util-path.h"
#include "util-mpm-ac.h"
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
    DetectKrb5CNameRegister();
    DetectKrb5ErrCodeRegister();
    DetectKrb5MsgTypeRegister();
    DetectKrb5SNameRegister();
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
