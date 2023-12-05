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

#include "app-layer/smb/detect-ntlmssp.h"
#include "suricata-common.h"
#include "suricata.h"
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
#include "app-layer/dns/detect-opcode.h"
#include "app-layer/dns/detect-query.h"
#include "app-layer/tls/detect-sni.h"
#include "app-layer/tls/detect-certs.h"
#include "app-layer/tls/detect-cert-fingerprint.h"
#include "app-layer/tls/detect-cert-issuer.h"
#include "app-layer/tls/detect-cert-subject.h"
#include "app-layer/tls/detect-cert-serial.h"
#include "app-layer/tls/detect-random.h"
#include "app-layer/tls/detect-ja3-hash.h"
#include "app-layer/tls/detect-ja3-string.h"
#include "app-layer/tls/detect-ja3s-hash.h"
#include "app-layer/tls/detect-ja3s-string.h"
#include "detect-engine-state.h"
#include "detect-engine-analyzer.h"

#include "app-layer/http/detect-cookie.h"
#include "app-layer/http/detect-method.h"
#include "app-layer/http/detect-ua.h"
#include "app-layer/http/detect-host.h"

#include "detect-mark.h"
#include "app-layer/nfs/detect-procedure.h"
#include "app-layer/nfs/detect-version.h"

#include "detect-engine-event.h"
#include "decode.h"

#include "detect-config.h"

#include "app-layer/smb/detect-share.h"

#include "detect-base64-decode.h"
#include "detect-base64-data.h"
#include "detect-ipaddr.h"
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
#include "detect-bytemath.h"
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
#include "detect-flow-age.h"
#include "detect-flow-pkts.h"
#include "detect-tcp-window.h"
#include "app-layer/ftp/detect-bounce.h"
#include "detect-isdataat.h"
#include "detect-id.h"
#include "detect-rpc.h"
#include "detect-asn1.h"
#include "detect-filename.h"
#include "detect-filestore.h"
#include "detect-filemagic.h"
#include "detect-filemd5.h"
#include "detect-filesha1.h"
#include "detect-filesha256.h"
#include "detect-filesize.h"
#include "detect-dataset.h"
#include "detect-datarep.h"
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
#include "detect-icmpv4hdr.h"
#include "detect-dce-iface.h"
#include "detect-dce-opnum.h"
#include "detect-dce-stub-data.h"
#include "detect-urilen.h"
#include "detect-bsize.h"
#include "detect-detection-filter.h"
#include "app-layer/http/detect-client-body.h"
#include "app-layer/http/detect-server-body.h"
#include "app-layer/http/detect-header.h"
#include "app-layer/http/detect-header-names.h"
#include "app-layer/http/detect-headers.h"
#include "app-layer/http/detect-raw-header.h"
#include "app-layer/http/detect-uri.h"
#include "app-layer/http/detect-protocol.h"
#include "app-layer/http/detect-start.h"
#include "app-layer/http/detect-stat-msg.h"
#include "app-layer/http/detect-request-line.h"
#include "app-layer/http/detect-response-line.h"
#include "app-layer/http2/detect.h"
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
#include "app-layer/template/detect.h"
#include "app-layer/template/detect-2.h"
#include "detect-tcphdr.h"
#include "detect-tcpmss.h"
#include "detect-udphdr.h"
#include "detect-icmpv6hdr.h"
#include "detect-icmpv6-mtu.h"
#include "detect-ipv4hdr.h"
#include "detect-ipv6hdr.h"
#include "app-layer/krb5/detect-cname.h"
#include "app-layer/krb5/detect-errcode.h"
#include "app-layer/krb5/detect-msgtype.h"
#include "app-layer/krb5/detect-sname.h"
#include "app-layer/krb5/detect-ticket-encryption.h"
#include "app-layer/sip/detect-method.h"
#include "app-layer/sip/detect-uri.h"
#include "app-layer/sip/detect-protocol.h"
#include "app-layer/sip/detect-stat-code.h"
#include "app-layer/sip/detect-stat-msg.h"
#include "app-layer/sip/detect-request-line.h"
#include "app-layer/sip/detect-response-line.h"
#include "app-layer/rfb/detect-secresult.h"
#include "app-layer/rfb/detect-sectype.h"
#include "app-layer/rfb/detect-name.h"
#include "detect-target.h"
#include "app-layer/template/detect-rust-buffer.h"
#include "app-layer/dhcp/detect-leasetime.h"
#include "app-layer/dhcp/detect-rebinding-time.h"
#include "app-layer/dhcp/detect-renewal-time.h"
#include "app-layer/snmp/detect-usm.h"
#include "app-layer/snmp/detect-version.h"
#include "app-layer/snmp/detect-community.h"
#include "app-layer/snmp/detect-pdu_type.h"
#include "app-layer/mqtt/detect-type.h"
#include "app-layer/mqtt/detect-flags.h"
#include "app-layer/mqtt/detect-qos.h"
#include "app-layer/mqtt/detect-protocol-version.h"
#include "app-layer/mqtt/detect-reason-code.h"
#include "app-layer/mqtt/detect-connect-flags.h"
#include "app-layer/mqtt/detect-connect-clientid.h"
#include "app-layer/mqtt/detect-connect-username.h"
#include "app-layer/mqtt/detect-connect-password.h"
#include "app-layer/mqtt/detect-connect-protocol-string.h"
#include "app-layer/mqtt/detect-connect-willtopic.h"
#include "app-layer/mqtt/detect-connect-willmessage.h"
#include "app-layer/mqtt/detect-connack-sessionpresent.h"
#include "app-layer/mqtt/detect-publish-topic.h"
#include "app-layer/mqtt/detect-publish-message.h"
#include "app-layer/mqtt/detect-subscribe-topic.h"
#include "app-layer/mqtt/detect-unsubscribe-topic.h"
#include "app-layer/quic/detect-sni.h"
#include "app-layer/quic/detect-ua.h"
#include "app-layer/quic/detect-version.h"
#include "app-layer/quic/detect-cyu-hash.h"
#include "app-layer/quic/detect-cyu-string.h"

#include "detect-bypass.h"
#include "app-layer/ftp/detect-data.h"
#include "detect-engine-content-inspection.h"

#include "detect-transform-compress-whitespace.h"
#include "detect-transform-strip-whitespace.h"
#include "detect-transform-md5.h"
#include "detect-transform-sha1.h"
#include "detect-transform-sha256.h"
#include "detect-transform-dotprefix.h"
#include "detect-transform-pcrexform.h"
#include "detect-transform-urldecode.h"
#include "detect-transform-xor.h"
#include "detect-transform-casechange.h"
#include "detect-transform-header-lowercase.h"

#include "util-rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer/http/parser.h"
#include "app-layer/smtp/parser.h"
#include "detect-frame.h"
#include "app-layer/tls/detect.h"
#include "app-layer/tls/detect-cert-validity.h"
#include "app-layer/tls/detect-version.h"
#include "app-layer/ssh/detect-proto.h"
#include "app-layer/ssh/detect-proto-version.h"
#include "app-layer/ssh/detect-software.h"
#include "app-layer/ssh/detect-software-version.h"
#include "app-layer/ssh/detect-hassh.h"
#include "app-layer/ssh/detect-hassh-server.h"
#include "app-layer/ssh/detect-hassh-string.h"
#include "app-layer/ssh/detect-hassh-server-string.h"
#include "app-layer/http/detect-stat-code.h"
#include "app-layer/ssl/detect-version.h"
#include "app-layer/ssl/detect-state.h"
#include "app-layer/modbus/detect.h"
#include "detect-cipservice.h"
#include "app-layer/dnp3/detect.h"
#include "app-layer/ike/detect-exch-type.h"
#include "app-layer/ike/detect-spi.h"
#include "app-layer/ike/detect-vendor.h"
#include "app-layer/ike/detect-chosen-sa.h"
#include "app-layer/ike/detect-key-exchange-payload-length.h"
#include "app-layer/ike/detect-nonce-payload-length.h"
#include "app-layer/ike/detect-nonce-payload.h"
#include "app-layer/ike/detect-key-exchange-payload.h"

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
        printf("\n%sDocumentation: %s%s", prefix, GetDocURL(), sigmatch_table[i].url);
    }
    if (sigmatch_table[i].alternative) {
        printf("\n%sReplaced by: %s", prefix, sigmatch_table[sigmatch_table[i].alternative].name);
    }
    printf("\n");
}

int SigTableList(const char *keyword)
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
                    printf("%s%s", GetDocURL(), sigmatch_table[i].url);
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
            if ((sigmatch_table[i].name != NULL) && strcmp(sigmatch_table[i].name, keyword) == 0) {
                printf("= %s =\n", sigmatch_table[i].name);
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    printf("Not built-in\n");
                    return TM_ECODE_FAILED;
                }
                SigMultilinePrint(i, "");
                return TM_ECODE_DONE;
            }
        }
        printf("Non existing keyword\n");
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_DONE;
}

static void DetectFileHandlerRegister(void)
{
    for (int i = 0; i < DETECT_TBLSIZE; i++) {
        if (filehandler_table[i].name)
            DetectFileRegisterFileProtocols(&filehandler_table[i]);
    }
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
    DetectHttpRequestHeaderRegister();
    DetectHttpResponseHeaderRegister();
    DetectHttpHeaderNamesRegister();
    DetectHttpHeadersRegister();
    DetectHttpProtocolRegister();
    DetectHttpStartRegister();
    DetectHttpRawHeaderRegister();
    DetectHttpMethodRegister();
    DetectHttpCookieRegister();

    DetectFilenameRegister();
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
    DetectHttp2Register();

    DetectDnsQueryRegister();
    DetectDnsOpcodeRegister();
    DetectModbusRegister();
    DetectCipServiceRegister();
    DetectEnipCommandRegister();
    DetectDNP3Register();

    DetectIkeExchTypeRegister();
    DetectIkeSpiRegister();
    DetectIkeVendorRegister();
    DetectIkeChosenSaRegister();
    DetectIkeKeyExchangePayloadLengthRegister();
    DetectIkeNoncePayloadLengthRegister();
    DetectIkeNonceRegister();
    DetectIkeKeyExchangeRegister();

    DetectTlsSniRegister();
    DetectTlsIssuerRegister();
    DetectTlsSubjectRegister();
    DetectTlsSerialRegister();
    DetectTlsFingerprintRegister();
    DetectTlsCertsRegister();
    DetectTlsCertChainLenRegister();
    DetectTlsRandomRegister();

    DetectTlsJa3HashRegister();
    DetectTlsJa3StringRegister();
    DetectTlsJa3SHashRegister();
    DetectTlsJa3SStringRegister();

    DetectAppLayerEventRegister();
    /* end of order dependent regs */

    DetectFrameRegister();

    DetectPcreRegister();
    DetectDepthRegister();
    DetectNocaseRegister();
    DetectRawbytesRegister();
    DetectBytetestRegister();
    DetectBytejumpRegister();
    DetectBytemathRegister();
    DetectSameipRegister();
    DetectGeoipRegister();
    DetectL3ProtoRegister();
    DetectIPProtoRegister();
    DetectWithinRegister();
    DetectDistanceRegister();
    DetectOffsetRegister();
    DetectReplaceRegister();
    DetectFlowRegister();
    DetectFlowAgeRegister();
    DetectFlowPktsToClientRegister();
    DetectFlowPktsToServerRegister();
    DetectFlowBytesToClientRegister();
    DetectFlowBytesToServerRegister();
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
    DetectIcmpv4HdrRegister();
    DetectDceIfaceRegister();
    DetectDceOpnumRegister();
    DetectDceStubDataRegister();
    DetectSmbNamedPipeRegister();
    DetectSmbShareRegister();
    DetectSmbNtlmsspUserRegister();
    DetectSmbNtlmsspDomainRegister();
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
    DetectSshHasshRegister();
    DetectSshHasshServerRegister();
    DetectSshHasshStringRegister();
    DetectSshHasshServerStringRegister();
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
    DetectIPAddrBufferRegister();
    DetectIpv4hdrRegister();
    DetectIpv6hdrRegister();
    DetectKrb5CNameRegister();
    DetectKrb5ErrCodeRegister();
    DetectKrb5MsgTypeRegister();
    DetectKrb5SNameRegister();
    DetectKrb5TicketEncryptionRegister();
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
    DetectDHCPLeaseTimeRegister();
    DetectDHCPRebindingTimeRegister();
    DetectDHCPRenewalTimeRegister();
    DetectSNMPUsmRegister();
    DetectSNMPVersionRegister();
    DetectSNMPCommunityRegister();
    DetectSNMPPduTypeRegister();
    DetectMQTTTypeRegister();
    DetectMQTTFlagsRegister();
    DetectMQTTQosRegister();
    DetectMQTTProtocolVersionRegister();
    DetectMQTTReasonCodeRegister();
    DetectMQTTConnectFlagsRegister();
    DetectMQTTConnectClientIDRegister();
    DetectMQTTConnectUsernameRegister();
    DetectMQTTConnectPasswordRegister();
    DetectMQTTConnectProtocolStringRegister();
    DetectMQTTConnectWillTopicRegister();
    DetectMQTTConnectWillMessageRegister();
    DetectMQTTConnackSessionPresentRegister();
    DetectMQTTPublishTopicRegister();
    DetectMQTTPublishMessageRegister();
    DetectMQTTSubscribeTopicRegister();
    DetectMQTTUnsubscribeTopicRegister();
    DetectQuicSniRegister();
    DetectQuicUaRegister();
    DetectQuicVersionRegister();
    DetectQuicCyuHashRegister();
    DetectQuicCyuStringRegister();

    DetectBypassRegister();
    DetectConfigRegister();

    DetectTransformCompressWhitespaceRegister();
    DetectTransformStripWhitespaceRegister();
    DetectTransformMd5Register();
    DetectTransformSha1Register();
    DetectTransformSha256Register();
    DetectTransformDotPrefixRegister();
    DetectTransformPcrexformRegister();
    DetectTransformUrlDecodeRegister();
    DetectTransformXorRegister();
    DetectTransformToLowerRegister();
    DetectTransformToUpperRegister();
    DetectTransformHeaderLowercaseRegister();

    DetectFileHandlerRegister();

    /* close keyword registration */
    DetectBufferTypeCloseRegistration();
}

#ifdef UNITTESTS
void SigTableRegisterTests(void)
{
    /* register the tests */
    for (int i = 0; i < DETECT_TBLSIZE; i++) {
        g_ut_modules++;
        if (sigmatch_table[i].RegisterTests != NULL) {
            sigmatch_table[i].RegisterTests();
            g_ut_covered++;
        } else {
            SCLogDebug("detection plugin %s has no unittest "
                       "registration function.",
                    sigmatch_table[i].name);

            if (coverage_unittests)
                SCLogWarning("detection plugin %s has no unittest "
                             "registration function.",
                        sigmatch_table[i].name);
        }
    }
}
#endif
