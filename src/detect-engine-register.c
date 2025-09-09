/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#include "detect-smb-ntlmssp.h"
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

#include "rust.h"

#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-dns-name.h"
#include "detect-dns-response.h"
#include "detect-tls-sni.h"
#include "detect-tls-certs.h"
#include "detect-tls-cert-fingerprint.h"
#include "detect-tls-cert-issuer.h"
#include "detect-tls-cert-subject.h"
#include "detect-tls-cert-serial.h"
#include "detect-tls-alpn.h"
#include "detect-tls-subjectaltname.h"
#include "detect-tls-random.h"
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

#include "detect-mark.h"
#include "detect-nfs-version.h"

#include "detect-engine-event.h"
#include "decode.h"

#include "detect-config.h"

#include "detect-smb-share.h"
#include "detect-smb-version.h"
#include "detect-smtp.h"

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
#include "detect-requires.h"
#include "detect-tcp-window.h"
#include "detect-tcp-wscale.h"
#include "detect-ftpbounce.h"
#include "detect-ftp-dynamic-port.h"
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
#include "detect-http2.h"
#include "detect-byte-extract.h"
#include "detect-file-data.h"
#include "detect-pkt-data.h"
#include "detect-replace.h"
#include "detect-tos.h"
#include "detect-app-layer-event.h"
#include "detect-app-layer-state.h"
#include "detect-lua.h"
#include "detect-iprep.h"
#include "detect-geoip.h"
#include "detect-app-layer-protocol.h"
#include "detect-template.h"
#include "detect-template2.h"
#include "detect-tcphdr.h"
#include "detect-tcpmss.h"
#include "detect-udphdr.h"
#include "detect-icmpv6hdr.h"
#include "detect-icmpv6-mtu.h"
#include "detect-ipv4hdr.h"
#include "detect-ipv6hdr.h"
#include "detect-krb5-cname.h"
#include "detect-krb5-errcode.h"
#include "detect-krb5-sname.h"
#include "detect-krb5-ticket-encryption.h"
#include "detect-sip-method.h"
#include "detect-sip-uri.h"
#include "detect-target.h"
#include "detect-quic-sni.h"
#include "detect-quic-ua.h"
#include "detect-quic-version.h"
#include "detect-quic-cyu-hash.h"
#include "detect-quic-cyu-string.h"
#include "detect-ja4-hash.h"
#include "detect-ftp-command.h"
#include "detect-entropy.h"
#include "detect-ftp-command-data.h"
#include "detect-ftp-completion-code.h"
#include "detect-ftp-reply.h"
#include "detect-ftp-mode.h"
#include "detect-ftp-reply-received.h"

#include "detect-bypass.h"
#include "detect-ftpdata.h"
#include "detect-engine-content-inspection.h"

#include "detect-transform-pcrexform.h"
#include "detect-transform-luaxform.h"

#include "util-rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "detect-frame.h"
#include "detect-tls.h"
#include "detect-tls-cert-validity.h"
#include "detect-tls-version.h"
#include "detect-ssh-proto.h"
#include "detect-ssh-proto-version.h"
#include "detect-ssh-software.h"
#include "detect-ssh-software-version.h"
#include "detect-ssh-hassh.h"
#include "detect-ssh-hassh-server.h"
#include "detect-ssh-hassh-string.h"
#include "detect-ssh-hassh-server-string.h"
#include "detect-http-stat-code.h"
#include "detect-ssl-version.h"
#include "detect-ssl-state.h"
#include "detect-modbus.h"
#include "detect-dnp3.h"
#include "detect-ike-exch-type.h"
#include "detect-ike-spi.h"
#include "detect-ike-vendor.h"
#include "detect-ike-chosen-sa.h"
#include "detect-ike-key-exchange-payload-length.h"
#include "detect-ike-nonce-payload-length.h"
#include "detect-ike-nonce-payload.h"
#include "detect-ike-key-exchange-payload.h"
#include "detect-vlan.h"
#include "detect-email.h"

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

int DETECT_TBLSIZE = 0;
int DETECT_TBLSIZE_IDX = DETECT_TBLSIZE_STATIC;

static void PrintFeatureList(const SigTableElmt *e, char sep)
{
    const uint32_t flags = e->flags;

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
    if (flags & SIGMATCH_SUPPORT_FIREWALL) {
        if (prev == 1)
            printf("%c", sep);
        printf("supports firewall");
        prev = 1;
    }
    if (flags & SIGMATCH_INFO_MULTI_BUFFER) {
        if (prev == 1)
            printf("%c", sep);
        printf("multi buffer");
        prev = 1;
    }
    if (flags & (SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_UINT16 | SIGMATCH_INFO_UINT32 |
                        SIGMATCH_INFO_UINT64)) {
        if (prev == 1)
            printf("%c", sep);
        if (flags & SIGMATCH_INFO_MULTI_UINT)
            printf("multi ");
        if (flags & SIGMATCH_INFO_ENUM_UINT)
            printf("enum ");
        if (flags & SIGMATCH_INFO_BITFLAGS_UINT)
            printf("bitflags ");
        if (flags & SIGMATCH_INFO_UINT8)
            printf("uint8");
        if (flags & SIGMATCH_INFO_UINT16)
            printf("uint16");
        if (flags & SIGMATCH_INFO_UINT32)
            printf("uint32");
        if (flags & SIGMATCH_INFO_UINT64)
            printf("uint64");
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

static void SigMultilinePrint(size_t i, const char *prefix)
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

/** \brief Check if a keyword exists. */
bool SigTableHasKeyword(const char *keyword)
{
    for (int i = 0; i < DETECT_TBLSIZE; i++) {
        const char *name = sigmatch_table[i].name;

        if (name == NULL || strlen(name) == 0) {
            continue;
        }

        if (strcmp(keyword, name) == 0) {
            return true;
        }
    }

    return false;
}

int SigTableList(const char *keyword)
{
    size_t size = DETECT_TBLSIZE;
    size_t i;

    if (keyword == NULL) {
        printf("=====Supported keywords=====\n");
        for (i = 0; i < size; i++) {
            const char *name = sigmatch_table[i].name;
            if (name != NULL && strlen(name) > 0) {
                if (name[0] == '_' || strcmp(name, "template") == 0)
                    continue;

                printf("- %s\n", name);
            }
        }
    } else if (strcmp("csv", keyword) == 0) {
        printf("name;description;app layer;features;documentation\n");
        for (i = 0; i < size; i++) {
            const char *name = sigmatch_table[i].name;
            if (name != NULL && strlen(name) > 0) {
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
            if ((sigmatch_table[i].name != NULL) &&
                strcmp(sigmatch_table[i].name, keyword) == 0) {
                printf("= %s =\n", sigmatch_table[i].name);
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
    for (int i = 0; i < DETECT_TBLSIZE_STATIC; i++) {
        if (filehandler_table[i].name)
            DetectFileRegisterFileProtocols(&filehandler_table[i]);
    }
}

static void SigCleanCString(SigTableElmt *base)
{
    SCSigTableNamesElmt kw;
    // remove const for mut to release
    kw.name = (char *)base->name;
    kw.desc = (char *)base->desc;
    kw.url = (char *)base->url;
    SCDetectSigMatchNamesFree(&kw);
}

void SCDetectHelperKeywordSetCleanCString(uint16_t id)
{
    sigmatch_table[id].Cleanup = SigCleanCString;
}

void SigTableCleanup(void)
{
    if (sigmatch_table != NULL) {
        for (int i = 0; i < DETECT_TBLSIZE; i++) {
            if ((sigmatch_table[i].Cleanup) == NULL) {
                continue;
            }
            sigmatch_table[i].Cleanup(&sigmatch_table[i]);
        }
        SCFree(sigmatch_table);
        sigmatch_table = NULL;
        DETECT_TBLSIZE = 0;
    }
}

#define ARRAY_CAP_STEP 16
static void (**PreregisteredCallbacks)(void) = NULL;
static size_t preregistered_callbacks_nb = 0;
static size_t preregistered_callbacks_cap = 0;

// Plugins can preregister keywords with this function :
// When an app-layer plugin is loaded, it wants to register its keywords
// But the plugin is loaded before keywords can register
// The preregistration callbacks will later be called by SigTableSetup
int SCSigTablePreRegister(void (*KeywordsRegister)(void))
{
    if (preregistered_callbacks_nb == preregistered_callbacks_cap) {
        void *tmp = SCRealloc(PreregisteredCallbacks,
                sizeof(void *) * (preregistered_callbacks_cap + ARRAY_CAP_STEP));
        if (tmp == NULL) {
            return 1;
        }
        preregistered_callbacks_cap += ARRAY_CAP_STEP;
        PreregisteredCallbacks = tmp;
    }
    PreregisteredCallbacks[preregistered_callbacks_nb] = KeywordsRegister;
    preregistered_callbacks_nb++;
    return 0;
}

void SigTableInit(void)
{
    if (sigmatch_table == NULL) {
        DETECT_TBLSIZE = DETECT_TBLSIZE_STATIC + DETECT_TBLSIZE_STEP;
        sigmatch_table = SCCalloc(DETECT_TBLSIZE, sizeof(SigTableElmt));
        if (sigmatch_table == NULL) {
            DETECT_TBLSIZE = 0;
            FatalError("Could not allocate sigmatch_table");
        }
    }
}

void SigTableSetup(void)
{
    DetectRegisterAppLayerHookLists();

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

    DetectDnsNameRegister();
    DetectDnsResponseRegister();
    DetectModbusRegister();
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
    DetectTlsSubjectAltNameRegister();
    DetectTlsAlpnRegister();
    DetectTlsRandomRegister();

    DetectTlsJa3HashRegister();
    DetectTlsJa3StringRegister();
    DetectTlsJa3SHashRegister();
    DetectTlsJa3SStringRegister();

    DetectAppLayerEventRegister();
    DetectAppLayerStateRegister();
    /* end of order dependent regs */

    DetectFrameRegister();

    DetectPcreRegister();
    DetectDepthRegister();
    DetectNocaseRegister();
    DetectRawbytesRegister();
    DetectBytetestRegister();
    DetectBytejumpRegister();
    DetectBytemathRegister();
    DetectEntropyRegister();
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
    DetectFlowPktsRegister();
    DetectFlowPktsToServerRegister();
    DetectFlowPktsToClientRegister();
    DetectFlowBytesRegister();
    DetectFlowBytesToServerRegister();
    DetectFlowBytesToClientRegister();
    DetectRequiresRegister();
    DetectWindowRegister();
    DetectRpcRegister();
    DetectFtpbounceRegister();
    DetectFtpdataRegister();
    DetectFtpDynamicPortRegister();
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
    DetectSmbVersionRegister();
    DetectTlsRegister();
    DetectTlsValidityRegister();
    DetectTlsVersionRegister();
    SCDetectNfsProcedureRegister();
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
    DetectTcpWscaleRegister();
    DetectICMPv6hdrRegister();
    DetectICMPv6mtuRegister();
    DetectIPAddrBufferRegister();
    DetectIpv4hdrRegister();
    DetectIpv6hdrRegister();
    DetectKrb5CNameRegister();
    DetectKrb5ErrCodeRegister();
    SCDetectKrb5MsgTypeRegister();
    DetectKrb5SNameRegister();
    DetectKrb5TicketEncryptionRegister();
    DetectSipMethodRegister();
    DetectSipUriRegister();
    DetectTargetRegister();
    DetectQuicSniRegister();
    DetectQuicUaRegister();
    DetectQuicVersionRegister();
    DetectQuicCyuHashRegister();
    DetectQuicCyuStringRegister();
    DetectJa4HashRegister();
    DetectFtpCommandRegister();
    DetectFtpCommandDataRegister();
    DetectFtpCompletionCodeRegister();
    DetectFtpReplyRegister();
    DetectFtpModeRegister();
    DetectFtpReplyReceivedRegister();

    DetectBypassRegister();
    DetectConfigRegister();

    DetectTransformCompressWhitespaceRegister();
    DetectTransformStripWhitespaceRegister();
    DetectTransformStripPseudoHeadersRegister();
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
    DetectTransformFromBase64DecodeRegister();
    SCDetectTransformDomainRegister();
    DetectTransformLuaxformRegister();

    DetectFileHandlerRegister();

    DetectVlanIdRegister();
    DetectVlanLayersRegister();

    DetectEmailRegister();

    SCDetectSMTPRegister();
    SCDetectDHCPRegister();
    SCDetectWebsocketRegister();
    SCDetectEnipRegister();
    SCDetectMqttRegister();
    SCDetectRfbRegister();
    SCDetectSipRegister();
    SCDetectTemplateRegister();
    SCDetectLdapRegister();
    SCDetectSdpRegister();
    SCDetectDNSRegister();
    SCDetectPgsqlRegister();

    for (size_t i = 0; i < preregistered_callbacks_nb; i++) {
        PreregisteredCallbacks[i]();
    }

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
                   "registration function.", sigmatch_table[i].name);

            if (coverage_unittests)
                SCLogWarning("detection plugin %s has no unittest "
                             "registration function.",
                        sigmatch_table[i].name);
        }
    }
}
#endif
