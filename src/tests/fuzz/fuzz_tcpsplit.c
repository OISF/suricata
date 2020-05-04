/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for differential tcp split
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-fast-pattern.h"
#include "conf-yaml-loader.h"

#include "flow-util.h"
#include "stream-tcp-util.h"
#include "util-byte.h"
#include "detect-parse.h"
#include "app-layer-parser.h"
#include "stream-tcp.h"

#define HEADER_LEN 6

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static int initialized = 0;
SCInstance suricata;
const uint8_t separator[] = {0x01, 0xD5, 0xCA, 0x7A};

const char configNoChecksum[] = "\
%YAML 1.1\n\
---\n\
pcap-file:\n\
\n\
  checksum-checks: no\n\
\n\
stream:\n\
\n\
  checksum-validation: no\n\
outputs:\n\
  - fast:\n\
      enabled: yes\n\
      filename: /dev/null\n\
  - eve-log:\n\
      enabled: yes\n\
      filetype: regular\n\
      filename: /dev/null\n\
      xff:\n\
        enabled: yes\n\
        mode: extra-data\n\
        deployment: reverse\n\
        header: X-Forwarded-For\n\
      types:\n\
        - alert:\n\
            payload: yes\n\
            payload-printable: yes\n\
            packet: yes\n\
            metadata: yes\n\
            http-body: yes\n\
            http-body-printable: yes\n\
            tagged-packets: yes\n\
        - anomaly:\n\
            enabled: yes\n\
            types:\n\
              decode: yes\n\
              stream: yes\n\
              applayer: yes\n\
            packethdr: yes\n\
        - http:\n\
            extended: yes\n\
            dump-all-headers: both\n\
        - dns\n\
        - tls:\n\
            extended: yes\n\
            session-resumption: yes\n\
        - files\n\
        - smtp:\n\
            extended: yes\n\
        - dnp3\n\
        - ftp\n\
        - rdp\n\
        - nfs\n\
        - smb\n\
        - tftp\n\
        - ikev2\n\
        - krb5\n\
        - snmp\n\
        - rfb\n\
        - sip\n\
        - dhcp:\n\
            enabled: yes\n\
            extended: yes\n\
        - ssh\n\
        - flow\n\
        - netflow\n\
        - metadata\n\
  - http-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
  - tls-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
app-layer:\n\
  protocols:\n\
    rdp:\n\
      enabled: yes\n\
    modbus:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 502\n\
    dnp3:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 20000\n\
    enip:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 44818\n\
        sp: 44818\n\
    sip:\n\
      enabled: yes\n\
";

TcpReassemblyThreadCtx *ra_ctx = NULL;
uint64_t forceLayer = 0;

static Packet *TestHelperBuildPacketAndFlow(const char *src, const char *dst,
                                     uint16_t sport, uint16_t dport)
{
    struct in_addr in;

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return NULL;

    struct timeval tv;
    TimeGet(&tv);
    COPY_TIMESTAMP(&tv, &p->ts);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = NULL;
    p->payload_len = 0;
    p->proto = IPPROTO_TCP;

    if (inet_pton(AF_INET, src, &in) != 1)
        goto error;
    p->src.addr_data32[0] = in.s_addr;
    p->sp = sport;

    if (inet_pton(AF_INET, dst, &in) != 1)
        goto error;
    p->dst.addr_data32[0] = in.s_addr;
    p->dp = dport;

    p->ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    if (p->ip4h == NULL)
        goto error;

    p->ip4h->s_ip_src.s_addr = p->src.addr_data32[0];
    p->ip4h->s_ip_dst.s_addr = p->dst.addr_data32[0];
    p->ip4h->ip_proto = IPPROTO_TCP;
    p->ip4h->ip_verhl = sizeof(IPV4Hdr);

    int hdr_offset = sizeof(IPV4Hdr);
    p->tcph = (TCPHdr *)(GET_PKT_DATA(p) + sizeof(IPV4Hdr));
    if (p->tcph == NULL)
        goto error;
    p->tcph->th_sport = htons(sport);
    p->tcph->th_dport = htons(dport);
    hdr_offset += sizeof(TCPHdr);

    SET_PKT_LEN(p, hdr_offset);
    p->payload = GET_PKT_DATA(p)+hdr_offset;

    //no UTHBuildFlow to have storage
    Flow *f = FlowAlloc();
    if (f == NULL) {
        goto error;
    }
    f->flags |= FLOW_IPV4;
    f->src.addr_data32[0] = p->src.addr_data32[0];
    f->dst.addr_data32[0] = p->dst.addr_data32[0];
    f->sp = sport;
    f->dp = dport;
    f->proto = IPPROTO_TCP;
    f->protomap = FlowGetProtoMapping(IPPROTO_TCP);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW;
    p->flags |= PKT_STREAM_EST;

    return p;

error:
    SCFree(p);
    return NULL;
}

static int TestHelperAddSegmentWithPayload(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, TcpStream *stream, uint32_t seq, const uint8_t *payload, uint16_t len, Packet *p)
{
    TcpSegment *s = StreamTcpGetSegment(tv, ra_ctx);
    if (s == NULL) {
        return -1;
    }
    s->seq = seq;
    TCP_SEG_LEN(s) = len;

    p->tcph->th_seq = htonl(seq);
    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, s, p, TCP_GET_SEQ(p), payload, len) < 0)
        return -1;

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        run_mode = RUNMODE_PCAP_FILE;
        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        suricata.sig_file = strdup("/tmp/fuzz.rules");
        suricata.sig_file_exclusive = 1;
        //loads rules after init
        suricata.delayed_detect = 1;

        SupportFastPatternForSigMatchTypes();
        PostConfLoadedSetup(&suricata);
        PreRunPostPrivsDropInit(run_mode);
        PostConfLoadedDetectSetup(&suricata);

        ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
        stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
        const char* forceLayerStr = getenv("FUZZ_APPLAYER");
        if (forceLayerStr) {
            if (ByteExtractStringUint64(&forceLayer, 10, 0, forceLayerStr) < 0) {
                forceLayer = 0;
                printf("Invalid numeric value for FUZZ_APPLAYER environment variable");
            }
        }

        initialized = 1;
    }

    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;
    size_t pos;
    int tcput = 0;
    int engineStarted = 0;
    Packet *p = NULL;
    Packet *psplit = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;

    //First extract signature until null character
    for (pos=0; pos < size; pos++) {
        if (data[pos] == 0) {
            break;
        }
    }
    if (pos > 0 && pos < size) {
        de_ctx = DetectEngineCtxInit();
        if(de_ctx == NULL) {
            goto end;
        }
        de_ctx->flags |= DE_QUIET;
        s = SigInit(de_ctx, (const char *) data);
        if(s == NULL) {
            goto end;
        }
        pos++;
    } else {
        // we need both a signature and data to be processed
        return 0;
    }

    //Second, init two fake packets and flows : one regular, the other will be split
    data += pos;
    size -= pos;
    if (size < HEADER_LEN) {
        goto end;
    }

    ThreadVars tv;
    TcpSession ssn;
    TcpSession ssnsplit;
    ThreadVars th_v;

    memset(&th_v, 0, sizeof(th_v));
    memset(&tv, 0x00, sizeof(tv));
    tcput = 1;
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&ssnsplit, 0, sizeof(TcpSession));
    StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    ssn.client.sb = x;
    ssn.server.sb = x;
    ssn.server.isn = 1;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.server, 1);
    ssn.server.base_seq = 2;
    ssn.client.isn = 1;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn.client, 1);
    ssn.client.base_seq = 2;
    StreamingBuffer xsplit = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
    ssnsplit.client.sb = xsplit;
    ssnsplit.server.sb = xsplit;
    ssnsplit.server.isn = 1;
    STREAMTCP_SET_RA_BASE_SEQ(&ssnsplit.server, 1);
    ssnsplit.server.base_seq = 2;
    ssnsplit.client.isn = 1;
    STREAMTCP_SET_RA_BASE_SEQ(&ssnsplit.client, 1);
    ssnsplit.client.base_seq = 2;

    p = TestHelperBuildPacketAndFlow("192.168.1.5", "192.168.1.1", (data[2] << 8) | data[3], (data[4] << 8) | data[5]);
    if(p == NULL) {
        goto end;
    }
    psplit = TestHelperBuildPacketAndFlow("192.168.1.7", "192.168.1.2", (data[2] << 8) | data[3], (data[4] << 8) | data[5]);
    if(psplit == NULL) {
        goto end;
    }
    p->flow->protoctx = &ssn;
    psplit->flow->protoctx = &ssnsplit;
    if (forceLayer > 0) {
        p->flow->alproto = forceLayer;
        p->flow->alproto_ts = forceLayer;
        p->flow->alproto_tc = forceLayer;
        psplit->flow->alproto = forceLayer;
        psplit->flow->alproto_ts = forceLayer;
        psplit->flow->alproto_tc = forceLayer;
    } else {
        p->flow->alproto = data[0];
        p->flow->alproto_ts = data[0];
        p->flow->alproto_tc = data[0];
        psplit->flow->alproto = data[0];
        psplit->flow->alproto_ts = data[0];
        psplit->flow->alproto_tc = data[0];
    }

    //Prepare to start parsing
    de_ctx->sig_list = s;
    SigGroupBuild(de_ctx);
    engineStarted = 1;
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    if (det_ctx == NULL) {
        abort();
    }

    uint32_t seqcli = 2;
    uint32_t seqsrv = 2;
    const uint8_t * albuffer = data + HEADER_LEN;
    size_t alsize = size - HEADER_LEN;
    int flip = 0;
    size_t segsize = 0;
    const uint8_t *alnext = memmem(albuffer, alsize, separator, 4);

    //Iterates TCP parsing
    while (alsize > 0) {
        if (alnext == NULL) {
            segsize = alsize;
        } else {
            segsize = alnext - albuffer;
        }
        if (flip) {
            p->flowflags = FLOW_PKT_TOSERVER;
            psplit->flowflags = FLOW_PKT_TOSERVER;
            flip = 0;
        } else {
            p->flowflags = FLOW_PKT_TOCLIENT;
            psplit->flowflags = FLOW_PKT_TOCLIENT;
            flip = 1;
        }
        //if we do not have data for this side, continue
        if (segsize > 0) {
            if (p->flowflags == FLOW_PKT_TOCLIENT) {
                if(TestHelperAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seqsrv, albuffer, segsize, p) == -1) {
                    goto end;
                }
                if (StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn,  &ssn.server, p, UPDATE_DIR_PACKET) < 0) {
                    goto end;
                }
                //extreme split one byte by one byte
                for (pos=0; pos<segsize; pos++) {
                    if(TestHelperAddSegmentWithPayload(&tv, ra_ctx, &ssnsplit.server, seqsrv + pos, albuffer + pos, 1, psplit) == -1) {
                        goto end;
                    }
                    if (StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssnsplit, &ssnsplit.server, psplit, UPDATE_DIR_PACKET) < 0) {
                        goto end;
                    }
                }
                seqsrv += segsize;
            } else {
                if(TestHelperAddSegmentWithPayload(&tv, ra_ctx,  &ssn.client, seqcli, albuffer, segsize, p) == -1) {
                    goto end;
                }
                if(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0) {
                    goto end;
                }
                for (pos=0; pos<segsize; pos++) {
                    if(TestHelperAddSegmentWithPayload(&tv, ra_ctx, &ssnsplit.client, seqcli + pos, albuffer + pos, 1, psplit) == -1) {
                        goto end;
                    }
                    if (StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssnsplit, &ssnsplit.client, psplit, UPDATE_DIR_PACKET) < 0) {
                        goto end;
                    }
                }
                seqcli += segsize;
            }
            if (p->flow->alparser && AppLayerParserStateIssetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF)) {
                break;
            }
        }
        if (alnext == NULL) {
            break;
        }
        alsize -= alnext - albuffer + 4;
        albuffer = alnext + 4;
        alnext = memmem(albuffer, alsize, separator, 4);
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, psplit);

    if(PacketAlertCheck(p, s->id) != PacketAlertCheck(psplit, s->id)) {
        printf("Assertion failure : different alerts with TCP split %d vs %d\n",
               PacketAlertCheck(p, s->id), PacketAlertCheck(psplit, s->id));
        abort();
    }

end:
    if (p != NULL) {
        FlowFree(p->flow);
        SCFree(p);
    }
    if (psplit != NULL) {
        FlowFree(psplit->flow);
        SCFree(psplit);
    }
    if (engineStarted) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    if (tcput) {
        StreamTcpStreamCleanup(&ssn.client);
        StreamTcpStreamCleanup(&ssn.server);
        StreamTcpSessionCleanup(&ssn);
        StreamTcpStreamCleanup(&ssnsplit.client);
        StreamTcpStreamCleanup(&ssnsplit.server);
        StreamTcpSessionCleanup(&ssnsplit);
    }

    return 0;
}
