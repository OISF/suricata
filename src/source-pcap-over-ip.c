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
 * \author Mahmoud Maatuq <mahmoudmatook.mm@gmail.com>
 *
 * Pcap over ip packet acquisition support - Example with split connect() functions
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "source-pcap-over-ip.h"
#include "util-bpf.h"
#include "util-debug.h"
#include "util-privs.h"
#include "util-datalink.h"
#include "util-optimize.h"
#include "util-time.h"
#include "tmqh-packetpool.h"

#if defined(OS_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifndef close
#define close(fd) closesocket(fd)
#endif
#ifndef sleep
#define sleep(x) Sleep((x)*1000)
#endif
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <pcap.h>

struct pcap_timeval {
    int32_t tv_sec;
    int32_t tv_usec;
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;
    uint32_t caplen;
    uint32_t len;
};

#ifndef PCAP_MAGIC_NUMBER
#define PCAP_MAGIC_NUMBER  0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC 0xd4c3b2a1
#endif

#define MAX_PACKET_BUFFER_SIZE (64 * 1024)

#ifndef SWAPLONG
#define SWAPLONG(y)                                                                                \
    (((((uint32_t)(y)) & 0xff) << 24) | ((((uint32_t)(y)) & 0xff00) << 8) |                        \
            ((((uint32_t)(y)) & 0xff0000) >> 8) | ((((uint32_t)(y)) >> 24) & 0xff))
#endif

#ifndef SWAPSHORT
#define SWAPSHORT(y)                                                                               \
    ((uint16_t)(((((uint32_t)(y)) & 0xff) << 8) | ((((uint32_t)(y)) & 0xff00) >> 8)))
#endif

#define PCAPOVERIP_STATE_DOWN 0
#define PCAPOVERIP_STATE_UP   1

typedef struct PcapOverIPThreadVars_ {
    int socket_fd;
    unsigned char state;

    struct bpf_program filter;
    const char *bpf_filter_str;

    time_t last_stats_dump;

    int datalink;

    uint64_t pkts;
    uint64_t bytes;

    ThreadVars *tv;
    TmSlot *slot;
    int cb_result;

    ChecksumValidationMode checksum_mode;

    uint16_t capture_packets;
    uint16_t capture_bytes;

    bool swapped;
    uint32_t snaplen;
} PcapOverIPThreadVars;

static TmEcode ReceivePcapOverIPThreadInit(ThreadVars *, const void *, void **);
static TmEcode ReceivePcapOverIPThreadDeinit(ThreadVars *tv, void *data);
static void ReceivePcapOverIPThreadExitStats(ThreadVars *, void *);
static TmEcode ReceivePcapOverIPLoop(ThreadVars *tv, void *data, void *slot);
static TmEcode ReceivePcapOverIPBreakLoop(ThreadVars *tv, void *data);

static TmEcode DecodePcapOverIPThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodePcapOverIPThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodePcapOverIP(ThreadVars *, Packet *, void *);

static int PcapOverIPParseRemote(const char *path, char *host, size_t hostlen, int *port);
static int PcapOverIPConnect(int socket_fd, const char *host, int port);
#if defined(OS_WIN32)
static int PcapOverIPConnectWindows(int socket_fd, const char *host, int port);
#else
static int PcapOverIPConnectUnix(int socket_fd, const char *host, int port);
#endif

static int PcapOverIPReadGlobalHeader(PcapOverIPThreadVars *ptv);
static int PcapOverIPReadPacket(
        PcapOverIPThreadVars *ptv, struct pcap_pkthdr *pkthdr, uint8_t *buf, int buflen);
static int PcapOverIPApplyFilter(
        PcapOverIPThreadVars *ptv, struct pcap_pkthdr *pkthdr, const uint8_t *data);
static pcap_t *PcapOverIPOpenDead(int datalink, int snaplen);

static SCMutex pcap_bpf_compile_lock = SCMUTEX_INITIALIZER;

void TmModuleReceivePcapOverIPRegister(void)
{
    tmm_modules[TMM_RECEIVEPCAPOVERIP].name = "ReceivePcapOverIP";
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadInit = ReceivePcapOverIPThreadInit;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadDeinit = ReceivePcapOverIPThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].PktAcqLoop = ReceivePcapOverIPLoop;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].PktAcqBreakLoop = ReceivePcapOverIPBreakLoop;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadExitPrintStats = ReceivePcapOverIPThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePcapOverIPRegister(void)
{
    tmm_modules[TMM_DECODEPCAPOVERIP].name = "DecodePcapOverIP";
    tmm_modules[TMM_DECODEPCAPOVERIP].ThreadInit = DecodePcapOverIPThreadInit;
    tmm_modules[TMM_DECODEPCAPOVERIP].Func = DecodePcapOverIP;
    tmm_modules[TMM_DECODEPCAPOVERIP].ThreadDeinit = DecodePcapOverIPThreadDeinit;
    tmm_modules[TMM_DECODEPCAPOVERIP].flags = TM_FLAG_DECODE_TM;
}

static char *PcapOverIPGeErrorStr(void)
{
#ifdef OS_WIN32
    return WSAGetLastError();
#else
    return strerror(errno);
#endif
}

static int PcapOverIPParseRemote(const char *path, char *host, size_t hostlen, int *port)
{
    char *col = strchr(path, ':');
    if (col == NULL)
        return -1;

    size_t hlen = (size_t)(col - path);
    if (hlen == 0 || hlen >= hostlen)
        return -1;

    strncpy(host, path, hlen);
    host[hlen] = '\0';

    char *endptr = NULL;
    int p = strtol(col + 1, &endptr, 10);
    if (endptr == (col + 1) || p <= 0 || p > 65535)
        return -1;
    *port = p;
    return 0;
}

static int PcapOverIPConnect(int socket_fd, const char *host, int port)
{
#if defined(OS_WIN32)
    return PcapOverIPConnectWindows(socket_fd, host, port);
#else
    return PcapOverIPConnectUnix(socket_fd, host, port);
#endif
}

#if defined(OS_WIN32)
static int PcapOverIPConnectWindows(int socket_fd, const char *host, int port)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (he == NULL || he->h_addr == NULL) {
            SCLogError("PcapOverIPConnectWindows: could not resolve host '%s' (WSA error %d)", host,
                    WSAGetLastError());
            return -1;
        }
        memcpy(&server_addr.sin_addr, he->h_addr, he->h_length);
    }

    int attempt_delay = 1;
    while (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        int werr = WSAGetLastError();
        if (werr == WSAEINTR)
            continue;

        if (attempt_delay > 8) {
            SCLogError(
                    "PcapOverIPConnectWindows: connect() failed after multiple retries (error: %d)",
                    werr);
            closesocket(socket_fd);
            return -1;
        }
        SCLogDebug("PcapOverIPConnectWindows: connect() failed, sleeping %d second(s) before retry",
                attempt_delay);
        Sleep(attempt_delay * 1000);
        attempt_delay *= 2;
    }

    SCLogDebug("PcapOverIPConnectWindows: connected to %s:%d", host, port);
    return socket_fd;
}

#else

static int PcapOverIPConnectUnix(int socket_fd, const char *host, int port)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (he == NULL || he->h_addr == NULL) {
            SCLogError("PcapOverIPConnectUnix: could not resolve host '%s': %s", host,
                    strerror(errno));
            return -1;
        }
        memcpy(&server_addr.sin_addr, he->h_addr, he->h_length);
    }

    int attempt_delay = 1;
    while (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno == EINTR)
            continue;

        if (attempt_delay > 8) {
            SCLogError("PcapOverIPConnectUnix: connect() failed after multiple retries: %s",
                    strerror(errno));
            close(socket_fd);
            return -1;
        }
        SCLogDebug("PcapOverIPConnectUnix: connect() failed, sleeping %d second(s) before retry",
                attempt_delay);
        sleep(attempt_delay);
        attempt_delay *= 2;
    }

    SCLogDebug("PcapOverIPConnectUnix: connected to %s:%d", host, port);
    return socket_fd;
}
#endif /* OS_WIN32 */

static int PcapOverIPReadGlobalHeader(PcapOverIPThreadVars *ptv)
{
    struct pcap_file_header ghdr;
    ssize_t r = 0;

    while (true) {
#ifdef OS_WIN32
        r = recv(ptv->socket_fd, (char *)&ghdr, sizeof(ghdr), MSG_WAITALL);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
            continue;
        }
#else
        r = recv(ptv->socket_fd, &ghdr, sizeof(ghdr), MSG_WAITALL);
        if (r == -1 && errno == EINTR) {
            continue;
        }
#endif
        break;
    }

    if (r < 0) {
        SCLogError("PcapOverIP: error reading global header: %s", PcapOverIPGeErrorStr());
        return -1;
    }

    if (r == 0) {
        return 0; /* EOF */
    }

    if (r != (ssize_t)sizeof(ghdr))
        return -1;

    if (ghdr.magic == PCAP_MAGIC_NUMBER) {
        ptv->swapped = false;
    } else if (ghdr.magic == PCAP_SWAPPED_MAGIC) {
        ptv->swapped = true;
        ghdr.version_major = SWAPSHORT(ghdr.version_major);
        ghdr.version_minor = SWAPSHORT(ghdr.version_minor);
        ghdr.thiszone = SWAPLONG(ghdr.thiszone);
        ghdr.sigfigs = SWAPLONG(ghdr.sigfigs);
        ghdr.snaplen = SWAPLONG(ghdr.snaplen);
        ghdr.linktype = SWAPLONG(ghdr.linktype);
    } else {
        return -1;
    }

    ptv->snaplen = ghdr.snaplen;
    ptv->datalink = ghdr.linktype;

    return 0;
}

static int PcapOverIPReadPacketHeader(PcapOverIPThreadVars *ptv, struct pcap_pkthdr *pkthdr)
{
    struct pcap_sf_pkthdr sf_hdr;
    ssize_t r = 0;

    while (true) {
#ifdef OS_WIN32
        r = recv(ptv->socket_fd, (char *)&sf_hdr, sizeof(sf_hdr), MSG_WAITALL);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
            continue;
#else
        r = recv(ptv->socket_fd, &sf_hdr, sizeof(sf_hdr), MSG_WAITALL);
        if (r == -1 && errno == EINTR)
            continue;
#endif
        break;
    }

    if (r < 0) {
        SCLogError("PcapOverIP: error reading packet header: %s", PcapOverIPGeErrorStr());
        return -1;
    }

    if (r == 0) {
        return 0; /* EOF */
    }

    if (r != (ssize_t)sizeof(sf_hdr))
        return -1;

    if (ptv->swapped) {
        sf_hdr.ts.tv_sec = SWAPLONG(sf_hdr.ts.tv_sec);
        sf_hdr.ts.tv_usec = SWAPLONG(sf_hdr.ts.tv_usec);
        sf_hdr.len = SWAPLONG(sf_hdr.len);
        sf_hdr.caplen = SWAPLONG(sf_hdr.caplen);
    }

    pkthdr->ts.tv_sec = sf_hdr.ts.tv_sec;
    pkthdr->ts.tv_usec = sf_hdr.ts.tv_usec;
    pkthdr->len = sf_hdr.len;
    pkthdr->caplen = sf_hdr.caplen;
    SCLogNotice("PcapOverIP: packet header: len=%u, caplen=%u", pkthdr->len, pkthdr->caplen);
    return 1;
}

static int PcapOverIPReadPacketData(PcapOverIPThreadVars *ptv, uint8_t *buf, int buflen, int toread)
{
    if (toread > buflen) {
        SCLogError("PcapOverIP: packet size %d exceeds buffer size %d", toread, buflen);
        return -1;
    }

    ssize_t total = 0;
    while (total < toread) {
#ifdef OS_WIN32
        ssize_t r = recv(ptv->socket_fd, (char *)(buf + total), toread - total, MSG_WAITALL);
        if (r == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
            continue;
#else
        ssize_t r = recv(ptv->socket_fd, buf + total, toread - total, MSG_WAITALL);
        if (r == -1 && errno == EINTR)
            continue;
#endif

        if (r < 0) {
            SCLogError("PcapOverIP: error reading packet data: %s", PcapOverIPGeErrorStr());
            return -1;
        }
        total += r;
    }

    if (total != toread) {
        return -1;
    }

    return (int)total;
}

static int PcapOverIPReadPacket(
        PcapOverIPThreadVars *ptv, struct pcap_pkthdr *pkthdr, uint8_t *buf, int buflen)
{
    int hr = PcapOverIPReadPacketHeader(ptv, pkthdr);
    if (hr <= 0) {
        return hr; /* 0 => EOF, <0 => error */
    }

    if (pkthdr->caplen == 0 || pkthdr->caplen > (uint32_t)buflen) {
        return -1;
    }

    int dr = PcapOverIPReadPacketData(ptv, buf, buflen, pkthdr->caplen);
    if (dr < 0) {
        return -1;
    }

    return 1;
}

static int PcapOverIPApplyFilter(
        PcapOverIPThreadVars *ptv, struct pcap_pkthdr *pkthdr, const uint8_t *data)
{
    if (ptv->filter.bf_insns == NULL) {
        return 1;
    }
    return pcap_offline_filter(&ptv->filter, pkthdr, data);
}

static pcap_t *PcapOverIPOpenDead(int datalink, int snaplen)
{
    return pcap_open_dead(datalink, snaplen > 0 ? snaplen : MAX_PACKET_BUFFER_SIZE);
}

/* =========================================
 * Thread Initialization / Deinitialization
 * ========================================= */
static TmEcode ReceivePcapOverIPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    PcapOverIPIfaceConfig *config = (PcapOverIPIfaceConfig *)initdata;

    if (config == NULL) {
        SCLogError("PcapOverIP: initdata == NULL");
        return TM_ECODE_FAILED;
    }

    PcapOverIPThreadVars *ptv = SCCalloc(1, sizeof(PcapOverIPThreadVars));
    if (ptv == NULL) {
        config->DerefFunc(config);
        return TM_ECODE_FAILED;
    }

    ptv->tv = tv;
    ptv->bpf_filter_str = config->bpf_filter;
    ptv->checksum_mode = config->checksum_mode;

    char host[256];
    int port;
    if (PcapOverIPParseRemote(config->socket_addr, host, sizeof(host), &port) < 0) {
        SCLogError("PcapOverIP: invalid host:port: %s", config->socket_addr);
        SCFree(ptv);
        config->DerefFunc(config);
        return TM_ECODE_FAILED;
    }

    ptv->socket_fd = (int)socket(AF_INET, SOCK_STREAM, 0);

    if (ptv->socket_fd < 0) {
        SCLogError("PcapOverIP: could not create socket: %s", strerror(errno));
        SCFree(ptv);
        config->DerefFunc(config);
        return TM_ECODE_FAILED;
    }

    int ret = PcapOverIPConnect(ptv->socket_fd, host, port);
    if (ret < 0) {
        SCLogError("PcapOverIP: could not connect to %s", config->socket_addr);
        SCFree(ptv);
        config->DerefFunc(config);
        return TM_ECODE_FAILED;
    }

    if (PcapOverIPReadGlobalHeader(ptv) < 0) {
        SCLogError("PcapOverIP: could not read global header");
        close(ptv->socket_fd);
        SCFree(ptv);
        config->DerefFunc(config);
        return TM_ECODE_FAILED;
    }

    DatalinkSetGlobalType(ptv->datalink);

    if (ptv->bpf_filter_str) {
        SCLogInfo("using bpf-filter \"%s\"", ptv->bpf_filter_str);
        SCMutexLock(&pcap_bpf_compile_lock);
        pcap_t *dead_pcap = PcapOverIPOpenDead(ptv->datalink, ptv->snaplen);
        if (dead_pcap == NULL) {
            SCMutexUnlock(&pcap_bpf_compile_lock);
            SCLogError("PcapOverIP: failed to create dead pcap for filter");
            close(ptv->socket_fd);
            SCFree(ptv);
            config->DerefFunc(config);
            return TM_ECODE_FAILED;
        }
        if (pcap_compile(dead_pcap, &ptv->filter, (char *)ptv->bpf_filter_str, 1, 0) < 0) {
            SCLogError("PcapOverIP: bpf compilation error: %s", pcap_geterr(dead_pcap));
            pcap_close(dead_pcap);
            SCMutexUnlock(&pcap_bpf_compile_lock);
            close(ptv->socket_fd);
            SCFree(ptv);
            config->DerefFunc(config);
            return TM_ECODE_FAILED;
        }
        pcap_close(dead_pcap);
        SCMutexUnlock(&pcap_bpf_compile_lock);
    }

    ptv->capture_packets = StatsRegisterCounter("capture.pcap_over_ip_packets", ptv->tv);
    ptv->capture_bytes = StatsRegisterCounter("capture.pcap_over_ip_bytes", ptv->tv);

    config->DerefFunc(config);
    ptv->state = PCAPOVERIP_STATE_UP;
    *data = ptv;

    return TM_ECODE_OK;
}

static TmEcode ReceivePcapOverIPThreadDeinit(ThreadVars *tv, void *data)
{
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    if (ptv != NULL) {
        if (ptv->socket_fd > 0) {
            close(ptv->socket_fd);
        }
        if (ptv->filter.bf_insns) {
            SCBPFFree(&ptv->filter);
        }
        SCFree(ptv);
    }
    return TM_ECODE_OK;
}

static void ReceivePcapOverIPThreadExitStats(ThreadVars *tv, void *data)
{
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    SCLogNotice(
            "PcapOverIP: processed %" PRIu64 " packets, %" PRIu64 " bytes", ptv->pkts, ptv->bytes);
}

static TmEcode ReceivePcapOverIPBreakLoop(ThreadVars *tv, void *data)
{
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    if (ptv->socket_fd > 0) {
#if defined(OS_WIN32)
        shutdown(ptv->socket_fd, SD_RECEIVE);
#else
        shutdown(ptv->socket_fd, SHUT_RD);
#endif
    }
    return TM_ECODE_OK;
}

static void PcapOverIPDumpCounters(PcapOverIPThreadVars *ptv)
{
    StatsSetUI64(ptv->tv, ptv->capture_packets, ptv->pkts);
    StatsSetUI64(ptv->tv, ptv->capture_bytes, ptv->bytes);
}

static TmEcode ReceivePcapOverIPLoop(ThreadVars *tv, void *data, void *slot)
{
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    TmThreadsSetFlag(tv, THV_RUNNING);

    uint8_t packet_buf[MAX_PACKET_BUFFER_SIZE];
    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            return TM_ECODE_OK;
        }

        PacketPoolWait();

        struct pcap_pkthdr pkthdr;
        int r = PcapOverIPReadPacket(ptv, &pkthdr, packet_buf, sizeof(packet_buf));
        if (r == 0) {
            /* EOF */
            break;
        } else if (r < 0) {
            SCLogError("PcapOverIP: read error");
            return TM_ECODE_FAILED;
        }

        if (!PcapOverIPApplyFilter(ptv, &pkthdr, packet_buf)) {
            /* packet filtered out */
            continue;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            continue;
        }

        PKT_SET_SRC(p, PKT_SRC_WIRE);
        p->ts.secs = pkthdr.ts.tv_sec;
        p->ts.usecs = pkthdr.ts.tv_usec;
        p->datalink = ptv->datalink;

        ptv->pkts++;
        ptv->bytes += pkthdr.caplen;

        if (unlikely(PacketCopyData(p, packet_buf, pkthdr.caplen))) {
            TmqhOutputPacketpool(tv, p);
            continue;
        }

        if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO ||
                ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }

        if (TmThreadsSlotProcessPkt(tv, ptv->slot, p) != TM_ECODE_OK) {
            ptv->cb_result = TM_ECODE_FAILED;
            break;
        }

        SCTime_t current_time = TimeGet();
        if ((time_t)SCTIME_SECS(current_time) != ptv->last_stats_dump) {
            PcapOverIPDumpCounters(ptv);
            ptv->last_stats_dump = SCTIME_SECS(current_time);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    PcapOverIPDumpCounters(ptv);
    StatsSyncCountersIfSignalled(tv);
    return TM_ECODE_OK;
}

/***********************************************
 * Decoder threads
 ***********************************************/
static TmEcode DecodePcapOverIPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL)
        return TM_ECODE_FAILED;

    DecodeRegisterPerfCounters(dtv, tv);
    *data = dtv;
    return TM_ECODE_OK;
}

static TmEcode DecodePcapOverIPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    return TM_ECODE_OK;
}

static TmEcode DecodePcapOverIP(ThreadVars *tv, Packet *p, void *data)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    DecodeUpdatePacketCounters(tv, dtv, p);
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}
