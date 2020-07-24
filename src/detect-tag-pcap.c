/* Copyright (C) 2007-2020 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect-tag-pcap.h"
#include "decode.h"
#include "pcap-helper.h"
#include "util-path.h"
#include "util-time.h"
#include "stream-tcp-private.h"
#include <pthread.h>
#include <errno.h>

#ifndef HOST_NAME_MAX
#ifdef __APPLE__
#define HOST_NAME_MAX 255
#elif defined(_WIN32) || defined(_WIN64)
#define HOST_NAME_MAX 255
#endif
#endif

/* PCAP_SNAPLEN (snapshot length) is the amount of data available per capture.
 * The default is 262144 bytes. Setting the snaplen to 0 will set it to
 * this default value, but also allow for backwards compatibility for older
 * versions of tcpdump. */
#define PCAP_SNAPLEN 0

typedef struct OutputConfig_ {
    char g_hostname[HOST_NAME_MAX];
    const char *g_output_dir;
} OutputConfig;

OutputConfig g_output_config;

static void DumpTcpSegment(TcpSession *session, TcpSegment *seg,
                          pcap_dumper_t *dump_handle, bool client);

/**
 * \brief Initializes filename for output pcap log.
 * \param output_directory Configurable filename from suricata.yaml.
 */
void InitializePcapLogFilenameSupport(const char *output_directory)
{
    if(gethostname(g_output_config.g_hostname, sizeof(g_output_config.g_hostname))
        != 0) {
        FatalError(SC_ERR_HOST_INIT, "Error looking up hostname in "
                                     "detect-tag-pcap.c Error: %s",
                                     strerror(errno));
    }

    if (output_directory == NULL) {
        g_output_config.g_output_dir = ConfigGetLogDirectory();
    } else {
        g_output_config.g_output_dir = output_directory;
    }
}

/**
 *  \brief Fills the result_path_buf with a full file path that can be used
 *   to create a file. InitializePcapLogFilenameSupport() must be run before
 *   this is called.
 *  \param result_path_buf buffer to hold the path string.
 *  \param result_buf_size length of the filename buffer used.
 *  \param p packet pointer.
 *  \param signature that alerted.
 *  \param thread_id unique id for the current thread.
 *  \param unique_id counter incrementing over time to add entropy to filenames.
 */
void GenerateStreamFilepath(char *result_path_buf, size_t result_buf_size,
        const Packet *p, const Signature *sig, int thread_id, uint32_t
        unique_id)
{
    time_t time = p->ts.tv_usec;
    struct tm local_tm;
    struct tm *t = SCLocalTime(time, &local_tm);
    if (unlikely(t == NULL)) {
        FatalError(SC_ERR_TS, "Unable to create time structure, ts-error");
    }

    char fmt_time_buf[64];
    CreateFormattedTimeString(t, "%Y%m%d_%H%M%S.%%06u", fmt_time_buf,
            sizeof(fmt_time_buf));

    char time_buf[64];
    int ret = snprintf(time_buf, sizeof(time_buf),
            fmt_time_buf, p->ts.tv_usec);
    if (ret < 0 || (size_t) ret >= sizeof(time_buf)) {
        SCLogError(SC_ERR_INVALID_NUM_BYTES, "Provided buffer size is too small"
                                             "to create full time buffer."
                                             " Error: %s", strerror(errno));
    }

    ret = snprintf(result_path_buf, result_buf_size,"%s/.%u-%u.%s.%u.%s.pcap",
            g_output_config.g_output_dir, thread_id, unique_id,
            g_output_config.g_hostname, sig->id, time_buf);

    if (ret < 0 || (size_t)ret >= result_buf_size) {
        FatalError(SC_ERR_INVALID_NUM_BYTES, "Provided buffer size is too "
                                             "small to create PCAP file path."
                                             " Error: %s", strerror(errno));
    }
}

/**
 *  \brief Registration for TaggedPcapEntry when writing the output to files.
 *  \param p pointer to the packet being alerted on.
 *  \param sig signature that triggered the alert.
 *  \param thread_id id of the thread we're on; used for uniqueness in filename.
 *  \param unique_id unique counter per thread that increments to increase
 *  the entropy of filenames.
 */
TaggedPcapEntry *SetupTaggedPcap(const Packet *p, const Signature *sig, int
        thread_id, int unique_id)
{
     TaggedPcapEntry *tpe = (TaggedPcapEntry*) SCMalloc(sizeof(*tpe));
     if (unlikely(tpe == NULL)) {
         return NULL;
     }
     tpe->pcap_file_path[0] = '\0';

     GenerateStreamFilepath(tpe->pcap_file_path, PCAP_PATH_MAX, p, sig,
             thread_id, unique_id);

     tpe->pcap_dead_handle = pcap_open_dead(p->datalink, PCAP_SNAPLEN);
     if (tpe->pcap_dead_handle == NULL) {
         SCLogError(SC_ERR_PCAP_OPEN_OFFLINE, "Error opening dead pcap "
                                              "handle: %s", pcap_geterr
                                              (tpe->pcap_dead_handle));
         SCFree(tpe);
         exit(EXIT_FAILURE);
     }

     tpe->pcap_dumper = pcap_dump_open(tpe->pcap_dead_handle,
             tpe->pcap_file_path);
     if (tpe->pcap_dumper == NULL) {
         SCLogError(SC_ERR_PCAP_OPEN_OFFLINE, "Failed to create tag output "
                                              "file at %s. Error: %s",
                                              tpe->pcap_file_path,
                                              pcap_geterr(tpe->pcap_dead_handle));
         SCFree(tpe);
         exit(EXIT_FAILURE);
     }
     return tpe;
}

/**
 *  \brief Frees memory associated with TagDataPcapEntry
 *  \param tpe tagged pcap file object to clean up
 */
void CleanUpTaggedPcap(TaggedPcapEntry *tpe)
{
    if (tpe != NULL) {
        pcap_dump_close(tpe->pcap_dumper);
        pcap_close(tpe->pcap_dead_handle);
        SCUndotFilepath(tpe->pcap_file_path);
        SCFree(tpe);
    }
}

/**
 *  \brief Log the packet passed in to the relevant TaggedPcapEntry. The
 *   logging destination is a pcap_dumper.
 *  \param tpe tagged pcap file object to dump packets to.
 *  \param p packet structure to log packets from.
 */
void DumpTaggedPacket(pcap_dumper_t *dump_handle, const Packet *p)
{
    struct pcap_pkthdr pcap_hdr;
    pcap_hdr.ts.tv_sec = p->ts.tv_sec;
    pcap_hdr.ts.tv_usec = p->ts.tv_usec;
    pcap_hdr.caplen = GET_PKT_LEN(p);
    pcap_hdr.len = GET_PKT_LEN(p);
    pcap_dump((u_char *) dump_handle, &pcap_hdr, GET_PKT_DATA(p));
}

/**
 *  \brief Logs TcpSession to pcap file. Should be called immediately after
 *   creation of the pcap file. Scans through the TcpSegment RB Trees on both
 *   client and server side and dumps the segments in order to pcap file.
 *  \param session to be dumped to pcap.
 *  \param dump_handle pcap_dumper location.
 *  \param p Packet being processed at time of alert.
 */
void LogTcpSession(TcpSession *session, pcap_dumper_t *dump_handle, const
        Packet *p)
{
    TcpSegment *server_node = session->server.seg_tree.rbh_root;
    TcpSegment *client_node = session->client.seg_tree.rbh_root;

    while(server_node != NULL || client_node != NULL){
        if (server_node == NULL) {
            /*
             * This means the server side RB Tree has been completely searched,
             * thus all that remains is to dump the TcpSegments on the client
             * side.
             */
            DumpTcpSegment(session, client_node, dump_handle, true);
            client_node = TCPSEG_RB_NEXT(client_node);
        } else if (client_node == NULL) {
            /*
             * This means the client side RB Tree has been completely searched,
             * thus all that remains is to dump the TcpSegments on the server
             * side.
             */
            DumpTcpSegment(session, server_node, dump_handle, false);
            server_node = TCPSEG_RB_NEXT(server_node);
        } else {
            if (client_node->pcap_cnt < server_node->pcap_cnt) {
                DumpTcpSegment(session, client_node, dump_handle, true);
                client_node = TCPSEG_RB_NEXT(client_node);
            } else {
                DumpTcpSegment(session, server_node, dump_handle, false);
                server_node = TCPSEG_RB_NEXT(server_node);
            }
        }
    }
}

/**
 * \brief Dumps content of a TcpSegment to specified pcap output file.
 * \param tcpSegment to be dumped to pcap.
 * \param dump_handle pcap_dumper location.
 * \bool client direction of segment (to client or to server).
 */
static void DumpTcpSegment(TcpSession *session, TcpSegment *seg,
        pcap_dumper_t *dump_handle, bool client)
{
    struct pcap_pkthdr pcap_hdr;
    uint32_t packet_len = seg->pktlen;
    uint32_t payload_len = seg->payload_len;
    uint32_t packet_header_len = packet_len - payload_len;

    pcap_hdr.ts.tv_sec = seg->ts.tv_sec;
    pcap_hdr.ts.tv_usec = seg->ts.tv_usec;

    if (seg->pkt_hdr != NULL) {
        if (client) {
            SplitPcapDump((u_char *) dump_handle, &pcap_hdr, seg->pkt_hdr,
                    packet_header_len, session->client.sb.buf +
                    seg->sbseg.stream_offset, payload_len);
        } else {
            SplitPcapDump((u_char *) dump_handle, &pcap_hdr, seg->pkt_hdr,
                    packet_header_len, session->server.sb.buf +
                    seg->sbseg.stream_offset, payload_len);
        }
    }
}
