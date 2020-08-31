/* Copyright (C) 2020 Open Information Security Foundation
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
#include "util-time.h"
#include "stream-tcp-private.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
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

static int GenerateStreamFilenameTimebuf(char *time_buf,size_t time_buf_size,
                                   time_t packet_time);
static void DumpTcpSegment(TcpSession *session, TcpSegment *seg,
                          pcap_dumper_t *dump_handle, bool client);
static int GenerateStreamFilepath(char *result_path_buf, size_t result_buf_size,
                            TaggedPcapEntry *tpe);

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
 * \brief Fills the time_buf with a time string that will be used in the pcap
 *  filename.
 * \param time_buf buffer to hold the time string.
 * \param time_buf_size length of the time buffer.
 * \param packet_time time value that is used to generate the time string.
 * \retual 1 if creation of filename timebuf is successful
 * \retval -1 if creation of filename timebuf is not successful
 */
static int GenerateStreamFilenameTimebuf(char *time_buf, size_t time_buf_size,
        time_t packet_time)
{
    time_t time = packet_time;
    struct tm local_tm;
    struct tm *t = SCLocalTime(time, &local_tm);

    if (unlikely(t == NULL)) {
        SCLogError(SC_ERR_TS, "Unable to create time structure, ts-error");
        return -1;
    }

    char fmt_time_buf[64];
    CreateFormattedTimeString(t, "%Y%m%d_%H%M%S.%%06u", fmt_time_buf,
                              sizeof(fmt_time_buf));

    int ret = snprintf(time_buf, time_buf_size,
                       fmt_time_buf, packet_time);
    if (ret < 0 || (size_t) ret >= time_buf_size) {
        SCLogError(SC_ERR_INVALID_NUM_BYTES, "Provided buffer size is too "
                                             "small to create full time "
                                             "buffer. Error: %s",
                                             strerror(errno));
        return -1;
    } else {
        return 1;
    }
}

/**
 *  \brief Fills the result_path_buf with a full file path that can be used
 *   to create a file. InitializePcapLogFilenameSupport() must be run before
 *   this is called
 *  \param result_path_buf buffer to hold the path string.
 *  \param result_buf_size length of the filename buffer used.
 *  \param p packet pointer.
 *  \param signature that alerted.
 *  \param thread_id unique id for the current thread.
 *  \param unique_id counter incrementing over time to add entropy to filenames.
 *  \retual 1 if creation of filepath is successful
 *  \retval -1 if creation of filepath is not successful
 */
static int GenerateStreamFilepath(char *result_path_buf, size_t result_buf_size,
        TaggedPcapEntry *tpe)
{
    if (tpe == NULL || result_path_buf == NULL) {
        return -1;
    }
    char time_buf[FILENAME_TIMEBUF_SIZE];
    if (GenerateStreamFilenameTimebuf(time_buf, FILENAME_TIMEBUF_SIZE, tpe->time) != 1){
        return -1;
    }
    int ret;

    ret = snprintf(result_path_buf, result_buf_size,"%s/%u-%u.%s.%u.%s.pcap",
            g_output_config.g_output_dir, tpe->thread_id, tpe->unique_id,
            g_output_config.g_hostname, tpe->signature_id, time_buf);

    if (ret < 0 || (size_t) ret >= result_buf_size) {
        SCLogError(SC_ERR_INVALID_NUM_BYTES, "Provided buffer size is too "
                                             "small to create PCAP file path. "
                                             "Error: %s", strerror(errno));
        return -1;
    } else {
        return 1;
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
    char *pcap_file_path = (char *) SCCalloc(1, sizeof(char) * PATH_MAX);
    if (unlikely(pcap_file_path == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for pcap dump file path.");
        return NULL;
    }
    TaggedPcapEntry *tpe = (TaggedPcapEntry*) SCCalloc(1,sizeof(*tpe));
    if (unlikely(tpe == NULL)) {
        return NULL;
    }
    /*
     * Initialize tpe's id & time variables
     */
    tpe->time = p->ts.tv_usec;
    tpe->thread_id = thread_id;
    tpe->unique_id = unique_id;
    tpe->signature_id = sig->id;

    if (GenerateStreamFilepath(pcap_file_path, PATH_MAX, tpe) != 1) {
        SCFree(pcap_file_path);
        SCFree(tpe);
        SCLogError(SC_ERR_PCAP_DUMP_FILE, "Error creating filepath for pcap dump.");
        return NULL;
    }

    tpe->pcap_dead_handle = pcap_open_dead(p->datalink, PCAP_SNAPLEN);
    if (tpe->pcap_dead_handle == NULL) {
        SCLogError(SC_ERR_PCAP_DUMP_OPEN, "Error opening dead pcap "
                                          "handle: %s",
                                          pcap_geterr(tpe->pcap_dead_handle));
        SCFree(pcap_file_path);
        SCFree(tpe);
        return NULL;
    }

    tpe->pcap_dumper = pcap_dump_open(tpe->pcap_dead_handle,
            pcap_file_path);
    if (tpe->pcap_dumper == NULL) {
        SCLogError(SC_ERR_PCAP_DUMP_OPEN, "Failed to create tag output "
                                          "file at %s. Error: %s",
                                          pcap_file_path,
                                          pcap_geterr(tpe->pcap_dead_handle));
        SCFree(pcap_file_path);
        SCFree(tpe);
        return NULL;
    }

    SCFree(pcap_file_path);
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
        SCFree(tpe);
    }
}

/**
 *  \brief Log the packet passed in to the relevant TaggedPcapEntry. The
 *   logging destination is a pcap dumper.
 *  \param dump_handle pcap_dumper location.
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
    if (server_node == NULL && client_node == NULL) {
        return;
    }

    while (server_node != NULL || client_node != NULL) {
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
            if TIMEVAL_EARLIER(client_node->pcap_hdr_storage->ts, server_node->pcap_hdr_storage->ts) {
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
 * \param seg TcpSegment to be dumped to pcap.
 * \param dump_handle pcap_dumper location.
 * \bool client direction of segment (to client or to server).
 */
static void DumpTcpSegment(TcpSession *session, TcpSegment *seg,
        pcap_dumper_t *dump_handle, bool client)
{
    if (seg->pcap_hdr_storage == NULL || seg->pcap_hdr_storage->pkt_hdr == NULL)
    {
        return;
    }
    struct pcap_pkthdr pcap_hdr;
    uint32_t packet_len = seg->pcap_hdr_storage->pktlen;
    uint32_t payload_len = seg->payload_len;
    uint32_t packet_header_len = packet_len - payload_len;

    pcap_hdr.ts.tv_sec = seg->pcap_hdr_storage->ts.tv_sec;
    pcap_hdr.ts.tv_usec = seg->pcap_hdr_storage->ts.tv_usec;

    if (client) {
        SplitPcapDump((u_char *) dump_handle, &pcap_hdr,
                seg->pcap_hdr_storage->pkt_hdr, packet_header_len,
                session->client.sb.buf + seg->sbseg.stream_offset, payload_len);
    } else {
        SplitPcapDump((u_char *) dump_handle, &pcap_hdr,
                seg->pcap_hdr_storage->pkt_hdr, packet_header_len,
                session->server.sb.buf + seg->sbseg.stream_offset, payload_len);
        }
}
