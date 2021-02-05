/* Copyright (C) 2021 Open Information Security Foundation
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
 *  An extension of the pcap-log module, that is very similar, but requires unique logging as
 *  pcaps are generated on a per alert basis and need to be separate captures from one another.
 *  Enabled through signature tags (tag:session; must be in the signature) AND
 *  through suricata.yaml:
 *      outputs:
 *          - pcap-log:
 *              enabled: yes
 *              mode: capture-alert
 *
 *  Features of the pcap-log module such as compression and use of a ring buffer have not been
 *  implemented. To prevent against huge flows, file size limits set in suricata.yaml are still
 *  enabled. Additionally, limits defined in log-pcap-capture-alert.h guide the organization of
 *  the capture files, as there is potential for a significant amount of capture files. They are
 *  as follows:
 *      MAX_CAPTURE_DIRS_PER_DIR: The maximum number of directories in a directory
 *      containing directories of alert captures.
 *      MAX_CAPTURES_PER_DIR: The maximum number of alerts able to exist in each directory.
 *      MAX_CAPTURES_PER_ALERT: The maximum number of capture files for a single alert. The maximum
 *      total size permitted for a single alert would be MAX_CAPTURES_PER_ALERT x file size limit.
 *
 *  Compression and ring buffer are possibilities for further development, but it isn't clear
 *  whether a ring buffer would actually be beneficial as overwriting a capture would lead to
 *  the deletion of the packet that was the cause of an alert.
 */

#include "suricata-common.h"
#include "detect-engine-tag.h"
#include "log-pcap.h"
#include "log-pcap-capture-alert.h"
#include "util-time.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

/* PCAP_SNAPLEN (snapshot length) is the amount of data available per capture.
 * The default is 262144 bytes. Setting the snaplen to 0 will set it to
 * this default value, but also allow for backwards compatibility for older
 * versions of tcpdump. */
#define PCAP_SNAPLEN 0
#define FILENAME_TIMEBUF_SIZE 64

/// Forward Declarations
void CloseTaggedPcap(TaggedPcapEntry *tpe);
void DumpTaggedPacket(pcap_dumper_t *dump_handle, const Packet *p);
static int GenerateStreamFilepath(char *result_path_buf, size_t result_buf_size,
                                  PcapLogData *pcap_log, TaggedPcapEntry *tpe);
static int GenerateStreamFilenameTimebuf(char *time_buf, size_t time_buf_size,
                                         time_t packet_time);
static int PcapLogAlertCapturesCreateDir(PcapLogData *pl, char* time_buf);
static int PcapLogAlertCreateDir(PcapLogData *pl, char* time_buf);
static int PcapLogRotateAlertCaptureFile(ThreadVars *t, PcapLogData *pcap_log, TaggedPcapEntry *tpe,
                                  const Packet *p);
TaggedPcapEntry *SetupTaggedPcap(const Packet *p, const Signature *sig, PcapLogThreadData *td,
                                 int thread_id);


/**
 * \brief Creates directory that will contain multiple directories of alert captures.
 * \param pl PcapLogData where the directory name is stored.
 * \param time_buf time string generated from the packet time used to organize the directory
 * \return Returns 0 upon success and -1 upon failure.
 */
static int PcapLogAlertCreateDir(PcapLogData *pl, char* time_buf)
{
    char *alert_dirname = NULL;
    char alert_dir_path[PATH_MAX];

    if (pl->alert_dirname != NULL)
    {
        alert_dirname = pl->alert_dirname;
    } else {
        alert_dirname = SCMalloc(NAME_MAX);
        if (unlikely(alert_dirname == NULL)) {
            return -1;
        }
        pl->alert_dirname = alert_dirname;
    }

    /** Clear the old alert directory name */
    memset(pl->alert_dirname, 0x00, NAME_MAX);

    /** Assemble new alert directory name and create it */

    int ret;
    ret = snprintf(pl->alert_dirname, NAME_MAX, "alerts-%s", time_buf);
    if (ret < 0 || (size_t)ret >= NAME_MAX) {
        SCLogError(SC_ERR_SPRINTF,"failed to construct alert directory name for log pcap module");
        return -1;
    } else {
        ret = snprintf(alert_dir_path, PATH_MAX, "%s/%s", pl->dir, pl->alert_dirname);
        if (ret < 0 || (size_t)ret >= NAME_MAX) {
            SCLogError(SC_ERR_SPRINTF,"failed to construct path");
            return -1;
        } else {
            /* if mkdir fails file open will fail, so deal with errors there */
            (void)SCMkDir(alert_dir_path, 0700);
            pl->alert_dir_cnt++;
            return 0;
        }
    }

}

/**
 * \brief Creates directory that will contain alert captures.
 * \param pl PcapLogData where the directory name is stored.
 * \param time_buf time string generated from the packet time used to organize the directory
 * \return Returns 0 upon success and -1 upon failure.
 */
static int PcapLogAlertCapturesCreateDir(PcapLogData *pl, char* time_buf)
{
    char *alert_capture_dirname = NULL;
    if (pl->alert_capture_dirname != NULL)
    {
        alert_capture_dirname = pl->alert_capture_dirname;
    } else {
        alert_capture_dirname = SCMalloc(PATH_MAX);
        if (unlikely(alert_capture_dirname == NULL)) {
            return -1;
        }
        pl->alert_capture_dirname = alert_capture_dirname;
    }

    /** Clear the old capture directory name */
    memset(pl->alert_capture_dirname, 0x00, PATH_MAX);

    /** Assemble Folder Path */
    int ret;
    ret = snprintf(pl->alert_capture_dirname, PATH_MAX, "%s/%s/alert-captures-%" PRIu32 "-%s",
            pl->dir, pl->alert_dirname, (uint32_t) pl->thread_number, time_buf);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        SCLogError(SC_ERR_SPRINTF,"failed to construct path");
        return -1;
    } else {
        /* if mkdir fails file open will fail, so deal with errors there */
        (void)SCMkDir(pl->alert_capture_dirname, 0700);
        return 0;
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
        PcapLogData *pcap_log, TaggedPcapEntry *tpe)
{
    if (tpe == NULL || result_path_buf == NULL) {
        return -1;
    }
    char time_buf[FILENAME_TIMEBUF_SIZE];
    if (GenerateStreamFilenameTimebuf(time_buf, FILENAME_TIMEBUF_SIZE, tpe->time) != 1){
        return -1;
    }

    if (pcap_log->alert_dirname == NULL ||
            pcap_log->alert_dir_cnt % MAX_CAPTURE_DIRS_PER_DIR == 0) {
        PcapLogAlertCreateDir(pcap_log, time_buf);
    }

    if (pcap_log->alert_capture_dirname == NULL ||
            pcap_log->alert_capture_cnt % MAX_CAPTURES_PER_DIR == 0) {
        PcapLogAlertCapturesCreateDir(pcap_log, time_buf);
    }
    int ret;

    ret = snprintf(result_path_buf, result_buf_size,"%s/%u-%u-%u-%s-%u%s",
                   pcap_log->alert_capture_dirname, tpe->thread_id, tpe->unique_id,
                   tpe->signature_id, time_buf, tpe->file_cnt, PCAP_SUFFIX);

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
TaggedPcapEntry *SetupTaggedPcap(const Packet *p, const Signature *sig, PcapLogThreadData *td,
        int thread_id)
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
    tpe->unique_id = td->pcap_log->alert_capture_cnt;
    tpe->signature_id = sig->id;
    tpe->size_current = 0;
    tpe->size_limit = td->pcap_log->size_limit;
    tpe->file_cnt = 1;

    if (GenerateStreamFilepath(pcap_file_path, PATH_MAX, td->pcap_log, tpe) != 1) {
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
    td->pcap_log->alert_capture_cnt++;
    return tpe;
}

/**
 * /brief Rotates the alert capture file if it has reached the file limit size. This is specific to
 *  each alert capture. The maximum number of files generated per alert is defined in
 *  log-pcap-capture-alert.h as MAX_CAPTURES_PER_ALERT. After this limit data is no longer captured
 *  for this alert.
 * \param t ThreadVars containing information for new filename generation.
 * \param pcap_log PcapLogData containing information for new filename and path generation.
 * \param tpe TaggedPcapEntry whose dump handle, dumper, and size will need to be updated.
 * \param p pointer to the packet being alerted on.
 * \return 0 upon success and -1 upon failure.
 */
static int PcapLogRotateAlertCaptureFile(ThreadVars *t, PcapLogData *pcap_log, TaggedPcapEntry *tpe,
       const Packet *p)
{
    CloseTaggedPcap(tpe);
    char *pcap_file_path = (char *) SCCalloc(1, sizeof(char) * PATH_MAX);
    if (unlikely(pcap_file_path == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for pcap dump file path.");
        return -1;
    }
    tpe->file_cnt++;

    if (GenerateStreamFilepath(pcap_file_path, PATH_MAX, pcap_log, tpe) != 1) {
        SCFree(pcap_file_path);
        SCLogError(SC_ERR_PCAP_DUMP_FILE, "Error creating filepath when rotating pcap dump.");
        return -1;
    }

    tpe->pcap_dead_handle = pcap_open_dead(p->datalink, PCAP_SNAPLEN);
    if (tpe->pcap_dead_handle == NULL) {
        SCLogError(SC_ERR_PCAP_DUMP_OPEN, "Error opening dead pcap "
                                          "handle: %s",
                   pcap_geterr(tpe->pcap_dead_handle));
        SCFree(pcap_file_path);
        return -1;
    }

    tpe->pcap_dumper = pcap_dump_open(tpe->pcap_dead_handle,
                                      pcap_file_path);
    if (tpe->pcap_dumper == NULL) {
        SCLogError(SC_ERR_PCAP_DUMP_OPEN, "Failed to create tag output "
                                          "file at %s. Error: %s",
                   pcap_file_path,
                   pcap_geterr(tpe->pcap_dead_handle));
        SCFree(pcap_file_path);
        return -1;
    }

    SCFree(pcap_file_path);
    pcap_log->alert_capture_cnt++;
    return 0;
}

/**
 * \brief Generate pcap events for the alerted packet. Handles single packet
 *  protocols/alerts and multiple packet alerts. For single packet
 *  alerts, the alert file or event message are created and output.
 *  For multiple packet alerts, the pcap file is created.
 * \param tv thread-specific variables.
 * \param td thread data containing the output context.
 * \param p Pointer to current packet being processed.
 */
void GeneratePcapFiles(ThreadVars *tv, PcapLogThreadData *td,
                              const Packet *p)
{
    if (!(p->flags & PKT_HAS_FLOW) && p->flags & PKT_HAS_TAG) {
        /*
         * Some single packet protocols won't have a flow created for them.
         * A tagged rule alert can still trigger on the packet meaning we'd
         * still want to produce a PCAP.
         */
        for (uint16_t x = 0; x < p->alerts.cnt; x++) {
            /* Is the alert from a tagged signature? */
            if (p->alerts.alerts[x].s->sm_arrays[DETECT_SM_LIST_TMATCH] !=
                NULL) {
                TaggedPcapEntry *pcap_file = SetupTaggedPcap(p, p->alerts
                        .alerts->s, td, tv->id);
                if (pcap_file == NULL) {
                    /*
                     * SCLogErrors are handled in SetupTaggedPcap.
                     */
                    return;
                }
                DumpTaggedPacket(pcap_file->pcap_dumper, p);
                CleanUpTaggedPcap(pcap_file);
            }
        }
    }

    /**
     *  The flow is locked during this method call. It's safe to read and
     *  modify session tags.
     */
    DetectTagDataEntry *tags = TagGetFlowTag(p->flow);

    /**
     *  Log this packet to every tag's output PCAP stream. The detect-tag
     *  code will handle cleanup and deletion of expired tags.
     */
    while (tags != NULL) {
        DetectTagDataEntry *current_tag = tags;
        tags = tags->next;
        /* Initialize the tag's output(s) PCAP stream if not already done. */
        if (current_tag->pcap_file == NULL) {
            /**
              * Find the Signature instance inside the packet that matches
              * the tag's SID.
              */
            const PacketAlert *tag_alert = NULL;
            for (uint16_t x=0; x < p->alerts.cnt; x++) {
                if (p->alerts.alerts[x].s->id == current_tag->sid) {
                    tag_alert = &p->alerts.alerts[x];
                    break;
                }
            }
            if (tag_alert == NULL) {
                /**
                   * This case happens when a rule hits its threshold
                   * settings. The alert doesn't get generated but the
                   * tagging will still occur. Skip the tag.
                   */
                continue;
            }
            current_tag->pcap_file = SetupTaggedPcap(p, tag_alert->s, td, tv->id);

            if (current_tag->pcap_file == NULL) {
                /*
                 * SCLogErrors are handled in SetupTaggedPcap.
                 */
                return;
            }
        }

        if (current_tag->pcap_file->size_current + GET_PKT_LEN(p) >
                        current_tag->pcap_file->size_limit && current_tag->pcap_file->file_cnt <
                        MAX_CAPTURES_PER_ALERT) {
            PcapLogRotateAlertCaptureFile(tv, td->pcap_log, current_tag->pcap_file, p);
        }
        if (current_tag->pcap_file->file_cnt < MAX_CAPTURES_PER_ALERT) {
            DumpTaggedPacket(current_tag->pcap_file->pcap_dumper, p);
            current_tag->pcap_file->size_current += GET_PKT_LEN(p);
        }
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
 * \brief This closes the TaggedPcapEntry's pcap dumper and dump handle and resets the size. This is
 * used when rotating the file.
 * \param tpe The TaggedPcapEntry whose pcap dumper and dump handle are closed.
 */
void CloseTaggedPcap(TaggedPcapEntry *tpe)
{
    if (tpe != NULL) {
        pcap_dump_close(tpe->pcap_dumper);
        pcap_close(tpe->pcap_dead_handle);
    }
    tpe->size_current = 0;
    return;
}

/**
 *  \brief Frees memory associated with TagDataPcapEntry.
 *  \param tpe tagged pcap file object to clean up.
 */
void CleanUpTaggedPcap(TaggedPcapEntry *tpe)
{
    if (tpe != NULL) {
        pcap_dump_close(tpe->pcap_dumper);
        pcap_close(tpe->pcap_dead_handle);
        SCFree(tpe);
    }
}
