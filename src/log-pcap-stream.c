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

/**
 *  Pcap packet logging module.
 *  Enabled through suricata.yaml:
 *  - stream-pcap-log:
 *      enabled: yes/no
 *      output_directory: # Defaults to default-log-dir
 *      session-dump: yes/no # Dumps tcp session upon creation of pcap file.
 */
#include "suricata-common.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "log-pcap-stream.h"
#include "util-atomic.h"
#include "output.h"
#include "detect-engine-tag.h"

#define MODULE_NAME "PcapLogStream"

/**
 *  \brief Variable to store the output context. Contains the filename of the
 *   output file.
 */
typedef struct StreamOutputCtx_ {
    char filename[NAME_MAX];
    bool session_dump_enabled;
} StreamOutputCtx;

/**
 *  \brief Variables to maintain context on this thread.
 */
typedef struct StreamPcapLogThreadData_ {
    uint32_t count;
    StreamOutputCtx *stream_output_ctx;
} StreamPcapLogThreadData;

/* Forward declarations for registration. */

static int StreamPcapLog(ThreadVars *tv, void *thread_data, const Packet *p);
static int StreamPcapLogCondition(ThreadVars *tv, const Packet *p);
static TmEcode StreamPcapLogThreadInit(ThreadVars *tv, const void *initdata,
                                       void **data);
static TmEcode StreamPcapLogThreadDeInit(ThreadVars *tv, void *thread_data);
static OutputInitResult StreamPcapLogInitCtx(ConfNode *conf);
static void StreamPcapLogFileDeInitCtx(OutputCtx *output_ctx);

static StreamOutputCtx *getStreamOutputCtx(const OutputCtx *output_ctx);
static void GeneratePcapFiles(ThreadVars *tv, StreamPcapLogThreadData *td,
                              const Packet* p);

/**
 * \brief Stream pcap logging main function.
 * \param tv thread-specific variables.
 * \param thread_data thread module specific data.
 * \param p Pointer to current packet being processed.
 * \return TM_ECODE_OK on success.
 */
static int StreamPcapLog(ThreadVars *tv, void *thread_data, const Packet *p)
{
    StreamPcapLogThreadData *td = (StreamPcapLogThreadData *) thread_data;
    td->count++;
    GeneratePcapFiles(tv, thread_data, p);
    return TM_ECODE_OK;
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
static void GeneratePcapFiles(ThreadVars *tv, StreamPcapLogThreadData *td,
        const Packet* p)
{
    if (!(p->flags & PKT_HAS_FLOW)) {
        /*
         * Single packet protocols (eg. ICMP) won't have a flow created for
         * them. A tagged rule alert can still trigger on the packet meaning
         * we'd want to produce a PCAP.
         */
        for (uint16_t x = 0; x < p->alerts.cnt; x++) {
            /* Is the alert from a tagged signature? */
            if (p->alerts.alerts[x].s->sm_arrays[DETECT_SM_LIST_TMATCH] !=
            NULL) {
                TaggedPcapEntry *pcap_file = SetupTaggedPcap(p, p->alerts
                .alerts->s, tv->id, td->count);
                DumpTaggedPacket(pcap_file->pcap_dumper, p);
                CleanUpTaggedPcap(pcap_file);
            }
        }
        return;
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
               const PacketAlert* tagAlert = NULL;
               for (uint16_t x=0; x < p->alerts.cnt; x++) {
                   if (p->alerts.alerts[x].s->id == current_tag->sid) {
                       tagAlert = &p->alerts.alerts[x];
                       break;
                   }
               }
               if (tagAlert == NULL) {
                   /**
                    * This case happens when a rule hits its threshold
                    * settings. The alert doesn't get generated but the
                    * tagging will still occur. Skip the tag.
                    */
                    continue;
               }
               current_tag->pcap_file = SetupTaggedPcap(p, tagAlert->s,
                       tv->id, td->count);

               if (td->stream_output_ctx->session_dump_enabled) {
                   TcpSession *session = (TcpSession *) p->flow->protoctx;
                   if (session != NULL) {
                       LogTcpSession(session,
                               current_tag->pcap_file->pcap_dumper,
                               p);
                   }
               }
          }
          DumpTaggedPacket(current_tag->pcap_file->pcap_dumper, p);
      }
}

/**
 *  \brief StreamPcapLogRegister Register the logger to the output-packet
 *   root logger.
 */
void StreamPcapLogRegister(void)
{
    SCLogNotice("StreamPcapLogRegister Enter");
    OutputRegisterPacketModule(LOGGER_PCAP,        // Logger ID
            MODULE_NAME,                           // Logger name
            "stream-pcap-log",                     // Configuration name
            StreamPcapLogInitCtx,                  // Output init function
            StreamPcapLog,                         // Packet logger function
            StreamPcapLogCondition,                // Packet condition function
            StreamPcapLogThreadInit,               // Thread init function
            StreamPcapLogThreadDeInit,             // Thread deinit
            NULL);                                 // Thread print stats
}

/**
 * \brief Determines whether or not to log this packet.
 * \param tv thread-specific variables.
 * \param p Pointer to current packet being processed.
 * \return TRUE if the packet should be logged.
 * \return FALSE if we do not need to log the packet.
 */
static int StreamPcapLogCondition(ThreadVars *tv, const Packet *p)
{
    /* Flow is necessary for tag lookups. Reject invalid packets. */
    if ((p->ethh && p->flags & PKT_HAS_FLOW && !(p->flags & PKT_IS_INVALID)) ||
        p->alerts.cnt > 0) {
        return TRUE;
    }
    return FALSE;
}

/**
 *  \brief StreamPcapLogThreadInit Initialize the thread data.
 *  \param initdata Contains the output_ctx created by StreamPcapLogIitCtx
 *  \param data Populated with the thread data structure.
 *  \return TM_ECODE_OK On success.
 *  \return TM_ECODE_FAILED On serious error.
 */
static TmEcode StreamPcapLogThreadInit(ThreadVars *tv, const void *initdata,
        void **data)
{
    // Create and initialize the thread data.
    if (initdata == NULL) {
        SCLogDebug("Error getting context for StreamLogPcap. \"initdata\" "
                   "argument NULL");
        return TM_ECODE_FAILED;
    }
    StreamOutputCtx *stream_output_ctx = getStreamOutputCtx((OutputCtx*)
            initdata);
    StreamPcapLogThreadData *td = SCMalloc(sizeof(*td));
    if (unlikely(td == NULL)) {
        return TM_ECODE_FAILED;
    }
    td->stream_output_ctx = stream_output_ctx;
    td->count = 0;
    *data = (void *)td;
    return TM_ECODE_OK;
}

/**
 * \brief Thread deinit function.
 * \param thread_data StreamPcapLog thread data.
 * \return TM_ECODE_OK On success.
 */
static TmEcode StreamPcapLogThreadDeInit(ThreadVars *tv, void *thread_data)
{
    StreamPcapLogThreadData *td = thread_data;
    SCFree(td);
    return TM_ECODE_OK;
}

/**
 *  \brief Fill in stream-pcap logging struct from the provided ConfNode.
 *  \param conf The configuration node for this output.
 *  \return output_ctx: Output context (contains a StreamOutputCtx data member)
 */
static OutputInitResult StreamPcapLogInitCtx(ConfNode *conf)
{
    SCLogNotice("StreamPcapLogInitCtx enter");
    OutputInitResult result =  {NULL, false};
    /* Create the output context from the configuration node. */
    StreamOutputCtx *stream_output_ctx =
            SCMalloc(sizeof(*stream_output_ctx));
    if (unlikely(stream_output_ctx == NULL)) {
        SCReturnCT(result, "OutputInitResult");
    }
    OutputCtx *output_ctx = SCMalloc(sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(stream_output_ctx);
        SCReturnCT(result, "OutputInitResult");
    }
    /* Initialize filename */
    stream_output_ctx->filename[0] = '\0';

    /* Load output options. */
    const char *outputDirectory = ConfNodeLookupChildValue(conf,
            "output-directory");

    InitializePcapLogFilenameSupport(outputDirectory);

    if (ConfNodeChildValueIsTrue(conf, "session-dump")) {
        stream_output_ctx->session_dump_enabled = true;
    } else {
        stream_output_ctx->session_dump_enabled = false;
    }
    output_ctx->data = stream_output_ctx;
    output_ctx->DeInit = StreamPcapLogFileDeInitCtx;
    result.ctx = output_ctx;
    result.ok = true;
    SCReturnCT(result, "OutputInitResult");
}

/**
 *  \brief Helper function to extract the StreamOutputCtx from an
 *   OutputCtx->data
 *  \param output_ctx Structure that output modules use to maintain private data
 *  \return *StreamOutputCtx on success.
 *  \return NULL on failure or if output_ctx->data is NULL.
 */
static StreamOutputCtx *getStreamOutputCtx(const OutputCtx *output_ctx)
{
    if (output_ctx == NULL) {
        return NULL;
    }
    return (StreamOutputCtx *) output_ctx->data;
}

/**
 * \brief StreamPcapLogFileDeInitCtx Free and close the output context
 *  created by StreamPcapLogInitCtx.
 * \param output_ctx The output context to free.
 */
static void StreamPcapLogFileDeInitCtx(OutputCtx *output_ctx)
{
    SCLogNotice("StreamPcapLogFileDeInitCtx Enter");
    if (output_ctx == NULL) {
        return;
    }
    if (output_ctx->data != NULL) {
        StreamOutputCtx *stream_output_ctx_data = (StreamOutputCtx *)
                output_ctx->data;
        SCFree(stream_output_ctx_data);
    }
    SCFree(output_ctx);
}
