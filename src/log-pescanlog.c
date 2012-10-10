/* Copyright (C) 2012 BAE Systems
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 * Implements pescan logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "util-debug.h"

#include "output.h"
#include "log-pescanlog.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-file.h"
#include "util-logopenfile.h"
#include "util-pescan.h"

#define DEFAULT_LOG_FILENAME "pescan.log"

#define MODULE_NAME "LogPescanLog"

#define OUTPUT_BUFFER_SIZE 65535
#define PE_BUFFER_SIZE 4096
#define MAX_FIELD_SIZE 128
#define MAX_SECT_NAME 8
#define PE_ANOMALY_COUNT 9

/**
 * \brief Array of strings containing the names of the PE header anomalies
 *
 */
static char *pe_anomalies[] = {
        "pe_flag_exec_and_write",
        "pe_flag_exec_no_code",
        "pe_flag_non_printable",
        "pe_flag_no_exec",
        "pe_flag_code_sum",
        "pe_flag_data_sum",
        "pe_flag_udata_sum",
        "pe_flag_entry_not_exec",
        "pe_flag_entry_not_code",
        0
};

/* Prototypes for internally used functions */
TmEcode LogPescanLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogPescanLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogPescanLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogPescanLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogPescanLogThreadDeinit(ThreadVars *, void *);
void LogPescanLogExitPrintStats(ThreadVars *, void *);
OutputCtx *LogPescanLogInitCtx(ConfNode *conf);
static void LogPescanLogDeInitCtx(OutputCtx *);
void LogPescanLogRegisterTests(void);

/**
 * \brief Registration function for managing the PEScan logger and logging transactions
 *
 */
void TmModuleLogPescanLogRegister (void) {
    tmm_modules[TMM_PESCANLOG].name = MODULE_NAME;
    tmm_modules[TMM_PESCANLOG].ThreadInit = LogPescanLogThreadInit;
    tmm_modules[TMM_PESCANLOG].Func = LogPescanLog;
    tmm_modules[TMM_PESCANLOG].ThreadExitPrintStats = LogPescanLogExitPrintStats;
    tmm_modules[TMM_PESCANLOG].ThreadDeinit = LogPescanLogThreadDeinit;
    tmm_modules[TMM_PESCANLOG].RegisterTests = LogPescanLogRegisterTests;
    tmm_modules[TMM_PESCANLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "pescan-log", LogPescanLogInitCtx);
}

/** \struct LogPescanFileCtx
 * \brief Structure containing the context of the logging output file
 */
typedef struct LogPescanFileCtx_ {
    LogFileCtx *file_ctx; /**< Pointer to the file context */
    uint32_t flags; /**< Store mode flags */
} LogPescanFileCtx;

/** \struct LogPescanLogThread
 * \brief Structure containing the context of the logging thread for handling multi-threading
 */
typedef struct LogPescanLogThread_ {
    LogPescanFileCtx *pescanlog_ctx; /**< LogFileCtx has the pointer to the file and a mutex to allow multithreading */

    uint32_t pe_cnt; /**< Count of PEs found */

    MemBuffer *buffer; /**< Output buffer for writing log entries */
} LogPescanLogThread;

/**
 * \brief General safe function to add a variable argument string to an existing buffer of a specified size
 *
 * \param buf the buffer in which to add the string
 * \param len the size allocated to the buffer
 * \param pos the offset / position within the buffer to add the string
 * \param format the format string (ie. printf format)
 * \param ... the variable arguments
 *
 * \retval 0 if no bytes were added to the buffer
 * \retval n number of bytes added to the buffer (excluding null-terminator)
 */
static int AddToBuffer(char *buf, uint32_t len, uint32_t pos, const char * format, ...) {

    va_list ap;
    char tbuf[MAX_FIELD_SIZE + 1];
    int tlen;

    /* First make sure there is at least two bytes available (one char + null-terminating char) */
    if (pos > len - 2) {
        return 0;
    }

    /* Store params in a temp buffer */
    va_start(ap, format);
    tlen = vsnprintf(tbuf, MAX_FIELD_SIZE, format, ap);
    va_end(ap);

    if (tlen > MAX_FIELD_SIZE) {
        SCLogDebug("AddToBuffer: temp size exceeded");
        return 0;
    }

    /* Not enough room to add anything so quit */
    if (tlen + pos > len - 2) {
        SCLogDebug("AddToBuffer: total buf size exceeded");
        return 0;
    }

    /* Add the string */
    return snprintf(buf + pos, len - pos, "%s", tbuf);
}

/**
 * \brief General safe function to add the section flags to a buffer
 *
 * \param buf the buffer in which to add the string
 * \param len the size allocated to the buffer
 * \param w the bitwise flag containing the section information
 *
 * \retval 0 if no bytes were added to the buffer
 * \retval n number of bytes added to the buffer (excluding null-terminator)
 */
// This function determines the characteristics of each section of a PE.
static uint32_t PrintSectFlags(char *buf, uint32_t len, unsigned w)
{
    uint32_t pos = 0;

    if (len < 5) {
        return 0;
    }

    /* Init buffer */
    buf[0] = 0;

    if( w & 0x20 )
        pos += AddToBuffer(buf, len, pos, "code ");

    if( w & 0x40 )
        pos += AddToBuffer(buf, len, pos, "data ");

    if( w & 0x80 )
        pos += AddToBuffer(buf, len, pos, "udata ");

    if( w & 0x00010000 )
        pos += AddToBuffer(buf, len, pos, "reserved ");

    if( w & 0x00020000 )
        pos += AddToBuffer(buf, len, pos, "reserved ");

    if( w & 0x00040000 )
        pos += AddToBuffer(buf, len, pos, "reserved ");

    if( w & 0x00080000 )
        pos += AddToBuffer(buf, len, pos, "reserved ");

    if( w & 0x00f00000 )
        pos += AddToBuffer(buf, len, pos, "alignment ");

    if( w & 0x02000000 )
        pos += AddToBuffer(buf, len, pos, "discard ");

    if( w & 0x04000000 )
        pos += AddToBuffer(buf, len, pos, "nocache ");

    if( w & 0x08000000 )
        pos += AddToBuffer(buf, len, pos, "nopage ");

    if( w & 0x10000000 )
        pos += AddToBuffer(buf, len, pos, "shared ");

    if( w & 0x20000000 )
        pos += AddToBuffer(buf, len, pos, "execute ");

    if( w & 0x40000000 )
        pos += AddToBuffer(buf, len, pos, "read ");

    if( w & 0x80000000 )
        pos += AddToBuffer(buf, len, pos, "write ");

    /* Remove last ' ' */
    if (pos > 0) {
        buf[pos - 1] = 0;
    }

    return pos;
}

/**
 * \brief Prints the PE Score and anomaly flag information into a pre-existing string buffer
 *
 * The last parameter is a pointer to the libpescan function "double pescore(peattrib_t *)" which
 * should be passed in if the score is to be re-generated, otherwise NULL is acceptable when the score was
 * already generated elsewhere.
 *
 * \param wp a pointer to the PE header attributes struct
 * \param buf the buffer in which to add the string
 * \param len the size allocated to the buffer
 * \param fptr a pointer to the pescore generating function (NULL for no generation)
 *
 * \retval 0 if no bytes were added to the buffer
 * \retval n number of bytes added to the buffer (excluding null-terminator)
 */
static uint32_t PrintPEScore( peattrib_t * wp, char * buf, uint32_t len, double (*fptr)(peattrib_t * pestruct) )
{
    uint32_t pos = 0, idx;

    /* Init buffer */
    buf[0] = 0;

    /* If score function not passed in, then ignore */
    if (fptr != NULL) {
        wp->pescore = (*fptr)(wp);
    }

    pos += AddToBuffer(buf, len, pos, "pe_score=%g ", wp->pescore); /* always provide a score */
    pos += AddToBuffer(buf, len, pos, "pe_flags=0x%x ", wp->fvflags); /* always provide flags */
    pos += AddToBuffer(buf, len, pos, "pe_flagcnt=%d ", wp->fvflagcnt); /* always provide flag count */

    /* Exit if not enough space left to continue */
    if (pos > len - 20) {
        return pos;
    }

    for (idx = 0; idx < PE_ANOMALY_COUNT; idx++) {

        if (wp->fv[idx] > 0) {
            pos += AddToBuffer(buf, len, pos, "%s=%ld ", pe_anomalies[idx], wp->fv[idx]);
        }
    }

    return pos;
}

/**
 * \brief Prints the PE Header information (excluding score / anomaly flags) into a pre-existing string buffer
 *
 * This function only prints information that is meaningful for any PE and is not used as a classifier for good / bad PEs.
 *
 * \param wp a pointer to the PE header attributes struct
 * \param buf the buffer in which to add the string
 * \param len the size allocated to the buffer
 *
 * \retval 0 if no bytes were added to the buffer
 * \retval n number of bytes added to the buffer (excluding null-terminator)
 */
static uint32_t PrintPEHeader( peattrib_t *wp, char *buf, uint32_t len ) {
    uint32_t pos = 0, k;

    int i;
    int w;
    char cxbuf[256];

    w = wp->machine;

    if( wp->trunc )
        pos += AddToBuffer(buf, len, pos, "pe_truncated ");

    if( w == 0x014c ) { // 32bit
        pos += AddToBuffer(buf, len, pos, "pe_mach_bits=32 ");
    }
    else if( w == 0x8664 ) { // x86_64 bit
        pos += AddToBuffer(buf, len, pos, "pe_mach_bits=64 ");
    }
    else {
        pos += AddToBuffer(buf, len, pos, "pe_mach_bits=0x%x ", w);
    }

    pos += AddToBuffer(buf, len, pos, "pe_hdr_type=%s ", (wp->pesize==PE_32)?"PE32":((wp->pesize==PE_64)?"PE64":"??") );
    pos += AddToBuffer(buf, len, pos, "pe_os_version=%d.%d ",wp->os_major,wp->os_minor);
    pos += AddToBuffer(buf, len, pos, "pe_offset=%d ",wp->peoffset);

    w = wp->petype;
    pos += AddToBuffer(buf, len, pos, "pe_binary=");

    if( w & PE_EXE )
        pos += AddToBuffer(buf, len, pos, "EXE");
    else
        pos += AddToBuffer(buf, len, pos, "NONEXE");
    if( w & PE_DLL )
        pos += AddToBuffer(buf, len, pos, "/DLL");
    if( w & PE_SYS )
        pos += AddToBuffer(buf, len, pos,"/SYS");
    pos += AddToBuffer(buf, len, pos, " ");
    pos += AddToBuffer(buf, len, pos, "pe_checksum=0x%x ",wp->chksum);
    pos += AddToBuffer(buf, len, pos, "pe_num_sections=%u ",wp->nsections);
    pos += AddToBuffer(buf, len, pos, "pe_image_size=%x ", wp->size_of_image);
    pos += AddToBuffer(buf, len, pos, "pe_opt_hdr_size=%u ", wp->opt_hdr_size);
    pos += AddToBuffer(buf, len, pos, "pe_link_ver=%d.%d ", wp->link_major,wp->link_minor);
    pos += AddToBuffer(buf, len, pos, "pe_code_size=0x%x ", wp->size_of_code  );
    pos += AddToBuffer(buf, len, pos, "pe_data_size=0x%x ", wp->size_of_data  );
    pos += AddToBuffer(buf, len, pos, "pe_udata_size=0x%x ", wp->size_of_udata );
    pos += AddToBuffer(buf, len, pos, "pe_entry_point=0x%x ", wp->entryptr );
    pos += AddToBuffer(buf, len, pos, "pe_baseof_code=0x%x ", wp->base_of_code );
    pos += AddToBuffer(buf, len, pos, "pe_sizeof_hdrs=0x%x ", wp->size_of_hdrs );
    pos += AddToBuffer(buf, len, pos, "pe_num_rva_dirs=0x%x ", wp->nrva );
    pos += AddToBuffer(buf, len, pos, "pe_export_va=0x%x ", wp->export_rva );
    pos += AddToBuffer(buf, len, pos, "pe_export_size=0x%x ", wp->export_size );
    pos += AddToBuffer(buf, len, pos, "pe_import_va=0x%x ", wp->import_rva );
    pos += AddToBuffer(buf, len, pos, "pe_import_size=0x%x ", wp->import_size );
    pos += AddToBuffer(buf, len, pos, "pe_rsrc_rva=0x%x ", wp->rsrc_rva );
    pos += AddToBuffer(buf, len, pos, "pe_rsrc_size=0x%x ", wp->rsrc_size );

    for(i = 0; i < wp->nsections; i++) {

        pos += AddToBuffer(buf, len, pos, "pe_section_name='");

        for(k = 0; k < MAX_SECT_NAME; k++) {
            if( wp->sx[i].name[k] >32 && wp->sx[i].name[k] <=127 )
                pos += AddToBuffer(buf, len, pos, "%c",wp->sx[i].name[k]);
        }

        pos += AddToBuffer(buf, len, pos, "' ");
        pos += AddToBuffer(buf, len, pos,"pe_section_raw_size=0x%x ",wp->sx[i].raw_size);
        pos += AddToBuffer(buf, len, pos, "pe_section_raw_offset=0x%x ",wp->sx[i].raw_offset);
        pos += AddToBuffer(buf, len, pos, "pe_section_virt_size=0x%x ",wp->sx[i].virt_size);
        pos += AddToBuffer(buf, len, pos, "pe_section_virt_addr=0x%x ",wp->sx[i].virt_rva);

        w=wp->sx[i].cx;
        pos += AddToBuffer(buf, len, pos, "pe_section_flags='" );

        PrintSectFlags(cxbuf,sizeof(cxbuf),w);

        pos += AddToBuffer(buf, len, pos, "%s' ",cxbuf);
    }

    return pos;
}

/**
 * \brief Creates a time string and stores it in the specified output buffer
 *
 * \param ts pointer to a time value structure (read-only)
 * \param str pointer to the output buffer
 * \param dize size allocated for the output buffer
 */
static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

/**
 * \brief Logs the PEScan results to the file specified by the provided context
 *
 * This function handles both IPv4 and IPv6 protocols.
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param p pointer to the current packet
 * \param data pointer to the current threading context
 * \param pq pointer to the queue containing the packet
 * \param postpq pointer to the queue where the packet goes next
 * \param ipproto IP Protocol (AF_NET for IPv4 or AF_NET6 for IPv6)
 *
 * \retval TM_ECODE_OK on Success
 */
static TmEcode LogPescanLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
        PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogPescanLogThread *aft = (LogPescanLogThread *)data;
    LogPescanFileCtx *pelog = aft->pescanlog_ctx;
    char timebuf[64];
    char pebuf[PE_BUFFER_SIZE];
    int pebuflen;
    uint8_t flags = 0;

    /* no flow, no file state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= STREAM_TOCLIENT;
    else
        flags |= STREAM_TOSERVER;

    /* check if we have HTTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */

    /* Get files from flow (must be some to continue) */
    FileContainer *ffc = AppLayerGetFilesFromFlow(p->flow, flags);
    if (ffc == NULL) {
        goto end;
    }

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;

    switch (ipproto) {
    case AF_INET:
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
        break;
    case AF_INET6:
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
        break;
    default:
        goto end;
    }
    sp = p->sp;
    dp = p->dp;

    /* Traverse through each file in the container */
    File *ff;
    for (ff = ffc->head; ff != NULL; ff = ff->next) {
        SCLogDebug("ff %p - flags %d", ff, ff->flags);

        /* If pescan disabled, break; */
        if (ff->flags & FILE_NOPESCAN) {
            break;
        }

        /* If already logged, then skip */
        else if (ff->pescan_flags & PEFILE_LOGGED) {
            continue;
        }

        /* If not scanned, determine what to do */
        else if (!(ff->pescan_flags & PEFILE_SCANNED)) {

            /* Any files that were not scanned by the detector should be scanned here */
            if (ff->chunks_head != NULL && (ff->state == FILE_STATE_CLOSED || ff->size >= PEScanGetConfig()->wait_scan_bytes)) {

                /* Scan the file */
                PEScanFile(ff);
            }

            else {
                continue;
            }
        }

        /* Only log non-PEs while in debug mode */
        if (ff->peattrib == NULL && !SCLogDebugEnabled()) {
            continue;
        }

        /* If we reached this point, then we have a PE (or non-PE in debug mode) that has been scanned
           but needs to be logged
         */

        /* reset */
        MemBufferReset(aft->buffer);

        /* time */
        MemBufferWriteString(aft->buffer, "%s ", timebuf);

        /* Filename */
        MemBufferWriteString(aft->buffer, "FILENAME \"");
        PrintRawUriBuf((char *) aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size, ff->name, ff->name_len);
        MemBufferWriteString(aft->buffer, "\" ");

        /* Found a PE to log */
        if (ff->peattrib != NULL) {

            MemBufferWriteString(aft->buffer, "PE-SCORE ");
            pebuflen = PrintPEScore(ff->peattrib, pebuf, PE_BUFFER_SIZE, NULL);
            if (pebuflen >= 0) {
                MemBufferWriteString(aft->buffer, "[");
                PrintRawUriBuf((char *) aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size, (uint8_t *) pebuf, pebuflen);
                MemBufferWriteString(aft->buffer, "] ");
            }

            MemBufferWriteString(aft->buffer, "PE-HEADER ");
            pebuflen = PrintPEHeader(ff->peattrib, pebuf, PE_BUFFER_SIZE);
            if (pebuflen >= 0) {
                MemBufferWriteString(aft->buffer, "[");
                PrintRawUriBuf((char *) aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size, (uint8_t *) pebuf, pebuflen);
                MemBufferWriteString(aft->buffer, "] ");
            }

            /* Inc counter */
            aft->pe_cnt++;
        }

        /* Found a scanned file that is NOT a PE (This only occurs in debug mode) */
        else if (ff->pescan_flags & PEFILE_SCANNED) {
            MemBufferWriteString(aft->buffer, "[NOT A PE] ");
        }

        /* Finish logging the transaction */
        MemBufferWriteString(aft->buffer, " [***] %s:%" PRIu16 " -> %s:%" PRIu16 "\n", srcip, sp, dstip, dp);

        /* Write to file */
        SCMutexLock(&pelog->file_ctx->fp_mutex);
        MemBufferPrintToFPAsString(aft->buffer, pelog->file_ctx->fp);
        fflush(pelog->file_ctx->fp);
        SCMutexUnlock(&pelog->file_ctx->fp_mutex);

        /* Mark file as PE-logged */
        ff->pescan_flags |= PEFILE_LOGGED;
    }

    /* Prune files that need to be cleaned up */
    FilePrune(ffc);

    end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

/**
 * \brief Calls LogPescanLogIPWrapper with the IPv4 flag
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param p pointer to the current packet
 * \param data pointer to the current threading context
 * \param pq pointer to the queue containing the packet
 * \param postpq pointer to the queue where the packet goes next
 *
 * \retval TM_ECODE_OK on Success
 */
TmEcode LogPescanLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogPescanLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

/**
 * \brief Calls LogPescanLogIPWrapper with the IPv6 flag
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param p pointer to the current packet
 * \param data pointer to the current threading context
 * \param pq pointer to the queue containing the packet
 * \param postpq pointer to the queue where the packet goes next
 *
 * \retval TM_ECODE_OK on Success
 */
TmEcode LogPescanLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogPescanLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

/**
 * \brief Entry point callback into the logger for both IPv4 and IPv6 traffic
 *
 * The function callback does quick checks such as making sure the packet is contained within a valid flow and is using the TCP protocol.
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param p pointer to the current packet
 * \param data pointer to the current threading context
 * \param pq pointer to the queue containing the packet
 * \param postpq pointer to the queue where the packet goes next
 *
 * \retval TM_ECODE_OK on Success
 */
TmEcode LogPescanLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogPescanLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogPescanLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Callback for initializing a new logger thread
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param initdata pointer to output context
 * \param data double pointer containing newly alloc'ed thread context
 *
 * \retval TM_ECODE_OK on Success
 * \retval TM_ECODE_FAILED on Failure
 */
TmEcode LogPescanLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogPescanLogThread *aft = SCMalloc(sizeof(LogPescanLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogPescanLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->pescanlog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

/**
 * \brief Callback for de-initializing a finished logger thread
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param data pointer to the thread context
 *
 * \retval TM_ECODE_OK on Success
 */
TmEcode LogPescanLogThreadDeinit(ThreadVars *t, void *data)
{
    LogPescanLogThread *aft = (LogPescanLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogPescanLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/**
 * \brief Callback for printing stats on exit
 *
 * Run on a per-thread basis
 *
 * \param tv pointer to thread-specific variables (unused)
 * \param data pointer to the thread context
 */
void LogPescanLogExitPrintStats(ThreadVars *tv, void *data) {
    LogPescanLogThread *aft = (LogPescanLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("PEScan logger logged %" PRIu32 " PEs", aft->pe_cnt);
}

/**
 * \brief Create a new pescan log file context.
 *
 * \param conf Pointer to ConfNode containing this loggers configuration.
 *
 * \retval NULL if failure
 * \retval OutputCtx* pointer to the output context if successful
 */
OutputCtx *LogPescanLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogPescanFileCtx *pescanlog_ctx = SCMalloc(sizeof(LogPescanFileCtx));
    if (pescanlog_ctx == NULL) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(pescanlog_ctx, 0x00, sizeof(LogPescanFileCtx));

    pescanlog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL) {
        LogFileFreeCtx(file_ctx);
        SCFree(pescanlog_ctx);
        return NULL;
    }

    output_ctx->data = pescanlog_ctx;
    output_ctx->DeInit = LogPescanLogDeInitCtx;

    SCLogDebug("HTTP log output initialized");

    return output_ctx;
}

/**
 * \brief Un-initializes a pescan log output context
 *
 * \param output_ctx pointer to the output context
 *
 */
static void LogPescanLogDeInitCtx(OutputCtx *output_ctx)
{
    LogPescanFileCtx *pescanlog_ctx = (LogPescanFileCtx *)output_ctx->data;
    LogFileFreeCtx(pescanlog_ctx->file_ctx);
    SCFree(pescanlog_ctx);
    SCFree(output_ctx);
}

/***************************** Unittests ****************************/
#ifdef UNITTESTS

/** \brief test PrintSectFlags function*/
int LogPescanLogTest01()
{

    int result = 0;

    if (PrintSectFlags(NULL, 0, 0) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    if (PrintSectFlags(NULL,4,0) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    char buf[4] = "abcd";
    if (PrintSectFlags(buf,4,0x20) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    char buf1[6] = "abcdef";
    if (PrintSectFlags(buf1,0,0x20) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    return result;
}

/** \brief test AddtoBuffer function*/
int LogPescanLogTest02()
{
    int result = 0;

    char buf2[128];
    char text[5] = "abcde";
    if (AddToBuffer(buf2,128,100,(const char *) printf,text) == 5) {
        result = 1;
    }
    else {
        result = 0;
    }
    // when exceeding total buffer size should return 0
    char buf3[10];
    char text1[16] = "abcdefghijklmnop";
    if (AddToBuffer(buf3,10,10,(const char *) printf,text1) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    // if there are less than two bytes available should return 0
    char buf4[200];
    char text2[150] = "kjahfkjfhajkdlfjaldhaalhjkdfhajkdsfaahdsjfhfj";
    if (AddToBuffer(buf4,200,201,(const char *) printf,text2) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    return result;
}

/** \brief test LogPescanLogInitCtx function*/
int LogPescanLogTest03()
{
    int result = 0;

    ConfNode *testNode = NULL;

    if (LogPescanLogInitCtx(testNode) == NULL ) {
        result = 1;
    }
    else {
        result = 0;
    }

    return result;
}

#endif

/**
 * \brief This function registers unit tests
 */
void LogPescanLogRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("LogPescanLogTest01", LogPescanLogTest01, 1);
    UtRegisterTest("LogPescanLogTest02", LogPescanLogTest02, 1);
    UtRegisterTest("LogPescanLogTest03", LogPescanLogTest03, 1);
#endif /* UNITTESTS */

}
