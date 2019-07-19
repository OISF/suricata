/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author William Metcalf <William.Metcalf@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * SPPcap packet logging module.
 */

#include "suricata-common.h"
#include "util-fmemopen.h"

#ifdef HAVE_LIBLZ4
#include <lz4frame.h>
#endif /* HAVE_LIBLZ4 */

#if defined(HAVE_DIRENT_H) && defined(HAVE_FNMATCH_H)
#define INIT_RING_BUFFER
#include <dirent.h>
#include <fnmatch.h>
#endif

#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "log-specific-pcap.h"
#include "decode-ipv4.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-cpu.h"
#include "util-atomic.h"
#include "util-print.h"

#include "source-pcap.h"

#include "output.h"

#include "queue.h"

#define DEFAULT_LOG_FILENAME            "sppcaplog"
#define MODULE_NAME                     "SPPcapLog"
#define MIN_LIMIT                       4 * 1024 * 1024
#define DEFAULT_LIMIT                   4 * 1024 * 1024
#define DEFAULT_FILE_LIMIT              0

#define LOGMODE_NORMAL                  0
#define LOGMODE_SGUIL                   1
#define LOGMODE_MULTI                   2

#define RING_BUFFER_MODE_DISABLED       0
#define RING_BUFFER_MODE_ENABLED        1

#define TS_FORMAT_SEC                   0
#define TS_FORMAT_USEC                  1

#define USE_STREAM_DEPTH_DISABLED       0
#define USE_STREAM_DEPTH_ENABLED        1

#define HONOR_PASS_RULES_DISABLED       0
#define HONOR_PASS_RULES_ENABLED        1

#define PCAP_SNAPLEN                    262144

static TAILQ_HEAD(, SPPcapFileName_) sppcap_file_list =
    TAILQ_HEAD_INITIALIZER(sppcap_file_list);

SC_ATOMIC_DECLARE(uint32_t, thread_cnt);

typedef struct SPPcapFileName_ {
    int isclosed;
    char *filename;
    char *dirname;

    /* Like a struct timeval, but with fixed size. This is only used when
     * seeding the ring buffer on start. */
    struct {
        uint64_t secs;
        uint32_t usecs;
    };

    TAILQ_ENTRY(SPPcapFileName_) next; /**< Pointer to next SPPcap File for tailq. */
} SPPcapFileName;

typedef struct SPPcapLogProfileData_ {
    uint64_t total;
    uint64_t cnt;
} SPPcapLogProfileData;

#define MAX_TOKS 9
#define MAX_FILENAMELEN 513

typedef struct SPPcapFLowlog_ {
    pcap_dumper_t *pcap_dumper; /**< actually writes the packets */
    pcap_t *pcap_dead_handle;   /**< pcap_dumper_t needs a handle */
    char *pcapfilename;
    uint64_t size_current;      /**< file current size */
    
    uint64_t size_limit;        /**< file size limit */
    uint64_t more_limit;
}SPPcapFLowlog;

/**
 * SPPcapLog thread vars
 *
 * Used for storing file options.
 */
typedef struct SPPcapLogData_ {
    int use_stream_depth;       /**< use stream depth i.e. ignore packets that reach limit */
    int honor_pass_rules;       /**< don't log if pass rules have matched */
    int is_private;             /**< TRUE if ctx is thread local */
    SCMutex plog_lock;
    struct pcap_pkthdr *h;      /**< pcap header struct */
    char *filename;             /**< current filename */
    int mode;                   /**< normal or sguil */
    int prev_day;               /**< last day, for finding out when */
    uint64_t size_current;      /**< file current size */
    uint64_t size_limit;        /**< file size limit */
    pcap_t *pcap_dead_handle;   /**< pcap_dumper_t needs a handle */
    pcap_dumper_t *pcap_dumper; /**< actually writes the packets */
    uint64_t profile_data_size; /**< track in bytes how many bytes we wrote */
    uint32_t file_cnt;          /**< count of pcap files we currently have */
    uint32_t max_files;         /**< maximum files to use in ring buffer mode */

    SPPcapLogProfileData profile_lock;
    SPPcapLogProfileData profile_write;
    SPPcapLogProfileData profile_unlock;
    SPPcapLogProfileData profile_handles; // open handles
    SPPcapLogProfileData profile_close;
    SPPcapLogProfileData profile_open;
    SPPcapLogProfileData profile_rotate;

    uint32_t thread_number;     /**< thread number, first thread is 1, second 2, etc */
    int use_ringbuffer;         /**< ring buffer mode enabled or disabled */
    int timestamp_format;       /**< timestamp format sec or usec */
    char *prefix;               /**< filename prefix */
    const char *suffix;         /**< filename suffix */
    char dir[PATH_MAX];         /**< pcap log directory */
    int reported;
    int threads;                /**< number of threads (only set in the global) */
} SPPcapLogData;

typedef struct SPPcapLogThreadData_ {
    SPPcapLogData *pcap_log;
} SPPcapLogThreadData;

/* Pattern for extracting timestamp from pcap log files. */
static const char timestamp_pattern[] = ".*?(\\d+)(\\.(\\d+))?";
static pcre *pcre_timestamp_code = NULL;
static pcre_extra *pcre_timestamp_extra = NULL;

/* global pcap data for when we're using multi mode. At exit we'll
 * merge counters into this one and then report counters. */
static SPPcapLogData *g_pcap_data = NULL;

static int SPPcapLogOpenFileCtx(SPPcapLogData *pl, const Packet *p);
static int SPPcapLog(ThreadVars *, void *, const Packet *);
static TmEcode SPPcapLogDataInit(ThreadVars *, const void *, void **);
static TmEcode SPPcapLogDataDeinit(ThreadVars *, void *);
static void SPPcapLogFileDeInitCtx(OutputCtx *);
static OutputInitResult SPPcapLogInitCtx(ConfNode *);
static void SPPcapLogProfilingDump(SPPcapLogData *);
static int SPPcapLogCondition(ThreadVars *, const Packet *);

void SPPcapLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_SPPCAP, MODULE_NAME, "specific-pcap-log",
        SPPcapLogInitCtx, SPPcapLog, SPPcapLogCondition, SPPcapLogDataInit,
        SPPcapLogDataDeinit, NULL);
    SPPcapLogProfileSetup();
    SC_ATOMIC_INIT(thread_cnt);
    return;
}

#define PCAPLOG_PROFILE_START \
    uint64_t pcaplog_profile_ticks = UtilCpuGetTicks()

#define PCAPLOG_PROFILE_END(prof) \
    (prof).total += (UtilCpuGetTicks() - pcaplog_profile_ticks); \
    (prof).cnt++

static int SPPcapLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        return FALSE;
    }
    if (IS_TUNNEL_PKT(p) && !IS_TUNNEL_ROOT_PKT(p)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * \brief Function to close pcaplog file
 *
 * \param t Thread Variable containing  input/output queue, cpu affinity etc.
 * \param pl SPPcapLog thread variable.
 */
static int SPPcapLogCloseFile(ThreadVars *t, SPPcapLogData *pl)
{
    if (pl != NULL) {
        PCAPLOG_PROFILE_START;

        if (pl->pcap_dumper != NULL) {
            pcap_dump_close(pl->pcap_dumper);
        }
        pl->size_current = 0;
        pl->pcap_dumper = NULL;

        if (pl->pcap_dead_handle != NULL)
            pcap_close(pl->pcap_dead_handle);
        pl->pcap_dead_handle = NULL;

        PCAPLOG_PROFILE_END(pl->profile_close);
    }

    return 0;
}

static void SPPcapFileNameFree(SPPcapFileName *pf)
{
    if (pf != NULL) {
        if (pf->filename != NULL) {
            SCFree(pf->filename);
        }
        if (pf->dirname != NULL) {
            SCFree(pf->dirname);
        }
        SCFree(pf);
    }

    return;
}

static int SPPcapLogOpenHandles(SPPcapLogData *pl, const Packet *p)
{
    PCAPLOG_PROFILE_START;

    SPPcapFLowlog* sppcap = (SPPcapFLowlog*)p->flow->sppcap;
    if (sppcap->pcap_dead_handle == NULL) {
        if ((sppcap->pcap_dead_handle = pcap_open_dead(p->datalink,
                PCAP_SNAPLEN)) == NULL) {
            SCLogError(SC_ERR_FOPEN, "Error opening dead pcap to dump packet");
            return TM_ECODE_FAILED;
        }
    }

    if (sppcap->pcap_dumper == NULL) {
        if ((sppcap->pcap_dumper = pcap_dump_open(sppcap->pcap_dead_handle,
                sppcap->pcapfilename)) == NULL) {
            SCLogError(SC_ERR_FOPEN, "Error opening dump file %s", pcap_geterr(sppcap->pcap_dead_handle));
            return TM_ECODE_FAILED;
        }
    }

    SCLogDebug("Setting pcap-log link type to %u", p->datalink);

    PCAPLOG_PROFILE_END(pl->profile_handles);
    return TM_ECODE_OK;
}

/** \internal
 *  \brief lock wrapper for main SPPcapLog() function
 *  NOTE: only meant for use in main SPPcapLog() function.
 */
static void SPPcapLogLock(SPPcapLogData *pl)
{
    if (!(pl->is_private)) {
        PCAPLOG_PROFILE_START;
        SCMutexLock(&pl->plog_lock);
        PCAPLOG_PROFILE_END(pl->profile_lock);
    }
}

/** \internal
 *  \brief unlock wrapper for main SPPcapLog() function
 *  NOTE: only meant for use in main SPPcapLog() function.
 */
static void SPPcapLogUnlock(SPPcapLogData *pl)
{
    if (!(pl->is_private)) {
        PCAPLOG_PROFILE_START;
        SCMutexUnlock(&pl->plog_lock);
        PCAPLOG_PROFILE_END(pl->profile_unlock);
    }
}

 /* \brief SPPcap logging main function
 *
 * \param t threadvar
 * \param p packet
 * \param data thread module specific data
 * \param pq pre-packet-queue
 * \param postpq post-packet-queue
 *
 * \retval TM_ECODE_OK on succes
 * \retval TM_ECODE_FAILED on serious error
 */
static int SPPcapLog (ThreadVars *t, void *thread_data, const Packet *p)
{
    size_t len;
    int ret = 0;
    SPPcapFLowlog* sppcap = NULL;

    SPPcapLogThreadData *td = (SPPcapLogThreadData *)thread_data;
    SPPcapLogData *pl = td->pcap_log;
    
    if ((p->flags & PKT_PSEUDO_STREAM_END) ||
        ((p->flags & PKT_STREAM_NOPCAPLOG) &&
         (pl->use_stream_depth == USE_STREAM_DEPTH_ENABLED)) ||
        (IS_TUNNEL_PKT(p) && !IS_TUNNEL_ROOT_PKT(p)) ||
        (pl->honor_pass_rules && (p->flags & PKT_NOPACKET_INSPECTION)) ||
        ((p->flags & PKT_HAS_FLOW) == 0))
    {
        return TM_ECODE_OK;
    }

    SPPcapLogLock(pl);
   
    if (p->alerts.cnt > 0 || p->flow->sppcap != NULL) {
        if (p->flow->sppcap == NULL) {
            p->flow->sppcap = (SPPcapFLowlog*)SCMalloc(sizeof(SPPcapFLowlog));
            if (p->flow->sppcap == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for SPPcapFLowlog");
                SPPcapLogUnlock(pl);
                return TM_ECODE_FAILED;
            }
            memset(p->flow->sppcap, 0, sizeof(SPPcapFLowlog));
            sppcap = (SPPcapFLowlog*)p->flow->sppcap;
            sppcap->size_limit = pl->size_limit;
            
            if (sppcap->pcapfilename == NULL) {
                ret = SPPcapLogOpenFileCtx(pl, p);
                if (ret < 0) {
                    SPPcapLogUnlock(pl);
                    return TM_ECODE_FAILED;
                }
                
                SCLogDebug("Opening PCAP log file %s", pl->filename);
            }
            
            SCLogDebug("Enter dump packet the filename is %s.", sppcap->pcapfilename);
            
            if (sppcap->pcap_dead_handle == NULL || sppcap->pcap_dumper == NULL) {
                if (SPPcapLogOpenHandles(pl, p) != TM_ECODE_OK) {
                    SPPcapLogUnlock(pl);
                    return TM_ECODE_FAILED;
                }
            }
        }
        
        sppcap = (SPPcapFLowlog*)p->flow->sppcap;
        len = sizeof(*pl->h) + GET_PKT_LEN(p);

        if (sppcap->size_current + len >= sppcap->size_limit || sppcap->more_limit) {
            sppcap->more_limit = 1;
            SPPcapLogUnlock(pl);
            return TM_ECODE_OK;
        }
        
        pl->h->ts.tv_sec = p->ts.tv_sec;
        pl->h->ts.tv_usec = p->ts.tv_usec;
        pl->h->caplen = GET_PKT_LEN(p);
        pl->h->len = GET_PKT_LEN(p);
        pl->size_current += len;
        sppcap->size_current += len;
        
        PCAPLOG_PROFILE_START;        
        pcap_dump((u_char *)sppcap->pcap_dumper, pl->h, GET_PKT_DATA(p));
        pcap_dump_flush(sppcap->pcap_dumper);
        //SCLogNotice("End specific-log-pcap dump alert packet.");
        
        PCAPLOG_PROFILE_END(pl->profile_write);
        pl->profile_data_size += len;
        
        SCLogDebug("pl->size_current %"PRIu64",  pl->size_limit %"PRIu64,
                   pl->size_current, pl->size_limit);
    }  

    SPPcapLogUnlock(pl);
    return TM_ECODE_OK;
}

static TmEcode SPPcapLogDataInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for LogSPPcap. \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    SPPcapLogData *pl = ((OutputCtx *)initdata)->data;

    SPPcapLogThreadData *td = SCCalloc(1, sizeof(*td));
    if (unlikely(td == NULL))
        return TM_ECODE_FAILED;

    td->pcap_log = pl;
    BUG_ON(td->pcap_log == NULL);

    /* count threads in the global structure */
    SCMutexLock(&pl->plog_lock);
    pl->threads++;
    SCMutexUnlock(&pl->plog_lock);

    *data = (void *)td;
    return TM_ECODE_OK;
}

static void SPPcapLogDataFree(SPPcapLogData *pl)
{

    SPPcapFileName *pf;
    while ((pf = TAILQ_FIRST(&sppcap_file_list)) != NULL) {
        TAILQ_REMOVE(&sppcap_file_list, pf, next);
        SPPcapFileNameFree(pf);
    }
    
    if (pl->h)
        SCFree(pl->h);
    if (pl->filename)
        SCFree(pl->filename);
    if (pl->prefix)
        SCFree(pl->prefix);
    SCFree(pl);
}

/**
 *  \brief Thread deinit function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param data SPPcapLog thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */
static TmEcode SPPcapLogDataDeinit(ThreadVars *t, void *thread_data)
{
    SPPcapLogThreadData *td = (SPPcapLogThreadData *)thread_data;
    SPPcapLogData *pl = td->pcap_log;

    if (pl->pcap_dumper != NULL) {
        if (SPPcapLogCloseFile(t,pl) < 0) {
            SCLogDebug("SPPcapLogCloseFile failed");
        }
    }

    if (pl->reported == 0) {
        SPPcapLogProfilingDump(pl);
        pl->reported = 1;
    }

    if (pl != g_pcap_data) {
        SPPcapLogDataFree(pl);
    }

    SCFree(td);
    return TM_ECODE_OK;
}

static int ParseFilename(SPPcapLogData *pl, const char *filename)
{
    size_t filename_len = 0;

    if (filename) {
        filename_len = strlen(filename);
        if (filename_len > (MAX_FILENAMELEN-1)) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid filename option. Max filename-length: %d",MAX_FILENAMELEN-1);
            goto error;
        }
    }
    return 0;
error:
    return -1;
}

static int SPPcapLogGetTimeOfFile(const char *filename, uint64_t *secs,
    uint32_t *usecs)
{
    int pcre_ovecsize = 4 * 3;
    int pcre_ovec[pcre_ovecsize];
    char buf[PATH_MAX];

    int n = pcre_exec(pcre_timestamp_code, pcre_timestamp_extra,
        filename, strlen(filename), 0, 0, pcre_ovec,
        pcre_ovecsize);
    if (n != 2 && n != 4) {
        /* No match. */
        return 0;
    }

    if (n >= 2) {
        /* Extract seconds. */
        if (pcre_copy_substring(filename, pcre_ovec, pcre_ovecsize,
                1, buf, sizeof(buf)) < 0) {
            return 0;
        }
        if (ByteExtractStringUint64(secs, 10, 0, buf) < 0) {
            return 0;
        }
    }
    if (n == 4) {
        /* Extract microseconds. */
        if (pcre_copy_substring(filename, pcre_ovec, pcre_ovecsize,
                3, buf, sizeof(buf)) < 0) {
            return 0;
        }
        if (ByteExtractStringUint32(usecs, 10, 0, buf) < 0) {
            return 0;
        }
    }

    return 1;
}

static int SPPcapLogInitRingBuffer(SPPcapLogData *pl)
{
    char pattern[PATH_MAX];

    SCLogInfo("Initializing PCAP ring buffer for %s/%s.",
        pl->dir, DEFAULT_LOG_SSP_PATH);

    strlcpy(pattern, pl->dir, PATH_MAX);
    if (pattern[strlen(pattern) - 1] != '/') {
        strlcat(pattern, "/", PATH_MAX);
    }

    strlcat(pattern, DEFAULT_LOG_SSP_PATH, PATH_MAX);

    /* Pattern is now just the directory name. */
    DIR *dir = opendir(pattern);
    if (dir == NULL) {
        SCLogWarning(SC_ERR_DIR_OPEN, "Failed to open directory %s: %s",
            pattern, strerror(errno));
        return TM_ECODE_FAILED;
    }

    for (;;) {
        struct dirent *entry = readdir(dir);
        if (entry == NULL) {
            break;
        }

        if (strcmp("..", entry->d_name) == 0 || strcmp(".", entry->d_name) == 0) {
            continue;
        }

        uint64_t secs = 0;
        uint32_t usecs = 0;

        if (!SPPcapLogGetTimeOfFile(entry->d_name, &secs, &usecs)) {
            /* Failed to get time stamp out of file name. Not necessarily a
             * failure as the file might just not be a pcap log file. */
            continue;
        }

        SPPcapFileName *pf = SCCalloc(sizeof(*pf), 1);
        if (unlikely(pf == NULL)) {
            goto fail;
        }
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", pattern, entry->d_name) == PATH_MAX)
            goto fail;

        if ((pf->filename = SCStrdup(path)) == NULL) {
            goto fail;
        }
        if ((pf->dirname = SCStrdup(pattern)) == NULL) {
            goto fail;
        }
        pf->secs = secs;
        pf->usecs = usecs;
        pf->isclosed = 1;

        if (TAILQ_EMPTY(&sppcap_file_list)) {
            TAILQ_INSERT_TAIL(&sppcap_file_list, pf, next);
        } else {
            /* Ordered insert. */
            SPPcapFileName *it = NULL;
            TAILQ_FOREACH(it, &sppcap_file_list, next) {
                if (pf->secs < it->secs) {
                    break;
                } else if (pf->secs == it->secs && pf->usecs < it->usecs) {
                    break;
                }
            }
            if (it == NULL) {
                TAILQ_INSERT_TAIL(&sppcap_file_list, pf, next);
            } else {
                TAILQ_INSERT_BEFORE(it, pf, next);
            }
        }
        pl->file_cnt++;
        continue;

    fail:
        if (pf != NULL) {
            if (pf->filename != NULL) {
                SCFree(pf->filename);
            }
            if (pf->dirname != NULL) {
                SCFree(pf->dirname);
            }
            SCFree(pf);
        }
        break;
    }

    if (pl->file_cnt > pl->max_files) {
        SPPcapFileName *pf = TAILQ_FIRST(&sppcap_file_list);
        while (pf != NULL && pl->file_cnt > pl->max_files) {
            SCLogDebug("Removing PCAP file %s", pf->filename);
            if (remove(pf->filename) != 0) {
                SCLogWarning(SC_WARN_REMOVE_FILE,
                    "Failed to remove PCAP file %s: %s", pf->filename,
                    strerror(errno));
            }
            TAILQ_REMOVE(&sppcap_file_list, pf, next);
            SPPcapFileNameFree(pf);
            pf = TAILQ_FIRST(&sppcap_file_list);
            pl->file_cnt--;
        }
    }

    closedir(dir);

    SCLogNotice("Ring buffer initialized with %d files(max-files:%d).", 
                pl->file_cnt, pl->max_files);

    return TM_ECODE_OK;
}

/** \brief Fill in pcap logging struct from the provided ConfNode.
 *  \param conf The configuration node for this output.
 *  \retval output_ctx
 * */
static OutputInitResult SPPcapLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    const char *pcre_errbuf;
    int pcre_erroffset;

    SPPcapLogData *pl = SCMalloc(sizeof(SPPcapLogData));
    if (unlikely(pl == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for SPPcapLogData");
        exit(EXIT_FAILURE);
    }
    memset(pl, 0, sizeof(SPPcapLogData));

    pl->h = SCMalloc(sizeof(*pl->h));
    if (pl->h == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate Memory for pcap header struct");
        exit(EXIT_FAILURE);
    }

    /* Set the defaults */
    pl->mode = LOGMODE_NORMAL;
    pl->max_files = DEFAULT_FILE_LIMIT;
    pl->use_ringbuffer = RING_BUFFER_MODE_DISABLED;
    pl->timestamp_format = TS_FORMAT_SEC;
    pl->use_stream_depth = USE_STREAM_DEPTH_DISABLED;
    pl->honor_pass_rules = HONOR_PASS_RULES_DISABLED;

    SCMutexInit(&pl->plog_lock, NULL);

    /* Initialize PCREs. */
    pcre_timestamp_code = pcre_compile(timestamp_pattern, 0, &pcre_errbuf,
        &pcre_erroffset, NULL);
    if (pcre_timestamp_code == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE,
            "Failed to compile \"%s\" at offset %"PRIu32": %s",
            timestamp_pattern, pcre_erroffset, pcre_errbuf);
    }
    pcre_timestamp_extra = pcre_study(pcre_timestamp_code, 0, &pcre_errbuf);
    if (pcre_errbuf != NULL) {
        FatalError(SC_ERR_PCRE_STUDY, "Fail to study pcre: %s", pcre_errbuf);
    }

    /* conf params */
    const char *filename = NULL;

    if (conf != NULL) { /* To faciliate unit tests. */
        filename = ConfNodeLookupChildValue(conf, "filename");
    }

    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;
    
    if (filename) {
        if (ParseFilename(pl, filename) != 0)
            exit(EXIT_FAILURE);
    }

    if ((pl->prefix = SCStrdup(filename)) == NULL) {
        exit(EXIT_FAILURE);
    }

    pl->suffix = "";

    pl->size_limit = DEFAULT_LIMIT;
    if (conf != NULL) {
        const char *s_limit = NULL;
        s_limit = ConfNodeLookupChildValue(conf, "limit");
        if (s_limit != NULL) {
            if (ParseSizeStringU64(s_limit, &pl->size_limit) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize unified2 output, invalid limit: %s",
                    s_limit);
                exit(EXIT_FAILURE);
            }
        } 
    }

    if (conf != NULL) {
        const char *s_mode = NULL;
        s_mode = ConfNodeLookupChildValue(conf, "mode");
        if (s_mode != NULL) {
            if (strcasecmp(s_mode, "normal") != 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "log-pcap: invalid mode \"%s\". Valid options: \"normal\", "
                    "\"sguil\", or \"multi\" mode ", s_mode);
                exit(EXIT_FAILURE);
            }
        }

        const char *s_dir = NULL;
        s_dir = ConfNodeLookupChildValue(conf, "dir");
        if (s_dir == NULL) {
            const char *log_dir = NULL;
            log_dir = ConfigGetLogDirectory();
            strlcpy(pl->dir, log_dir, sizeof(pl->dir));
            SCLogInfo("Using log dir %s", pl->dir);
        }
    }

    SCLogInfo("using %s logging", pl->mode == LOGMODE_SGUIL ?
              "Sguil compatible" : (pl->mode == LOGMODE_MULTI ? "multi" : "normal"));

    uint32_t max_file_limit = DEFAULT_FILE_LIMIT;
    if (conf != NULL) {
        const char *max_number_of_files_s = NULL;
        max_number_of_files_s = ConfNodeLookupChildValue(conf, "max-files");
        if (max_number_of_files_s != NULL) {
            if (ByteExtractStringUint32(&max_file_limit, 10, 0,
                                        max_number_of_files_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to initialize "
                           "pcap-log output, invalid number of files limit: %s",
                           max_number_of_files_s);
                exit(EXIT_FAILURE);
            } else if (max_file_limit < 1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Failed to initialize pcap-log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            } else {
                pl->max_files = max_file_limit;
                pl->use_ringbuffer = RING_BUFFER_MODE_ENABLED;
            }
        }
    }

    const char *ts_format = NULL;
    if (conf != NULL) { /* To faciliate unit tests. */
        ts_format = ConfNodeLookupChildValue(conf, "ts-format");
    }
    if (ts_format != NULL) {
        if (strcasecmp(ts_format, "usec") == 0) {
            pl->timestamp_format = TS_FORMAT_USEC;
        } else if (strcasecmp(ts_format, "sec") != 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "log-pcap ts_format specified %s is invalid must be"
                " \"sec\" or \"usec\"", ts_format);
            exit(EXIT_FAILURE);
        }
    }

    const char *use_stream_depth = NULL;
    if (conf != NULL) { /* To faciliate unit tests. */
        use_stream_depth = ConfNodeLookupChildValue(conf, "use-stream-depth");
    }
    if (use_stream_depth != NULL) {
        if (ConfValIsFalse(use_stream_depth)) {
            pl->use_stream_depth = USE_STREAM_DEPTH_DISABLED;
        } else if (ConfValIsTrue(use_stream_depth)) {
            pl->use_stream_depth = USE_STREAM_DEPTH_ENABLED;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "log-pcap use_stream_depth specified is invalid must be");
            exit(EXIT_FAILURE);
        }
    }

    const char *honor_pass_rules = NULL;
    if (conf != NULL) { /* To faciliate unit tests. */
        honor_pass_rules = ConfNodeLookupChildValue(conf, "honor-pass-rules");
    }
    if (honor_pass_rules != NULL) {
        if (ConfValIsFalse(honor_pass_rules)) {
            pl->honor_pass_rules = HONOR_PASS_RULES_DISABLED;
        } else if (ConfValIsTrue(honor_pass_rules)) {
            pl->honor_pass_rules = HONOR_PASS_RULES_ENABLED;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "log-pcap honor-pass-rules specified is invalid");
            exit(EXIT_FAILURE);
        }
    }

    /* create the output ctx and send it back */
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for OutputCtx.");
        exit(EXIT_FAILURE);
    }
    output_ctx->data = pl;
    output_ctx->DeInit = SPPcapLogFileDeInitCtx;
    g_pcap_data = pl;

    if (pl->max_files && pl->use_ringbuffer == RING_BUFFER_MODE_ENABLED) {
        if (SPPcapLogInitRingBuffer(pl) == TM_ECODE_FAILED) {
            SCLogNotice("Init ring buffer error.");
        }
    }

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void SPPcapLogFileDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx == NULL)
        return;

    SPPcapLogData *pl = output_ctx->data;

    SPPcapFileName *pf = NULL;
    TAILQ_FOREACH(pf, &sppcap_file_list, next) {
        SCLogDebug("PCAP files left at exit: %s\n", pf->filename);
    }
    
    SPPcapLogDataFree(pl);
    SCFree(output_ctx);
    return;
}

/**
 *  \brief Read the config set the file pointer, open the file
 *
 *  \param SPPcapLogData.
 *
 *  \retval -1 if failure
 *  \retval 0 if succesful
 */
static int SPPcapLogOpenFileCtx(SPPcapLogData *pl, const Packet *p)
{
    char srcip[16], dstip[16];
    char ssp_path[DEFAULT_LOG_SSP_PATH_LEN];
    char filename[DEFAULT_LOG_SSP_PATH_LEN];
    int ret;

    if (pl->file_cnt >= pl->max_files) {
        SPPcapFileName* pf;
        SPPcapFileName* pf_next;

        TAILQ_FOREACH_SAFE(pf, &sppcap_file_list, next, pf_next) {
            if (pf->isclosed) {
                if (remove(pf->filename) != 0) {
                    // VJ remove can fail because file is already gone
                    //LogWarning(SC_ERR_PCAP_FILE_DELETE_FAILED,
                    //           "failed to remove log file %s: %s",
                    //           pf->filename, strerror( errno ));
                }
                
                TAILQ_REMOVE(&sppcap_file_list, pf, next);
                SCLogDebug("Removing pcap file %s", pf->filename);
                SPPcapFileNameFree(pf);
                pl->file_cnt--;
                break;
            }
        }
    }

    PCAPLOG_PROFILE_START;

    /** get the time so we can have a filename with seconds since epoch */
    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));
    TimeGet(&ts);

    /* Place to store the name of our PCAP file */
    SPPcapFileName *pf = SCMalloc(sizeof(SPPcapFileName));
    if (unlikely(pf == NULL)) {
        return -1;
    }
    
    memset(pf, 0, sizeof(SPPcapFileName)); 
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));    

    // mkdir the alert dir
    ret = snprintf(ssp_path, DEFAULT_LOG_SSP_PATH_LEN, "%s%s", pl->dir, DEFAULT_LOG_SSP_PATH);
    if (!SCPathExists(ssp_path)) {
        SCLogInfo("Filestore (v2) creating directory %s", ssp_path);
        if (SCDefaultMkDir(ssp_path) != 0) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Filestore (v2) failed to create directory %s: %s", ssp_path,
                    strerror(errno));
            goto error;
        }
    }
    
    if (pl->mode == LOGMODE_NORMAL) {
        ret = snprintf(filename, DEFAULT_LOG_SSP_PATH_LEN, "%s/%s-%s:%u-%s:%u.%" PRIu32 ".%s",
                    ssp_path, "log", 
                    srcip, p->flow->sp, dstip, p->flow->dp, 
                    (uint32_t)ts.tv_sec, "pcap");
        if (ret < 0 || (size_t)ret >= PATH_MAX) {
            SCLogError(SC_ERR_SPRINTF,"failed to construct path");
            goto error;
        }
    }
    
    SPPcapFLowlog* sppcap = (SPPcapFLowlog*)p->flow->sppcap;
    if ((sppcap->pcapfilename = SCStrdup(filename)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory. For filename");
        goto error;
    }

    if ((pf->filename = SCStrdup(filename)) == NULL) {
        SCFree(sppcap->pcapfilename);
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory. For filename");
        goto error;
    }

    SCLogDebug("Opening pcap file log %s", sppcap->pcapfilename);
    SCLogDebug("Opening pcap file log %s", pf->filename);
    TAILQ_INSERT_TAIL(&sppcap_file_list, pf, next);
    pl->file_cnt++;
    PCAPLOG_PROFILE_END(pl->profile_open);
    return 0;

error:
    SPPcapFileNameFree(pf);
    return -1;
}

static void SPPcapLogSetClosed(char* filename)
{
    SPPcapFileName *pf;
    TAILQ_FOREACH(pf, &sppcap_file_list, next) {
        if (strcmp(filename, pf->filename) == 0) {
            pf->isclosed = 1;
        }
    }

    return;
}

void SPPcapLogCloseFileCtx(void *fptr)
{
    Flow* f = (Flow*)fptr;
    if (f != NULL && f->sppcap != NULL) {
        SPPcapFLowlog* sppcap = (SPPcapFLowlog*)f->sppcap;
                
        if (sppcap->pcap_dumper != NULL) {
            pcap_dump_close(sppcap->pcap_dumper);
        }

        sppcap->pcap_dumper = NULL;

        if (sppcap->pcap_dead_handle != NULL)
            pcap_close(sppcap->pcap_dead_handle);
        sppcap->pcap_dead_handle = NULL;

        if (sppcap->pcapfilename != NULL) {
            SPPcapLogSetClosed(sppcap->pcapfilename);
            SCFree(sppcap->pcapfilename);
            sppcap->pcapfilename = NULL;
        }

        SCFree(sppcap);

        f->sppcap = NULL;
    }
    
    SCLogDebug("Enter pcap log close pcap file");
}

static int profiling_pcaplog_enabled = 0;
static int profiling_pcaplog_output_to_file = 0;
static char *profiling_pcaplog_file_name = NULL;
static const char *profiling_pcaplog_file_mode = "a";

static void FormatNumber(uint64_t num, char *str, size_t size)
{
    if (num < 1000UL)
        snprintf(str, size, "%"PRIu64, num);
    else if (num < 1000000UL)
        snprintf(str, size, "%3.1fk", (float)num/1000UL);
    else if (num < 1000000000UL)
        snprintf(str, size, "%3.1fm", (float)num/1000000UL);
    else
        snprintf(str, size, "%3.1fb", (float)num/1000000000UL);
}

static void ProfileReportPair(FILE *fp, const char *name, SPPcapLogProfileData *p)
{
    char ticks_str[32] = "n/a";
    char cnt_str[32] = "n/a";
    char avg_str[32] = "n/a";

    FormatNumber((uint64_t)p->cnt, cnt_str, sizeof(cnt_str));
    FormatNumber((uint64_t)p->total, ticks_str, sizeof(ticks_str));
    if (p->cnt && p->total)
        FormatNumber((uint64_t)(p->total/p->cnt), avg_str, sizeof(avg_str));

    fprintf(fp, "%-28s %-10s %-10s %-10s\n", name, cnt_str, avg_str, ticks_str);
}

static void ProfileReport(FILE *fp, SPPcapLogData *pl)
{
    ProfileReportPair(fp, "open", &pl->profile_open);
    ProfileReportPair(fp, "close", &pl->profile_close);
    ProfileReportPair(fp, "write", &pl->profile_write);
    ProfileReportPair(fp, "rotate (incl open/close)", &pl->profile_rotate);
    ProfileReportPair(fp, "handles", &pl->profile_handles);
    ProfileReportPair(fp, "lock", &pl->profile_lock);
    ProfileReportPair(fp, "unlock", &pl->profile_unlock);
}

static void FormatBytes(uint64_t num, char *str, size_t size)
{
    if (num < 1000UL)
        snprintf(str, size, "%"PRIu64, num);
    else if (num < 1048576UL)
        snprintf(str, size, "%3.1fKiB", (float)num/1000UL);
    else if (num < 1073741824UL)
        snprintf(str, size, "%3.1fMiB", (float)num/1000000UL);
    else
        snprintf(str, size, "%3.1fGiB", (float)num/1000000000UL);
}

static void SPPcapLogProfilingDump(SPPcapLogData *pl)
{
    FILE *fp = NULL;

    if (profiling_pcaplog_enabled == 0)
        return;

    if (profiling_pcaplog_output_to_file == 1) {
        fp = fopen(profiling_pcaplog_file_name, profiling_pcaplog_file_mode);
        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s",
                    profiling_pcaplog_file_name, strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    /* counters */
    fprintf(fp, "\n\nOperation                    Cnt        Avg ticks  Total ticks\n");
    fprintf(fp,     "---------------------------- ---------- ---------- -----------\n");

    ProfileReport(fp, pl);
    uint64_t total = pl->profile_write.total + pl->profile_rotate.total +
                     pl->profile_handles.total + pl->profile_open.total +
                     pl->profile_close.total + pl->profile_lock.total +
                     pl->profile_unlock.total;

    /* overall stats */
    fprintf(fp, "\nOverall: %"PRIu64" bytes written, average %d bytes per write.\n",
        pl->profile_data_size, pl->profile_write.cnt ?
            (int)(pl->profile_data_size / pl->profile_write.cnt) : 0);
    fprintf(fp, "         PCAP data structure overhead: %"PRIuMAX" per write.\n",
        (uintmax_t)sizeof(struct pcap_pkthdr));

    /* print total bytes written */
    char bytes_str[32];
    FormatBytes(pl->profile_data_size, bytes_str, sizeof(bytes_str));
    fprintf(fp, "         Size written: %s\n", bytes_str);

    /* ticks per MiB and GiB */
    uint64_t ticks_per_mib = 0, ticks_per_gib = 0;
    uint64_t mib = pl->profile_data_size/(1024*1024);
    if (mib)
        ticks_per_mib = total/mib;
    char ticks_per_mib_str[32] = "n/a";
    if (ticks_per_mib > 0)
        FormatNumber(ticks_per_mib, ticks_per_mib_str, sizeof(ticks_per_mib_str));
    fprintf(fp, "         Ticks per MiB: %s\n", ticks_per_mib_str);

    uint64_t gib = pl->profile_data_size/(1024*1024*1024);
    if (gib)
        ticks_per_gib = total/gib;
    char ticks_per_gib_str[32] = "n/a";
    if (ticks_per_gib > 0)
        FormatNumber(ticks_per_gib, ticks_per_gib_str, sizeof(ticks_per_gib_str));
    fprintf(fp, "         Ticks per GiB: %s\n", ticks_per_gib_str);

    if (fp != stdout)
        fclose(fp);
}

void SPPcapLogProfileSetup(void)
{
    ConfNode *conf = ConfGetNode("profiling.pcap-log");
    if (conf != NULL && ConfNodeChildValueIsTrue(conf, "enabled")) {
        profiling_pcaplog_enabled = 1;
        SCLogInfo("pcap-log profiling enabled");

        const char *filename = ConfNodeLookupChildValue(conf, "filename");
        if (filename != NULL) {
            const char *log_dir;
            log_dir = ConfigGetLogDirectory();

            profiling_pcaplog_file_name = SCMalloc(PATH_MAX);
            if (unlikely(profiling_pcaplog_file_name == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "can't duplicate file name");
                exit(EXIT_FAILURE);
            }

            snprintf(profiling_pcaplog_file_name, PATH_MAX, "%s/%s", log_dir, filename);

            const char *v = ConfNodeLookupChildValue(conf, "append");
            if (v == NULL || ConfValIsTrue(v)) {
                profiling_pcaplog_file_mode = "a";
            } else {
                profiling_pcaplog_file_mode = "w";
            }

            profiling_pcaplog_output_to_file = 1;
            SCLogInfo("pcap-log profiling output goes to %s (mode %s)",
                    profiling_pcaplog_file_name, profiling_pcaplog_file_mode);
        }
    }
}

