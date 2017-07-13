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
 * Pcap packet logging module.
 */

#include "suricata-common.h"

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
#include "log-pcap.h"
#include "decode-ipv4.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-byte.h"
#include "util-misc.h"
#include "util-cpu.h"
#include "util-atomic.h"

#include "source-pcap.h"

#include "output.h"

#include "queue.h"

#define DEFAULT_LOG_FILENAME            "pcaplog"
#define MODULE_NAME                     "PcapLog"
#define MIN_LIMIT                       1 * 1024 * 1024
#define DEFAULT_LIMIT                   100 * 1024 * 1024
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

SC_ATOMIC_DECLARE(uint32_t, thread_cnt);

typedef struct PcapFileName_ {
    char *filename;
    char *dirname;

    /* Like a struct timeval, but with fixed size. This is only used when
     * seeding the ring buffer on start. */
    struct {
        uint64_t secs;
        uint32_t usecs;
    };

    TAILQ_ENTRY(PcapFileName_) next; /**< Pointer to next Pcap File for tailq. */
} PcapFileName;

typedef struct PcapLogProfileData_ {
    uint64_t total;
    uint64_t cnt;
} PcapLogProfileData;

#define MAX_TOKS 9

/**
 * PcapLog thread vars
 *
 * Used for storing file options.
 */
typedef struct PcapLogData_ {
    int use_stream_depth;       /**< use stream depth i.e. ignore packets that reach limit */
    int honor_pass_rules;       /**< don't log if pass rules have matched */
    int is_private;             /**< TRUE if ctx is thread local */
    SCMutex plog_lock;
    uint64_t pkt_cnt;		    /**< total number of packets */
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

    PcapLogProfileData profile_lock;
    PcapLogProfileData profile_write;
    PcapLogProfileData profile_unlock;
    PcapLogProfileData profile_handles; // open handles
    PcapLogProfileData profile_close;
    PcapLogProfileData profile_open;
    PcapLogProfileData profile_rotate;

    TAILQ_HEAD(, PcapFileName_) pcap_file_list;

    uint32_t thread_number;     /**< thread number, first thread is 1, second 2, etc */
    int use_ringbuffer;         /**< ring buffer mode enabled or disabled */
    int timestamp_format;       /**< timestamp format sec or usec */
    char *prefix;               /**< filename prefix */
    char dir[PATH_MAX];         /**< pcap log directory */
    int reported;
    int threads;                /**< number of threads (only set in the global) */
    char *filename_parts[MAX_TOKS];
    int filename_part_cnt;
} PcapLogData;

typedef struct PcapLogThreadData_ {
    PcapLogData *pcap_log;
} PcapLogThreadData;

/* Pattern for extracting timestamp from pcap log files. */
static const char timestamp_pattern[] = ".*?(\\d+)(\\.(\\d+))?";
static pcre *pcre_timestamp_code = NULL;
static pcre_extra *pcre_timestamp_extra = NULL;

/* global pcap data for when we're using multi mode. At exit we'll
 * merge counters into this one and then report counters. */
static PcapLogData *g_pcap_data = NULL;

static int PcapLogOpenFileCtx(PcapLogData *);
static int PcapLog(ThreadVars *, void *, const Packet *);
static TmEcode PcapLogDataInit(ThreadVars *, const void *, void **);
static TmEcode PcapLogDataDeinit(ThreadVars *, void *);
static void PcapLogFileDeInitCtx(OutputCtx *);
static OutputCtx *PcapLogInitCtx(ConfNode *);
static void PcapLogProfilingDump(PcapLogData *);
static int PcapLogCondition(ThreadVars *, const Packet *);

void PcapLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_PCAP, MODULE_NAME, "pcap-log",
        PcapLogInitCtx, PcapLog, PcapLogCondition, PcapLogDataInit,
        PcapLogDataDeinit, NULL);
    PcapLogProfileSetup();
    SC_ATOMIC_INIT(thread_cnt);
    return;
}

#define PCAPLOG_PROFILE_START \
    uint64_t pcaplog_profile_ticks = UtilCpuGetTicks()

#define PCAPLOG_PROFILE_END(prof) \
    (prof).total += (UtilCpuGetTicks() - pcaplog_profile_ticks); \
    (prof).cnt++

static int PcapLogCondition(ThreadVars *tv, const Packet *p)
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
 * \param pl PcapLog thread variable.
 */
static int PcapLogCloseFile(ThreadVars *t, PcapLogData *pl)
{
    if (pl != NULL) {
        PCAPLOG_PROFILE_START;

        if (pl->pcap_dumper != NULL)
            pcap_dump_close(pl->pcap_dumper);
        pl->size_current = 0;
        pl->pcap_dumper = NULL;

        if (pl->pcap_dead_handle != NULL)
            pcap_close(pl->pcap_dead_handle);
        pl->pcap_dead_handle = NULL;

        PCAPLOG_PROFILE_END(pl->profile_close);
    }

    return 0;
}

static void PcapFileNameFree(PcapFileName *pf)
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

/**
 * \brief Function to rotate pcaplog file
 *
 * \param t Thread Variable containing  input/output queue, cpu affinity etc.
 * \param pl PcapLog thread variable.
 *
 * \retval 0 on succces
 * \retval -1 on failure
 */
static int PcapLogRotateFile(ThreadVars *t, PcapLogData *pl)
{
    PcapFileName *pf;
    PcapFileName *pfnext;

    PCAPLOG_PROFILE_START;

    if (PcapLogCloseFile(t,pl) < 0) {
        SCLogDebug("PcapLogCloseFile failed");
        return -1;
    }

    if (pl->use_ringbuffer == RING_BUFFER_MODE_ENABLED && pl->file_cnt >= pl->max_files) {
        pf = TAILQ_FIRST(&pl->pcap_file_list);
        SCLogDebug("Removing pcap file %s", pf->filename);

        if (remove(pf->filename) != 0) {
            // VJ remove can fail because file is already gone
            //LogWarning(SC_ERR_PCAP_FILE_DELETE_FAILED,
            //           "failed to remove log file %s: %s",
            //           pf->filename, strerror( errno ));
        }

        /* Remove directory if Sguil mode and no files left in sguil dir */
        if (pl->mode == LOGMODE_SGUIL) {
            pfnext = TAILQ_NEXT(pf,next);

            if (strcmp(pf->dirname, pfnext->dirname) == 0) {
                SCLogDebug("Current entry dir %s and next entry %s "
                        "are equal: not removing dir",
                        pf->dirname, pfnext->dirname);
            } else {
                SCLogDebug("current entry %s and %s are "
                        "not equal: removing dir",
                        pf->dirname, pfnext->dirname);

                if (remove(pf->dirname) != 0) {
                    SCLogWarning(SC_ERR_PCAP_FILE_DELETE_FAILED,
                            "failed to remove sguil log %s: %s",
                            pf->dirname, strerror( errno ));
                }
            }
        }

        TAILQ_REMOVE(&pl->pcap_file_list, pf, next);
        PcapFileNameFree(pf);
        pl->file_cnt--;
    }

    if (PcapLogOpenFileCtx(pl) < 0) {
        SCLogError(SC_ERR_FOPEN, "opening new pcap log file failed");
        return -1;
    }
    pl->file_cnt++;
    SCLogDebug("file_cnt %u", pl->file_cnt);

    PCAPLOG_PROFILE_END(pl->profile_rotate);
    return 0;
}

static int PcapLogOpenHandles(PcapLogData *pl, const Packet *p)
{
    PCAPLOG_PROFILE_START;

    SCLogDebug("Setting pcap-log link type to %u", p->datalink);

    if (pl->pcap_dead_handle == NULL) {
        if ((pl->pcap_dead_handle = pcap_open_dead(p->datalink,
                        PCAP_SNAPLEN)) == NULL) {
            SCLogDebug("Error opening dead pcap handle");
            return TM_ECODE_FAILED;
        }
    }

    if (pl->pcap_dumper == NULL) {
        if ((pl->pcap_dumper = pcap_dump_open(pl->pcap_dead_handle,
                        pl->filename)) == NULL) {
            SCLogInfo("Error opening dump file %s", pcap_geterr(pl->pcap_dead_handle));
            return TM_ECODE_FAILED;
        }
    }

    PCAPLOG_PROFILE_END(pl->profile_handles);
    return TM_ECODE_OK;
}

/** \internal
 *  \brief lock wrapper for main PcapLog() function
 *  NOTE: only meant for use in main PcapLog() function.
 */
static void PcapLogLock(PcapLogData *pl)
{
    if (!(pl->is_private)) {
        PCAPLOG_PROFILE_START;
        SCMutexLock(&pl->plog_lock);
        PCAPLOG_PROFILE_END(pl->profile_lock);
    }
}

/** \internal
 *  \brief unlock wrapper for main PcapLog() function
 *  NOTE: only meant for use in main PcapLog() function.
 */
static void PcapLogUnlock(PcapLogData *pl)
{
    if (!(pl->is_private)) {
        PCAPLOG_PROFILE_START;
        SCMutexUnlock(&pl->plog_lock);
        PCAPLOG_PROFILE_END(pl->profile_unlock);
    }
}

/**
 * \brief Pcap logging main function
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
static int PcapLog (ThreadVars *t, void *thread_data, const Packet *p)
{
    size_t len;
    int rotate = 0;
    int ret = 0;

    PcapLogThreadData *td = (PcapLogThreadData *)thread_data;
    PcapLogData *pl = td->pcap_log;

    if ((p->flags & PKT_PSEUDO_STREAM_END) ||
        ((p->flags & PKT_STREAM_NOPCAPLOG) &&
         (pl->use_stream_depth == USE_STREAM_DEPTH_ENABLED)) ||
        (IS_TUNNEL_PKT(p) && !IS_TUNNEL_ROOT_PKT(p)) ||
        (pl->honor_pass_rules && (p->flags & PKT_NOPACKET_INSPECTION)))
    {
        return TM_ECODE_OK;
    }

    PcapLogLock(pl);

    pl->pkt_cnt++;
    pl->h->ts.tv_sec = p->ts.tv_sec;
    pl->h->ts.tv_usec = p->ts.tv_usec;
    pl->h->caplen = GET_PKT_LEN(p);
    pl->h->len = GET_PKT_LEN(p);
    len = sizeof(*pl->h) + GET_PKT_LEN(p);

    if (pl->filename == NULL) {
        ret = PcapLogOpenFileCtx(pl);
        if (ret < 0) {
            PcapLogUnlock(pl);
            return TM_ECODE_FAILED;
        }
        SCLogDebug("Opening PCAP log file %s", pl->filename);
    }

    if (pl->mode == LOGMODE_SGUIL) {
        struct tm local_tm;
        struct tm *tms = SCLocalTime(p->ts.tv_sec, &local_tm);
        if (tms->tm_mday != pl->prev_day) {
            rotate = 1;
            pl->prev_day = tms->tm_mday;
        }
    }

    if ((pl->size_current + len) > pl->size_limit || rotate) {
        if (PcapLogRotateFile(t,pl) < 0) {
            PcapLogUnlock(pl);
            SCLogDebug("rotation of pcap failed");
            return TM_ECODE_FAILED;
        }
    }

    /* XXX pcap handles, nfq, pfring, can only have one link type ipfw? we do
     * this here as we don't know the link type until we get our first packet */
    if (pl->pcap_dead_handle == NULL || pl->pcap_dumper == NULL) {
        if (PcapLogOpenHandles(pl, p) != TM_ECODE_OK) {
            PcapLogUnlock(pl);
            return TM_ECODE_FAILED;
        }
    }

    PCAPLOG_PROFILE_START;
    pcap_dump((u_char *)pl->pcap_dumper, pl->h, GET_PKT_DATA(p));
    pl->size_current += len;
    PCAPLOG_PROFILE_END(pl->profile_write);
    pl->profile_data_size += len;

    SCLogDebug("pl->size_current %"PRIu64",  pl->size_limit %"PRIu64,
               pl->size_current, pl->size_limit);

    PcapLogUnlock(pl);
    return TM_ECODE_OK;
}

static PcapLogData *PcapLogDataCopy(const PcapLogData *pl)
{
    BUG_ON(pl->mode != LOGMODE_MULTI);
    PcapLogData *copy = SCCalloc(1, sizeof(*copy));
    if (unlikely(copy == NULL)) {
        return NULL;
    }

    copy->h = SCCalloc(1, sizeof(*copy->h));
    if (unlikely(copy->h == NULL)) {
        SCFree(copy);
        return NULL;
    }

    copy->prefix = SCStrdup(pl->prefix);
    if (unlikely(copy->prefix == NULL)) {
        SCFree(copy->h);
        SCFree(copy);
        return NULL;
    }

    /* settings TODO move to global cfg struct */
    copy->is_private = TRUE;
    copy->mode = pl->mode;
    copy->max_files = pl->max_files;
    copy->use_ringbuffer = pl->use_ringbuffer;
    copy->timestamp_format = pl->timestamp_format;
    copy->use_stream_depth = pl->use_stream_depth;
    copy->size_limit = pl->size_limit;

    TAILQ_INIT(&copy->pcap_file_list);
    SCMutexInit(&copy->plog_lock, NULL);

    strlcpy(copy->dir, pl->dir, sizeof(copy->dir));

    int i;
    for (i = 0; i < pl->filename_part_cnt && i < MAX_TOKS; i++)
        copy->filename_parts[i] = pl->filename_parts[i];
    copy->filename_part_cnt = pl->filename_part_cnt;

    /* set thread number, first thread is 1 */
    copy->thread_number = SC_ATOMIC_ADD(thread_cnt, 1);

    SCLogDebug("copied, returning %p", copy);
    return copy;
}

#ifdef INIT_RING_BUFFER
static int PcapLogGetTimeOfFile(const char *filename, uint64_t *secs,
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

static TmEcode PcapLogInitRingBuffer(PcapLogData *pl)
{
    char pattern[PATH_MAX];

    SCLogInfo("Initializing PCAP ring buffer for %s/%s.",
        pl->dir, pl->prefix);

    strlcpy(pattern, pl->dir, PATH_MAX);
    if (pattern[strlen(pattern) - 1] != '/') {
        strlcat(pattern, "/", PATH_MAX);
    }
    if (pl->mode == LOGMODE_MULTI) {
        for (int i = 0; i < pl->filename_part_cnt; i++) {
            char *part = pl->filename_parts[i];
            if (part == NULL || strlen(part) == 0) {
                continue;
            }
            if (part[0] != '%' || strlen(part) < 2) {
                strlcat(pattern, part, PATH_MAX);
                continue;
            }
            switch (part[1]) {
                case 'i':
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "Thread ID not allowed inring buffer mode.");
                    return TM_ECODE_FAILED;
                case 'n': {
                    char tmp[PATH_MAX];
                    snprintf(tmp, PATH_MAX, "%"PRIu32, pl->thread_number);
                    strlcat(pattern, tmp, PATH_MAX);
                    break;
                }
                case 't':
                    strlcat(pattern, "*", PATH_MAX);
                    break;
                default:
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "Unsupported format character: %%%s", part);
                    return TM_ECODE_FAILED;
            }
        }
    } else {
        strlcat(pattern, pl->prefix, PATH_MAX);
        strlcat(pattern, ".*", PATH_MAX);
    }

    char *basename = strrchr(pattern, '/');
    *basename++ = '\0';

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
        if (fnmatch(basename, entry->d_name, 0) != 0) {
            continue;
        }

        uint64_t secs = 0;
        uint32_t usecs = 0;

        if (!PcapLogGetTimeOfFile(entry->d_name, &secs, &usecs)) {
            /* Failed to get time stamp out of file name. Not necessarily a
             * failure as the file might just not be a pcap log file. */
            continue;
        }

        PcapFileName *pf = SCCalloc(sizeof(*pf), 1);
        if (unlikely(pf == NULL)) {
            goto fail;
        }
        char path[PATH_MAX];
        snprintf(path, PATH_MAX - 1, "%s/%s", pattern, entry->d_name);
        if ((pf->filename = SCStrdup(path)) == NULL) {
            goto fail;
        }
        if ((pf->dirname = SCStrdup(pattern)) == NULL) {
            goto fail;
        }
        pf->secs = secs;
        pf->usecs = usecs;

        if (TAILQ_EMPTY(&pl->pcap_file_list)) {
            TAILQ_INSERT_TAIL(&pl->pcap_file_list, pf, next);
        } else {
            /* Ordered insert. */
            PcapFileName *it = NULL;
            TAILQ_FOREACH(it, &pl->pcap_file_list, next) {
                if (pf->secs < it->secs) {
                    break;
                } else if (pf->secs == it->secs && pf->usecs < it->usecs) {
                    break;
                }
            }
            if (it == NULL) {
                TAILQ_INSERT_TAIL(&pl->pcap_file_list, pf, next);
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
        PcapFileName *pf = TAILQ_FIRST(&pl->pcap_file_list);
        while (pf != NULL && pl->file_cnt > pl->max_files) {
            SCLogDebug("Removing PCAP file %s", pf->filename);
            if (remove(pf->filename) != 0) {
                SCLogWarning(SC_WARN_REMOVE_FILE,
                    "Failed to remove PCAP file %s: %s", pf->filename,
                    strerror(errno));
            }
            TAILQ_REMOVE(&pl->pcap_file_list, pf, next);
            PcapFileNameFree(pf);
            pf = TAILQ_FIRST(&pl->pcap_file_list);
            pl->file_cnt--;
        }
    }

    closedir(dir);

    /* For some reason file count is initialized at one, instead of 0. */
    SCLogNotice("Ring buffer initialized with %d files.", pl->file_cnt - 1);

    return TM_ECODE_OK;
}
#endif /* INIT_RING_BUFFER */

static TmEcode PcapLogDataInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for LogPcap. \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    PcapLogData *pl = ((OutputCtx *)initdata)->data;

    PcapLogThreadData *td = SCCalloc(1, sizeof(*td));
    if (unlikely(td == NULL))
        return TM_ECODE_FAILED;

    if (pl->mode == LOGMODE_MULTI)
        td->pcap_log = PcapLogDataCopy(pl);
    else
        td->pcap_log = pl;
    BUG_ON(td->pcap_log == NULL);

    PcapLogLock(td->pcap_log);

    /** Use the Ouptut Context (file pointer and mutex) */
    td->pcap_log->pkt_cnt = 0;
    td->pcap_log->pcap_dead_handle = NULL;
    td->pcap_log->pcap_dumper = NULL;
    if (td->pcap_log->file_cnt < 1) {
        td->pcap_log->file_cnt = 1;
    }

    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));
    TimeGet(&ts);
    struct tm local_tm;
    struct tm *tms = SCLocalTime(ts.tv_sec, &local_tm);
    td->pcap_log->prev_day = tms->tm_mday;

    PcapLogUnlock(td->pcap_log);

    /* count threads in the global structure */
    SCMutexLock(&pl->plog_lock);
    pl->threads++;
    SCMutexUnlock(&pl->plog_lock);

    *data = (void *)td;

    if (pl->max_files && (pl->mode == LOGMODE_MULTI || pl->threads == 1)) {
#ifdef INIT_RING_BUFFER
        if (PcapLogInitRingBuffer(td->pcap_log) == TM_ECODE_FAILED) {
            return TM_ECODE_FAILED;
        }
#else
        SCLogInfo("Unable to initialize ring buffer on this platform.");
#endif /* INIT_RING_BUFFER */
    }

    return TM_ECODE_OK;
}

static void StatsMerge(PcapLogData *dst, PcapLogData *src)
{
    dst->profile_open.total += src->profile_open.total;
    dst->profile_open.cnt += src->profile_open.cnt;

    dst->profile_close.total += src->profile_close.total;
    dst->profile_close.cnt += src->profile_close.cnt;

    dst->profile_write.total += src->profile_write.total;
    dst->profile_write.cnt += src->profile_write.cnt;

    dst->profile_rotate.total += src->profile_rotate.total;
    dst->profile_rotate.cnt += src->profile_rotate.cnt;

    dst->profile_handles.total += src->profile_handles.total;
    dst->profile_handles.cnt += src->profile_handles.cnt;

    dst->profile_lock.total += src->profile_lock.total;
    dst->profile_lock.cnt += src->profile_lock.cnt;

    dst->profile_unlock.total += src->profile_unlock.total;
    dst->profile_unlock.cnt += src->profile_unlock.cnt;

    dst->profile_data_size += src->profile_data_size;
}

static void PcapLogDataFree(PcapLogData *pl)
{

    PcapFileName *pf;
    while ((pf = TAILQ_FIRST(&pl->pcap_file_list)) != NULL) {
        TAILQ_REMOVE(&pl->pcap_file_list, pf, next);
        PcapFileNameFree(pf);
    }
    if (pl == g_pcap_data) {
        for (int i = 0; i < MAX_TOKS; i++) {
            if (pl->filename_parts[i] != NULL) {
                SCFree(pl->filename_parts[i]);
            }
        }
    }
    SCFree(pl->h);
    SCFree(pl->filename);
    SCFree(pl->prefix);
    SCFree(pl);
}

/**
 *  \brief Thread deinit function.
 *
 *  \param t Thread Variable containing  input/output queue, cpu affinity etc.
 *  \param data PcapLog thread data.
 *  \retval TM_ECODE_OK on succces
 *  \retval TM_ECODE_FAILED on failure
 */
static TmEcode PcapLogDataDeinit(ThreadVars *t, void *thread_data)
{
    PcapLogThreadData *td = (PcapLogThreadData *)thread_data;
    PcapLogData *pl = td->pcap_log;

    if (pl->pcap_dumper != NULL) {
        if (PcapLogCloseFile(t,pl) < 0) {
            SCLogDebug("PcapLogCloseFile failed");
        }
    }

    if (pl->mode == LOGMODE_MULTI) {
        SCMutexLock(&g_pcap_data->plog_lock);
        StatsMerge(g_pcap_data, pl);
        g_pcap_data->reported++;
        if (g_pcap_data->threads == g_pcap_data->reported)
            PcapLogProfilingDump(g_pcap_data);
        SCMutexUnlock(&g_pcap_data->plog_lock);
    } else {
        if (pl->reported == 0) {
            PcapLogProfilingDump(pl);
            pl->reported = 1;
        }
    }

    if (pl != g_pcap_data) {
        PcapLogDataFree(pl);
    }

    SCFree(td);
    return TM_ECODE_OK;
}

static int ParseFilename(PcapLogData *pl, const char *filename)
{
    char *toks[MAX_TOKS] = { NULL };
    int tok = 0;
    char str[512] = "";
    int s = 0;
    int i, x;
    char *p = NULL;

    if (filename) {
        for (i = 0; i < (int)strlen(filename); i++) {
            if (tok >= MAX_TOKS) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "invalid filename option. Max 2 %%-sign options");
                goto error;
            }

            str[s++] = filename[i];

            if (filename[i] == '%') {
                str[s-1] = '\0';
                SCLogDebug("filename with %%-sign: %s", str);

                p = SCStrdup(str);
                if (p == NULL)
                    goto error;
                toks[tok++] = p;

                s = 0;

                if (i+1 < (int)strlen(filename)) {
                    if (tok >= MAX_TOKS) {
                        SCLogError(SC_ERR_INVALID_ARGUMENT,
                                "invalid filename option. Max 2 %%-sign options");
                        goto error;
                    }

                    if (filename[i+1] != 'n' && filename[i+1] != 't' && filename[i+1] != 'i') {
                        SCLogError(SC_ERR_INVALID_ARGUMENT,
                                "invalid filename option. Valid %%-sign options: %%n, %%i and %%t");
                        goto error;
                    }
                    str[0] = '%';
                    str[1] = filename[i+1];
                    str[2] = '\0';
                    p = SCStrdup(str);
                    if (p == NULL)
                        goto error;
                    toks[tok++] = p;
                    i++;
                }
            }
        }
        if (s) {
            if (tok >= MAX_TOKS) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "invalid filename option. Max 3 %%-sign options");
                goto error;

            }
            str[s++] = '\0';
            p = SCStrdup(str);
            if (p == NULL)
                goto error;
            toks[tok++] = p;
        }

        /* finally, store tokens in the pl */
        for (i = 0; i < tok; i++) {
            if (toks[i] == NULL)
                goto error;

            SCLogDebug("toks[%d] %s", i, toks[i]);
            pl->filename_parts[i] = toks[i];
        }
        pl->filename_part_cnt = tok;
    }
    return 0;
error:
    for (x = 0; x < MAX_TOKS; x++) {
        if (toks[x] != NULL)
            SCFree(toks[x]);
    }
    return -1;
}

/** \brief Fill in pcap logging struct from the provided ConfNode.
 *  \param conf The configuration node for this output.
 *  \retval output_ctx
 * */
static OutputCtx *PcapLogInitCtx(ConfNode *conf)
{
    const char *pcre_errbuf;
    int pcre_erroffset;

    PcapLogData *pl = SCMalloc(sizeof(PcapLogData));
    if (unlikely(pl == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate Memory for PcapLogData");
        exit(EXIT_FAILURE);
    }
    memset(pl, 0, sizeof(PcapLogData));

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

    TAILQ_INIT(&pl->pcap_file_list);

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

    if ((pl->prefix = SCStrdup(filename)) == NULL) {
        exit(EXIT_FAILURE);
    }

    if (filename) {
        if (ParseFilename(pl, filename) != 0)
            exit(EXIT_FAILURE);
    }

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
            if (pl->size_limit < 4096) {
                SCLogInfo("pcap-log \"limit\" value of %"PRIu64" assumed to be pre-1.2 "
                        "style: setting limit to %"PRIu64"mb", pl->size_limit, pl->size_limit);
                uint64_t size = pl->size_limit * 1024 * 1024;
                pl->size_limit = size;
            } else if (pl->size_limit < MIN_LIMIT) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "Fail to initialize pcap-log output, limit less than "
                    "allowed minimum.");
                exit(EXIT_FAILURE);
            }
        }
    }

    if (conf != NULL) {
        const char *s_mode = NULL;
        s_mode = ConfNodeLookupChildValue(conf, "mode");
        if (s_mode != NULL) {
            if (strcasecmp(s_mode, "sguil") == 0) {
                pl->mode = LOGMODE_SGUIL;
            } else if (strcasecmp(s_mode, "multi") == 0) {
                pl->mode = LOGMODE_MULTI;
            } else if (strcasecmp(s_mode, "normal") != 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "log-pcap: invalid mode \"%s\". Valid options: \"normal\", "
                    "\"sguil\", or \"multi\" mode ", s_mode);
                exit(EXIT_FAILURE);
            }
        }

        const char *s_dir = NULL;
        s_dir = ConfNodeLookupChildValue(conf, "dir");
        if (s_dir == NULL) {
            s_dir = ConfNodeLookupChildValue(conf, "sguil-base-dir");
        }
        if (s_dir == NULL) {
            if (pl->mode == LOGMODE_SGUIL) {
                SCLogError(SC_ERR_LOGPCAP_SGUIL_BASE_DIR_MISSING,
                    "log-pcap \"sguil\" mode requires \"sguil-base-dir\" "
                    "option to be set.");
                exit(EXIT_FAILURE);
            } else {
                const char *log_dir = NULL;
                log_dir = ConfigGetLogDirectory();

                strlcpy(pl->dir,
                    log_dir, sizeof(pl->dir));
                    SCLogInfo("Using log dir %s", pl->dir);
            }
        } else {
            if (PathIsAbsolute(s_dir)) {
                strlcpy(pl->dir,
                        s_dir, sizeof(pl->dir));
            } else {
                const char *log_dir = NULL;
                log_dir = ConfigGetLogDirectory();

                snprintf(pl->dir, sizeof(pl->dir), "%s/%s",
                    log_dir, s_dir);
            }

            struct stat stat_buf;
            if (stat(pl->dir, &stat_buf) != 0) {
                SCLogError(SC_ERR_LOGDIR_CONFIG, "The sguil-base-dir directory \"%s\" "
                        "supplied doesn't exist. Shutting down the engine",
                        pl->dir);
                exit(EXIT_FAILURE);
            }
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
    output_ctx->DeInit = PcapLogFileDeInitCtx;
    g_pcap_data = pl;

    return output_ctx;
}

static void PcapLogFileDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx == NULL)
        return;

    PcapLogData *pl = output_ctx->data;

    PcapFileName *pf = NULL;
    TAILQ_FOREACH(pf, &pl->pcap_file_list, next) {
        SCLogDebug("PCAP files left at exit: %s\n", pf->filename);
    }
    PcapLogDataFree(pl);
    SCFree(output_ctx);
    return;
}

/**
 *  \brief Read the config set the file pointer, open the file
 *
 *  \param PcapLogData.
 *
 *  \retval -1 if failure
 *  \retval 0 if succesful
 */
static int PcapLogOpenFileCtx(PcapLogData *pl)
{
    char *filename = NULL;

    PCAPLOG_PROFILE_START;

    if (pl->filename != NULL)
        filename = pl->filename;
    else {
        filename = SCMalloc(PATH_MAX);
        if (unlikely(filename == NULL)) {
            return -1;
        }
        pl->filename = filename;
    }

    /** get the time so we can have a filename with seconds since epoch */
    struct timeval ts;
    memset(&ts, 0x00, sizeof(struct timeval));
    TimeGet(&ts);

    /* Place to store the name of our PCAP file */
    PcapFileName *pf = SCMalloc(sizeof(PcapFileName));
    if (unlikely(pf == NULL)) {
        return -1;
    }
    memset(pf, 0, sizeof(PcapFileName));

    if (pl->mode == LOGMODE_SGUIL) {
        struct tm local_tm;
        struct tm *tms = SCLocalTime(ts.tv_sec, &local_tm);

        char dirname[32], dirfull[PATH_MAX] = "";

        snprintf(dirname, sizeof(dirname), "%04d-%02d-%02d",
                tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday);

        /* create the filename to use */
        int ret = snprintf(dirfull, sizeof(dirfull), "%s/%s", pl->dir, dirname);
        if (ret < 0 || (size_t)ret >= sizeof(dirfull)) {
            SCLogError(SC_ERR_SPRINTF,"failed to construct path");
            goto error;
        }

        /* if mkdir fails file open will fail, so deal with errors there */
#ifndef OS_WIN32
        (void)mkdir(dirfull, 0700);
#else
        (void)mkdir(dirfull);
#endif
        if ((pf->dirname = SCStrdup(dirfull)) == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for "
                       "directory name");
            goto error;
        }

        if (pl->timestamp_format == TS_FORMAT_SEC) {
            snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, dirfull,
                     pl->prefix, (uint32_t)ts.tv_sec);
        } else {
            snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32 ".%" PRIu32,
                     dirfull, pl->prefix, (uint32_t)ts.tv_sec, (uint32_t)ts.tv_usec);
        }

    } else if (pl->mode == LOGMODE_NORMAL) {
        int ret;
        /* create the filename to use */
        if (pl->timestamp_format == TS_FORMAT_SEC) {
            ret = snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32, pl->dir,
                    pl->prefix, (uint32_t)ts.tv_sec);
        } else {
            ret = snprintf(filename, PATH_MAX, "%s/%s.%" PRIu32 ".%" PRIu32, pl->dir,
                    pl->prefix, (uint32_t)ts.tv_sec, (uint32_t)ts.tv_usec);
        }
        if (ret < 0 || (size_t)ret >= PATH_MAX) {
            SCLogError(SC_ERR_SPRINTF,"failed to construct path");
            goto error;
        }
    } else if (pl->mode == LOGMODE_MULTI) {
        if (pl->filename_part_cnt > 0) {
            /* assemble filename from stored tokens */

            strlcpy(filename, pl->dir, PATH_MAX);
            strlcat(filename, "/", PATH_MAX);

            int i;
            for (i = 0; i < pl->filename_part_cnt; i++) {
                if (pl->filename_parts[i] == NULL ||strlen(pl->filename_parts[i]) == 0)
                    continue;

                /* handle variables */
                if (pl->filename_parts[i][0] == '%') {
                    char str[64] = "";
                    if (strlen(pl->filename_parts[i]) < 2)
                        continue;

                    switch(pl->filename_parts[i][1]) {
                        case 'n':
                            snprintf(str, sizeof(str), "%u", pl->thread_number);
                            break;
                        case 'i':
                        {
                            long thread_id = SCGetThreadIdLong();
                            snprintf(str, sizeof(str), "%"PRIu64, (uint64_t)thread_id);
                            break;
                        }
                        case 't':
                        /* create the filename to use */
                        if (pl->timestamp_format == TS_FORMAT_SEC) {
                            snprintf(str, sizeof(str), "%"PRIu32, (uint32_t)ts.tv_sec);
                        } else {
                            snprintf(str, sizeof(str), "%"PRIu32".%"PRIu32,
                                    (uint32_t)ts.tv_sec, (uint32_t)ts.tv_usec);
                        }
                    }
                    strlcat(filename, str, PATH_MAX);

                /* copy the rest over */
                } else {
                    strlcat(filename, pl->filename_parts[i], PATH_MAX);
                }
            }
        } else {
            int ret;
            /* create the filename to use */
            if (pl->timestamp_format == TS_FORMAT_SEC) {
                ret = snprintf(filename, PATH_MAX, "%s/%s.%u.%" PRIu32, pl->dir,
                        pl->prefix, pl->thread_number, (uint32_t)ts.tv_sec);
            } else {
                ret = snprintf(filename, PATH_MAX, "%s/%s.%u.%" PRIu32 ".%" PRIu32, pl->dir,
                        pl->prefix, pl->thread_number, (uint32_t)ts.tv_sec, (uint32_t)ts.tv_usec);
            }
            if (ret < 0 || (size_t)ret >= PATH_MAX) {
                SCLogError(SC_ERR_SPRINTF,"failed to construct path");
                goto error;
            }
        }
        SCLogDebug("multi-mode: filename %s", filename);
    }

    if ((pf->filename = SCStrdup(pl->filename)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory. For filename");
        goto error;
    }
    SCLogDebug("Opening pcap file log %s", pf->filename);
    TAILQ_INSERT_TAIL(&pl->pcap_file_list, pf, next);

    PCAPLOG_PROFILE_END(pl->profile_open);
    return 0;

error:
    PcapFileNameFree(pf);
    return -1;
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

static void ProfileReportPair(FILE *fp, const char *name, PcapLogProfileData *p)
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

static void ProfileReport(FILE *fp, PcapLogData *pl)
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

static void PcapLogProfilingDump(PcapLogData *pl)
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
        pl->profile_data_size, (int)(pl->profile_data_size / pl->profile_write.cnt));
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

void PcapLogProfileSetup(void)
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
