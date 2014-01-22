/* vi: set et ts=4: */
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
 * \author Mike Pomraning <mpomraning@qualys.com>
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 *
 * File-like output for logging:  regular files and sockets.
 * On Tilera PCIe cards (TILEncore-Gx) add the option to send logs
 * across PCIe and then write the output files on the host system.
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "tm-modules.h"      /* LogFileCtx */
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */
#include "util-atomic.h"

#ifdef __tile__
#include <gxio/trio.h>
#include <mde-version.h>
#if MDE_VERSION_CODE >= MDE_VERSION(4,1,0)
#include <gxpci/gxpci.h>
#else
#include <gxpci.h>
#endif

/*
 * Tilera trio (PCIe) configuration.
 */
static gxio_trio_context_t trio_context_body;
static gxio_trio_context_t* trio_context = &trio_context_body;
/*
 * gxpci contexts used for log relay
 */
static gxpci_context_t gxpci_context_body;
static gxpci_context_t *gxpci_context = &gxpci_context_body;
/* The TRIO index. */
static int trio_index = 0;

/* The queue index of a packet queue. */
static unsigned int queue_index = 0;

/* The local PCIe MAC index. */
static int loc_mac;

static PcieFile *SCLogOpenPcieFileFp(const char *path, const char *append_setting);
#endif

/** \brief connect to the indicated local stream socket, logging any errors
 *  \param path filesystem path to connect to
 *  \retval FILE* on success (fdopen'd wrapper of underlying socket)
 *  \retval NULL on error
 */
static FILE *
SCLogOpenUnixSocketFp(const char *path, int sock_type)
{
    struct sockaddr_un sun;
    int s = -1;
    FILE * ret = NULL;

    memset(&sun, 0x00, sizeof(sun));

    s = socket(PF_UNIX, sock_type, 0);
    if (s < 0) goto err;

    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

    if (connect(s, (const struct sockaddr *)&sun, sizeof(sun)) < 0)
        goto err;

    ret = fdopen(s, "w");
    if (ret == NULL)
        goto err;

    return ret;

err:
    SCLogError(SC_ERR_SOCKET, "Error connecting to socket \"%s\": %s",
               path, strerror(errno));

    if (s >= 0)
        close(s);

    return NULL;
}

/** \brief open the indicated file, logging any errors
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static FILE *
SCLogOpenFileFp(const char *path, const char *append_setting)
{
    FILE *ret = NULL;

    if (strcasecmp(append_setting, "yes") == 0) {
        ret = fopen(path, "a");
    } else {
        ret = fopen(path, "w");
    }

    if (ret == NULL)
        SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                   path, strerror(errno));
    return ret;
}

/** \brief open a generic output "log file", which may be a regular file or a socket
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \param default_filename Default name of file to open, if not specified in ConfNode
 *  \retval 0 on success
 *  \retval -1 on error
 */
int
SCConfLogOpenGeneric(ConfNode *conf,
                     LogFileCtx *log_ctx,
                     const char *default_filename)
{
    char log_path[PATH_MAX];
    char *log_dir;
    const char *filename, *filetype;

    // Arg check
    if (conf == NULL || log_ctx == NULL || default_filename == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric(conf %p, ctx %p, default %p) "
                   "missing an argument",
                   conf, log_ctx, default_filename);
        return -1;
    }
    if (log_ctx->fp != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = default_filename;

    log_dir = ConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }

    filetype = ConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    const char *append = ConfNodeLookupChildValue(conf, "append");
    if (append == NULL)
        append = DEFAULT_LOG_MODE_APPEND;

    // Now, what have we been asked to open?
    if (strcasecmp(filetype, "unix_stream") == 0) {
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_STREAM);
    } else if (strcasecmp(filetype, "unix_dgram") == 0) {
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_DGRAM);
    } else if (strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0) {
        log_ctx->fp = SCLogOpenFileFp(log_path, append);
#ifdef __tile__
    } else if (strcasecmp(filetype, "pcie") == 0) {
        log_ctx->pcie_fp = SCLogOpenPcieFileFp(log_path, append);
        if (log_ctx->pcie_fp == NULL)
          return -1; // Error already logged by Open...Fp routine
#endif
    } else {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                   "%s.type.  Expected \"regular\" (default), \"unix_stream\" "
#ifdef __tile__
                   "\"pcie\" "
#endif
                   "or \"unix_dgram\"",
                   conf->name);
    }

    if (log_ctx->fp == NULL)
        return -1; // Error already logged by Open...Fp routine

    SCLogInfo("%s output device (%s) initialized: %s", conf->name, filetype,
              filename);

    return 0;
}

#ifdef __tile__

/*
 * Code for writing files over PCIe to host on Tilera TILEncore PCIe cards.
 */

#define OP_OPEN	   1
#define OP_WRITE   2
#define OP_CLOSE   3

/** Maximum number of commands in one PCIe function call */
#define MAX_CMDS_BATCH 64

typedef struct {
    uint32_t	magic;
    uint32_t	fileno;
    uint32_t	op;
    uint32_t    seq;
    uint32_t	len;
    uint32_t	next_offset;
    char	buf[];
} __attribute__((__packed__)) PcieMsg;

static int gxpci_fileno = 0;
static int pcie_initialized = 0;
/* Allocate a Huge page of memory, registered with Trio, into which
   data to be sent over PCIe is written. Each write starts at wc_pos.
*/
static char *log_mem = NULL;
static uint64_t wr_pos;		/* write position within log_mem */

static SCMutex raw_mutex __attribute__((aligned(64)));
static SCMutex pcie_mutex __attribute__((aligned(64)));
#define CHECK_SEQ_NUM 1
#ifdef CHECK_SEQ_NUM
static uint32_t raw_seq = 0;
#endif
static uint32_t comps_rcvd = 0;
/* Block of memory registered with PCIe DMA engine as a source for
 * PCIe data transfers. Must be <= Huge Page size (16 MB).
 * Must be large enough that it can't wrap before first PCIe transfer
 * has completed.
 */
#define PCIE_MEMORY_BLOCK_SIZE (4 * 1024 * 1024)

/* Send a buffer over PCIe to Host memory.
 * len must be smaller than one Packet Queue transfer block.
 * TODO: Check errors
 */
static void TilePcieDMABuf(void *buf, uint32_t len)
{
    gxpci_comp_t comp[MAX_CMDS_BATCH];
    gxpci_cmd_t cmd;
    int result;
    int credits;

    SCMutexLock(&pcie_mutex);

#ifdef CHECK_SEQ_NUM
    ((PcieMsg *)buf)->seq = ++raw_seq;
    __insn_mf();
#endif

    /* Wait for credits to be available for more PCIe writes. */
    do {
        result = gxpci_get_comps(gxpci_context, comp, 0, MAX_CMDS_BATCH);
        if (result) {
            if (unlikely(result == GXPCI_ERESET)) {
                SCLogInfo("gxpci channel is reset");
                return;
            } else {
                __sync_fetch_and_add(&comps_rcvd, result);
            }
        }

        credits = gxpci_get_cmd_credits(gxpci_context);
        if (unlikely(credits == GXPCI_ERESET)) {
            SCLogInfo("gxpci channel is reset");
            return;
        }
    } while (credits == 0);

    cmd.buffer = buf;
    /* Round transfer size up to next host cache-line. This will
     * transfer more data, but is more efficient.
     */
    cmd.size = (len + (CLS - 1)) & ~(CLS - 1);

    __insn_mf();

    /* Loop until the command is sent. */
    do {
        /* Send PCIe command to packet queue from tile to host. */
        result = gxpci_pq_t2h_cmd(gxpci_context, &cmd);
        if (result == 0)
            break;
        if (result == GXPCI_ERESET) {
            SCLogInfo("gxpci channel is reset");
            break;
        }
        /* Not enough credits to send command? */
        if (result == GXPCI_ECREDITS)
            continue;
    } while (1);

    SCMutexUnlock(&pcie_mutex);
}

/* Allocate a buffer for data that can be sent over PCIe.  Reserves
 * space at the beginning for the Pcie msg.  The buffer is allocated
 * from a 4MB pool on one huge page.  The allocation simply walks
 * throught the buffer sequentially.  This removes the need to free
 * the buffers, as they simply age out.
 */
PcieMsg *TilePcieAllocateBuffer(size_t size)
{
    size += sizeof(PcieMsg);
    /* Round up to cache-line size */
    size = (size + (CLS - 1)) & ~(CLS - 1);

    PcieMsg *pmsg;
    SCMutexLock(&raw_mutex);
    pmsg = (PcieMsg *)&log_mem[wr_pos];
    wr_pos += size;
    if (wr_pos > PCIE_MEMORY_BLOCK_SIZE) {
      /* Don't have enough space at the end of the memory block, so
       * wrap to the start.
       */
        pmsg = (PcieMsg *)&log_mem[0];
        wr_pos = size;

    }
    SCMutexUnlock(&raw_mutex);

    return pmsg;
}

static void PcieWriteOpen(PcieFile *fp, const char *path, const char append)
{
    /* Need space for file name, file mode character and string termination */
    const int buffer_size = strlen(path) + 2;

    /* Allocate space in the PCIe output buffer */
    PcieMsg *p = TilePcieAllocateBuffer(buffer_size);

    p->magic = 5555;
    p->fileno = fp->fileno;
    p->op = OP_OPEN;
    p->len = offsetof(PcieMsg, buf);
    /* Format is one character Mode, followed by file path. */
    p->len += snprintf(p->buf, buffer_size, "%c%s", append, path);

    TilePcieDMABuf(p, p->len);
}

int TilePcieWrite(PcieFile *fp, const char *buffer, int buffer_len)
{
    /* Allocate space in the PCIe output buffer */
    PcieMsg *p = TilePcieAllocateBuffer(buffer_len);

    p->magic = 5555;
    p->fileno = fp->fileno;
    p->op = OP_WRITE;
    p->len = offsetof(PcieMsg, buf);
    p->len += buffer_len;
    p->next_offset = 0;

    /* Can remove the need for this memcpy later. */
    memcpy(p->buf, buffer, buffer_len);

    TilePcieDMABuf(p, p->len);

    return 0;
}

static PcieFile *TilePcieOpenFileFp(const char *path, const char append_setting)
{
    int result;
    PcieFile *fp;

    /* Only initialize once */
    if (SCAtomicCompareAndSwap(&pcie_initialized, 0, 1)) {
        SCMutexInit(&raw_mutex, NULL);
        SCMutexInit(&pcie_mutex, NULL);

        SCLogInfo("Initializing Tile-Gx PCIe index %d / %d, queue: %d", 
                  trio_index, loc_mac, queue_index);
        
        result = gxio_trio_init(trio_context, trio_index);
        if (result < 0) {
            pcie_initialized = 0;
            SCLogError(SC_ERR_PCIE_INIT_FAILED,
                       "gxio_trio_init() failed: %d: %s",
                       result, gxio_strerror(result));
            return NULL;
        }

        result = gxpci_init(trio_context, gxpci_context, trio_index, loc_mac);
        if (result < 0) {
            pcie_initialized = 0;
            SCLogError(SC_ERR_PCIE_INIT_FAILED,
                       "gxpci_init() failed: %d: %s",
                       result, gxpci_strerror(result));
            return NULL;
        }

        /*
         * This indicates that we need to allocate an ASID ourselves,
         * instead of using one that is allocated somewhere else.
         */
        int asid = GXIO_ASID_NULL;

        result = gxpci_open_queue(gxpci_context, asid, GXPCI_PQ_T2H, 0,
                                  queue_index, 0, 0);
        if (result < 0) {
            pcie_initialized = 0;
            SCLogError(SC_ERR_PCIE_INIT_FAILED,
                       "gxpci_open_queue() failed: %d: %s",
                       result, gxpci_strerror(result));
            return NULL;
        }

        /*
         * Allocate and register data buffer
         */
        size_t hugepagesz = tmc_alloc_get_huge_pagesize();
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_huge(&alloc);
        tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);
        tmc_alloc_set_pagesize_exact(&alloc, hugepagesz);
        log_mem = tmc_alloc_map(&alloc, hugepagesz);
        BUG_ON(PCIE_MEMORY_BLOCK_SIZE > hugepagesz);

        result = gxpci_iomem_register(gxpci_context, log_mem, hugepagesz);
        if (result < 0) {
            pcie_initialized = 0;
            SCLogError(SC_ERR_PCIE_INIT_FAILED,
                       "gxpci_iomem_register() failed: %d: %s",
                       result, gxpci_strerror(result));
            return NULL;
        }
    }
    fp = SCMalloc(sizeof(PcieFile));
    if (fp == NULL) {
        SCLogError(SC_ERR_PCIE_INIT_FAILED,
                   "Failed to Allocate memory for PCIe file pointer");

        return NULL;
    }

    /* Sequentially allocate File descriptor numbers. Not currently ever freed */
    fp->fileno = SCAtomicFetchAndAdd(&gxpci_fileno, 1);
    PcieWriteOpen(fp, path, append_setting);

    return fp;
}

/** \brief open the indicated file remotely over PCIe to a host
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static PcieFile *
SCLogOpenPcieFileFp(const char *path, const char *append_setting)
{
    PcieFile *ret = NULL;

    if (strcasecmp(append_setting, "yes") == 0) {
        ret = TilePcieOpenFileFp(path, 'a');
    } else {
        ret = TilePcieOpenFileFp(path, 'w');
    }

    if (ret == NULL)
        SCLogError(SC_ERR_FOPEN, "Error opening PCIe file: \"%s\": %s",
                   path, strerror(errno));
    return ret;
}

#endif // __tilegx__
