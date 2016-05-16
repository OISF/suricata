/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 *
 * File-like output for logging on Tilera PCIe cards (TILEncore-Gx)
 * add the option to send logs across PCIe and then write the output
 * files on the host system.
 *
 */
#include <sys/types.h>

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "tm-modules.h"      /* LogFileCtx */
#include "conf.h"            /* ConfNode, etc. */
#include "util-atomic.h"
#include "util-logopenfile-tile.h"

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

/*
 * Code for writing files over PCIe to host on Tilera TILEncore PCIe cards.
 */

#define OP_OPEN    1
#define OP_WRITE   2
#define OP_CLOSE   3

/** Maximum number of commands in one PCIe function call */
#define MAX_CMDS_BATCH 64

typedef struct {
    uint32_t    magic;
    uint32_t    fileno;
    uint32_t    op;
    uint32_t    seq;
    uint32_t    len;
    uint32_t    next_offset;
    char        buf[];
} __attribute__((__packed__)) PcieMsg;

static int gxpci_fileno = 0;
static int pcie_initialized = 0;
/* Allocate a Huge page of memory, registered with Trio, into which
   data to be sent over PCIe is written. Each write starts at wc_pos.
*/
static char *log_mem = NULL;
static uint64_t wr_pos;         /* write position within log_mem */

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
static PcieMsg *TilePcieAllocateBuffer(size_t size)
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

static int TilePcieWrite(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    PcieFile *fp = log_ctx->pcie_fp;
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

    return buffer_len;
}

static PcieFile *TileOpenPcieFpInternal(const char *path, const char append_char)
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
    PcieWriteOpen(fp, path, append_char);

    return fp;
}

/** \brief Close a PCIe file
 *  \param PCIe file desriptor
 */
static void TileClosePcieFp(LogFileCtx *log_ctx)
{
    SCLogInfo("Closing Tile-Gx PCIe: %s", log_ctx->filename);

    /* TODO: Need to count open files and close when reaches zero. */
    SCMutexLock(&pcie_mutex);

    if (gxpci_context) {
        gxpci_destroy(gxpci_context);
        gxpci_context = NULL;
    }

    SCMutexUnlock(&pcie_mutex);

    free(log_ctx->pcie_fp);
}

/** \brief open the indicated file remotely over PCIe to a host
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
PcieFile *TileOpenPcieFp(LogFileCtx *log_ctx, const char *path,
                         const char *append_setting)
{
    PcieFile *ret = NULL;
    if (ConfValIsTrue(append_setting)) {
        ret = TileOpenPcieFpInternal(path, 'a');
    } else {
        ret = TileOpenPcieFpInternal(path, 'w');
    }

    /* Override the default Write and Close functions
     * with PCIe Write and Close functions.
     */
    log_ctx->Write = TilePcieWrite;
    log_ctx->Close = TileClosePcieFp;

    if (ret == NULL)
        SCLogError(SC_ERR_FOPEN, "Error opening PCIe file: \"%s\": %s",
                   path, strerror(errno));
    return ret;
}

#endif /* __tilegx__ */
