/* Copyright (C) 2013-2014 Tilera Corporation.
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
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * Host side of PCIe alert logging from Suricata running on a
 * TILEncore-Gx card.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include <asm/tilegxpci.h>

#define CHECK_SEQ_NUM 1

/* The "/dev/tilegxpci%d" device to be used. */
unsigned int card_index = 0;

unsigned int debug = 0;

/*
 * When set, drop all alerts rather than write to file. This is for
 * testing performance on a file system that can't write files fast
 * enough.
 */
unsigned int drop_alerts = 0;

/* Packet queue index. */
unsigned int queue_index;

/* Prefix added to all file paths sent from PCIe card. */
char * path_prefix = NULL;

/* By default, the host ring buffer is 4MB in size and it consists of
 * 1024 entries of 4KB buffers. Modify GXPCI_HOST_PQ_RING_ENTRIES in
 * <asm/tilegxpci.h> to change the size of each buffer. To increase
 * the total ring buffer size, re-configure the host kernel using
 * CONFIG_FORCE_MAX_ZONEORDER.
 */
#ifdef GXPCI_HOST_PQ_SEGMENT_ENTRIES
/* New definitions for MDE 4.1.5 */
#define RING_BUF_ELEMS      GXPCI_HOST_PQ_SEGMENT_ENTRIES
#define RING_BUF_ELEM_SIZE  (HOST_PQ_SEGMENT_MAX_SIZE / GXPCI_HOST_PQ_SEGMENT_ENTRIES)
#else
/* Definitions prior to MDE 4.1.5 */
#define RING_BUF_ELEMS      GXPCI_HOST_PQ_RING_ENTRIES
#define RING_BUF_ELEM_SIZE  (HOST_PQ_RING_BUF_MAX_SIZE / GXPCI_HOST_PQ_RING_ENTRIES)
#endif

/*********************************************************************/
/*                        Host-Side Packet Consumer                  */
/*********************************************************************/

#define TAIL_UPDATE_LIMIT_ENABLE

#define OP_OPEN         1
#define OP_WRITE        2
#define OP_CLOSE        3

typedef struct {
    uint32_t    magic;
    uint32_t    fileno;
    uint32_t    op;
    uint32_t    seq;
    volatile uint32_t    len;
    uint32_t    next_offset;
    char        buf[];
} TrioMsg;

typedef struct {
    FILE *fd;
} FDesc;

#define MAX_FDESC 1024

static FDesc *fdesc[MAX_FDESC];

void run_pcie_logging(void)
{
    char dev_name[40];
    int pq_fd;
    unsigned int host_ring_buffer_size = RING_BUF_ELEMS * RING_BUF_ELEM_SIZE;
    volatile TrioMsg *p;

    printf("Waiting for PCIe logging data from card %d on queue %d...\n", 
           card_index, queue_index);

    if (path_prefix) {
        printf("PCIe logging into directory: '%s'\n", path_prefix);
        fflush(stdout);
    }

    /* Open the packet queue file. */
    snprintf(dev_name, sizeof(dev_name), "/dev/tilegxpci%d/packet_queue/t2h/%d",
             card_index, queue_index);
    do {
        pq_fd = open(dev_name, O_RDWR);
        if (pq_fd < 0) {
            sleep(1);
        }
    } while (pq_fd < 0);

    /* mmap the register space. */
    struct gxpci_host_pq_regs_app* pq_regs =
        (struct gxpci_host_pq_regs_app*)
        mmap(0, sizeof(struct gxpci_host_pq_regs_app),
             PROT_READ | PROT_WRITE,
             MAP_SHARED, pq_fd, TILEPCI_PACKET_QUEUE_INDICES_MMAP_OFFSET);
    if (pq_regs == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap PCIe control registers.\n");
        exit(EXIT_FAILURE);
    }

    /* Configure and allocate the ring buffer for the receive queue. */
    tilepci_packet_queue_info_t buf_info;

    buf_info.buf_size = RING_BUF_ELEM_SIZE;

    int err = ioctl(pq_fd, TILEPCI_IOC_SET_PACKET_QUEUE_BUF, &buf_info);
    if (err < 0) {
        fprintf(stderr, "Failed TILEPCI_IOC_SET_PACKET_QUEUE_BUF: %s\n",
                strerror(errno));
        abort();
    }

    /* On the host side, mmap the receive queue region. */
    void* buffer =
        mmap(0, host_ring_buffer_size, PROT_READ | PROT_WRITE,
             MAP_SHARED, pq_fd, TILEPCI_PACKET_QUEUE_BUF_MMAP_OFFSET);
    assert(buffer != MAP_FAILED);

    /* On the host side, mmap the queue status. */
    struct tlr_pq_status *pq_status =
        mmap(0, sizeof(struct tlr_pq_status), PROT_READ | PROT_WRITE,
             MAP_SHARED, pq_fd, TILEPCI_PACKET_QUEUE_STS_MMAP_OFFSET);
    assert(pq_status != MAP_FAILED);

    pq_regs->consumer_index = 0;

    uint64_t packet_count = 0;
    volatile uint32_t write;
    uint32_t read = 0;

#ifdef CHECK_SEQ_NUM
    uint32_t expect_seq = 1;
#endif
    
#ifdef HOST_INTERRUPT_MODE
    volatile uint32_t* producer_index = &(pq_status->drv_consumer_index);
#else
    volatile uint32_t* producer_index = &(pq_regs->producer_index);
#endif

    volatile uint32_t* consumer_index = &(pq_regs->consumer_index);
    volatile enum gxpci_chan_status_t* status = &(pq_status->status);

    while (1) {
        if (*status == GXPCI_CHAN_RESET) {
            printf("Tile to Host PCIe logging channel was reset.\n");
            fflush(stdout);
            return;
        }

        // Get packets off the ring buffer by accessing the receive queue at
        // the new write index.
        write = *producer_index;

        while (write != read) {
            if (*status == GXPCI_CHAN_RESET) {
                printf("Tile to Host PCIe logging channel was reset.\n");
                fflush(stdout);
                return;
            }

            packet_count++;

            p = (TrioMsg *)(buffer + ((read&(RING_BUF_ELEMS-1))*RING_BUF_ELEM_SIZE));

            if (debug) {
                fprintf(stdout, "got a message\n");
                fprintf(stdout, "p->magic: %d\n", p->magic);
                fprintf(stdout, "p->fileno: %d\n", p->fileno);
#ifdef CHECK_SEQ_NUM
                fprintf(stdout, "p->seq: %d\n", p->seq);
#endif
                fprintf(stdout, "p->len: %d\n", p->len);
                fprintf(stdout, "p->next_offset: %d\n", p->next_offset);
                fprintf(stdout, "p->buf: ");
                fwrite((char *)&p->buf, sizeof(char), p->len - offsetof(TrioMsg, buf), stdout);
                fprintf(stdout, "\n");
                fflush(stdout);
            }

#ifdef CHECK_SEQ_NUM
            if (p->seq != expect_seq) {
                /* Check for a reset before reporting a bad sequence
                 * number to prevent confusing users. */
                if (*status == GXPCI_CHAN_RESET) {
                    printf("Tile to Host PCIe logging channel was reset.\n");
                    fflush(stdout);
                    return;
                }
                fprintf(stderr, "BAD sequence expected %d got %d\n", expect_seq, p->seq);
                return;
            }
            expect_seq = p->seq + 1;
#endif

            switch (p->op) {
            case OP_OPEN:
                if (p->fileno < MAX_FDESC) {
                    fdesc[p->fileno] = malloc(sizeof(FDesc));
                    if (fdesc[p->fileno]) {
                        char mode[2];
                        mode[0] = p->buf[0];
                        mode[1] = '\0';
                        char *file_name = (char *)&p->buf[1];
                        if (path_prefix) {
                            /* Added path_prefix to the start of the
                             * file name. Added space for '\0' and '\'.
                             * By default, no prefix is added. */
                            int new_size = strlen(path_prefix) + strlen(file_name) + 1 + 1;
                            char *new_name = malloc(new_size);
                            if (!new_name) {
                                fprintf(stderr, "Failed to allocate memory for %s/%s\n",
                                        path_prefix, file_name);
                                return;
                            }
                            snprintf(new_name, new_size, "%s/%s", 
                                     path_prefix, file_name);
                            file_name = new_name;
                        }
                        if ((fdesc[p->fileno]->fd = fopen(file_name, mode)) == NULL) {
                            fprintf(stderr, "Could not open %s: %s\n",
                                    file_name, strerror(errno));
                        } else {
                            printf("Opened '%s' for logging.\n", file_name);
                            fflush(stdout);
                        }
                    }
                } else {
                    fprintf(stderr, "File number %d exceeds Max of %d\n", p->fileno, MAX_FDESC);
                }
                break;
            case OP_WRITE:
                if (drop_alerts) {
                    /* TODO: Report alert count periodically. */
                } else {
                    if (fdesc[p->fileno] && fdesc[p->fileno]->fd) {
                        fwrite((char *)&p->buf, sizeof(char),
                               p->len - offsetof(TrioMsg, buf),
                               fdesc[p->fileno]->fd);
                        fflush(fdesc[p->fileno]->fd);
                    }
                }
                break;
            case OP_CLOSE:
                if (fdesc[p->fileno] && fdesc[p->fileno]->fd) {
                    fclose( fdesc[p->fileno]->fd);
                    free(fdesc[p->fileno]);
                    fdesc[p->fileno] = NULL;
                }
                break;
            }

            read++;
            /* Update the read index register to inform the tile side
             * that the packet has been read. */

#ifdef TAIL_UPDATE_LIMIT_ENABLE
            if ((packet_count & 0x3f) == 0)
                *consumer_index = read;
#else
            *consumer_index = read;
#endif
        }
    }
    return;
}

/*
 * Match argument list option.
 * Options ending in '=' take an additional value, which may be
 * attached in the same argument or detached in the following
 * argument.
 * @param arglist       Points to remaining argv, updated on match.
 * @param option        The option to match, ending in '=' if it takes a value.
 * @return              Value if option matches, NULL otherwise.
 */
char *shift_option(char ***arglist, const char* option)
{
    char** args = *arglist;
    char* arg = args[0], **rest = &args[1];
    int optlen = strlen(option);
    char* val = arg+optlen;
    if (option[optlen - 1] != '=') {
        if (strcmp(arg, option))
            return NULL;
    } else {
        if (strncmp(arg, option, optlen-1))
            return NULL;
        if (arg[optlen- 1 ] == '\0')
            val = *rest++;
        else if (arg[optlen - 1] != '=')
            return NULL;
    }
    *arglist = rest;
    return val;
}

int main(int argc, char** argv)
{
    char **args = &argv[1];

    /*
     * Scan command line options.
     */
    while (*args) {
        char* opt = NULL;

        if ((opt = shift_option(&args, "--queue_index=")))
            queue_index = strtoul(opt, NULL, 0);
        else if ((opt = shift_option(&args, "--card=")))
            card_index = strtoul(opt, NULL, 0);
        else if ((opt = shift_option(&args, "--debug")))
            debug = 1;
        else if ((opt = shift_option(&args, "--drop")))
            drop_alerts = 1;
        else if ((opt = shift_option(&args, "--prefix=")))
            path_prefix = opt;
        else {
            fprintf(stderr, "Unknown option '%s'.\n", args[0]);
            exit(EXIT_FAILURE);
        }
    }

    run_pcie_logging();

    return 0;
}
