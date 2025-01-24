/* Copyright (C) 2011,2012 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef SURICATA_SOURCE_AFP_H
#define SURICATA_SOURCE_AFP_H

#ifndef HAVE_PACKET_FANOUT /* not defined if linux/if_packet.h trying to force */
#define HAVE_PACKET_FANOUT 1

#define PACKET_FANOUT                  18

#define PACKET_FANOUT_HASH             0
#define PACKET_FANOUT_LB               1
#define PACKET_FANOUT_CPU              2
#define PACKET_FANOUT_ROLLOVER         3
#define PACKET_FANOUT_RND              4
#define PACKET_FANOUT_QM               5

#define PACKET_FANOUT_FLAG_ROLLOVER	   0x1000
#define PACKET_FANOUT_FLAG_DEFRAG      0x8000
#else /* HAVE_PACKET_FANOUT */
#include <linux/if_packet.h>
#endif /* HAVE_PACKET_FANOUT */
#include "queue.h"

#ifdef HAVE_PACKET_EBPF
#define AFP_MODE_XDP_BYPASS 1
#define AFP_MODE_EBPF_BYPASS 2
struct ebpf_timeout_config {
    const char *pinned_maps_name;
    uint16_t cpus_count;
    uint8_t mode;
    uint8_t flags;
};
#endif

/* value for flags */
#define AFP_NEED_PEER (1 << 0)
// (1<<1) vacant
#define AFP_SOCK_PROTECT (1<<2)
#define AFP_EMERGENCY_MODE (1<<3)
#define AFP_TPACKET_V3 (1<<4)
#define AFP_VLAN_IN_HEADER (1<<5)
#define AFP_MMAP_LOCKED (1<<6)
#define AFP_BYPASS   (1<<7)
#define AFP_XDPBYPASS   (1<<8)

#define AFP_COPY_MODE_NONE  0
#define AFP_COPY_MODE_TAP   1
#define AFP_COPY_MODE_IPS   2

#define AFP_IFACE_NAME_LENGTH 48

/* In kernel the allocated block size is allocated using the formula
 * page_size << order. So default value is using the same formula with
 * an order of 3 which guarantee we have some room in the block compared
 * to standard frame size */
#define AFP_BLOCK_SIZE_DEFAULT_ORDER 3

typedef struct AFPIfaceConfig_
{
    char iface[AFP_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;
    /* socket buffer size */
    int buffer_size;
    /* ring size in number of packets */
    int ring_size;
    /* block size for tpacket_v3 in */
    int block_size;
    /* block timeout for tpacket_v3 in milliseconds */
    int block_timeout;
    /* cluster param */
    uint16_t cluster_id;
    int cluster_type;
    /* promisc mode */
    int promisc;
    /* misc use flags including ring mode */
    unsigned int flags;
    uint8_t copy_mode;
    ChecksumValidationMode checksum_mode;
    const char *bpf_filter;
    const char *ebpf_lb_file;
    int ebpf_lb_fd;
    const char *ebpf_filter_file;
    int ebpf_filter_fd;
    const char *xdp_filter_file;
    int xdp_filter_fd;
    uint8_t xdp_mode;
    const char *out_iface;
#ifdef HAVE_PACKET_EBPF
    struct ebpf_timeout_config ebpf_t_config;
#endif
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} AFPIfaceConfig;

/**
 * \ingroup afppeers
 * @{
 */

typedef struct AFPPeer_ {
    SC_ATOMIC_DECLARE(int, socket);
    SC_ATOMIC_DECLARE(int, sock_usage);
    SC_ATOMIC_DECLARE(int, if_idx);
    SC_ATOMIC_DECLARE(uint64_t, send_errors);
    int flags;
    SCMutex sock_protect;
    int turn; /**< Field used to store initialisation order. */
    SC_ATOMIC_DECLARE(uint8_t, state);
    struct AFPPeer_ *peer;
    TAILQ_ENTRY(AFPPeer_) next;
    char iface[AFP_IFACE_NAME_LENGTH];
} AFPPeer;

/**
 * \brief per packet AF_PACKET vars
 *
 * This structure is used y the release data system and is cleaned
 * up by the AFPV_CLEANUP macro below.
 */
typedef struct AFPPacketVars_
{
    void *relptr;
    AFPPeer *peer; /**< Sending peer for IPS/TAP mode */
    /** Pointer to ::AFPPeer used for capture. Field is used to be able
     * to do reference counting.
     */
    AFPPeer *mpeer;
    uint8_t copy_mode;
    uint16_t vlan_tci;
#ifdef HAVE_PACKET_EBPF
    int v4_map_fd;
    int v6_map_fd;
    unsigned int nr_cpus;
#endif
} AFPPacketVars;

#ifdef HAVE_PACKET_EBPF
#define AFPV_CLEANUP(afpv)                                                                         \
    do {                                                                                           \
        (afpv)->relptr = NULL;                                                                     \
        (afpv)->copy_mode = 0;                                                                     \
        (afpv)->vlan_tci = 0;                                                                      \
        (afpv)->peer = NULL;                                                                       \
        (afpv)->mpeer = NULL;                                                                      \
        (afpv)->v4_map_fd = -1;                                                                    \
        (afpv)->v6_map_fd = -1;                                                                    \
    } while (0)
#else
#define AFPV_CLEANUP(afpv)                                                                         \
    do {                                                                                           \
        (afpv)->relptr = NULL;                                                                     \
        (afpv)->copy_mode = 0;                                                                     \
        (afpv)->vlan_tci = 0;                                                                      \
        (afpv)->peer = NULL;                                                                       \
        (afpv)->mpeer = NULL;                                                                      \
    } while (0)
#endif

/**
 * @}
 */

void TmModuleReceiveAFPRegister(void);

TmEcode AFPPeersListInit(void);
TmEcode AFPPeersListCheck(void);
void AFPPeersListClean(void);
int AFPGetLinkType(const char *ifname);

int AFPIsFanoutSupported(uint16_t cluster_id);

#endif /* SURICATA_SOURCE_AFP_H */
