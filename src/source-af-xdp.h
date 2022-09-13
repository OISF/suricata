/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Richard McConnell <richard_mcconnell@rapid7.com>
 */

#ifndef __SOURCE_AFXDP_H__
#define __SOURCE_AFXDP_H__

#define AFXDP_IFACE_NAME_LENGTH 48

typedef struct AFXDPIfaceConfig {
    char iface[AFXDP_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;
    int promisc;

    /* misc use flags */
    uint32_t mode;
    uint32_t bind_flags;
    int mem_alignment;
    bool enable_busy_poll;
    uint32_t busy_poll_time;
    uint32_t busy_poll_budget;
    uint32_t gro_flush_timeout;
    uint32_t napi_defer_hard_irqs;

    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} AFXDPIfaceConfig;

/**
 * \brief per packet AF_XDP vars
 *
 * This structure is used by the release data system
 */
typedef struct AFXDPPacketVars_ {
    void *fq;
    uint32_t fq_idx;
    uint64_t orig;
} AFXDPPacketVars;

void TmModuleReceiveAFXDPRegister(void);
void TmModuleDecodeAFXDPRegister(void);

TmEcode AFXDPQueueProtectionInit(void);
void AFXDPMutexClean(void);

#endif /* __SOURCE_AFXDP_H__ */
