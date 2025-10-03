/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * Functions for pcap packet counter manipulation.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "source-pcap-packet.h"
#include "runmodes.h"

static inline bool PcapPacketNumRunmodeCanAccess(void)
{
    return SCRunmodeGet() == RUNMODE_PCAP_FILE || SCRunmodeGet() == RUNMODE_UNITTEST ||
           SCRunmodeGet() == RUNMODE_UNIX_SOCKET;
}

inline uint64_t PcapPacketCntGet(const Packet *p)
{
    if (PcapPacketNumRunmodeCanAccess() && p != NULL) {
        return p->pcap_v.pcap_cnt;
    }
    return 0;
}

inline void PcapPacketCntSet(Packet *p, uint64_t pcap_cnt)
{
    if (PcapPacketNumRunmodeCanAccess() && p != NULL) {
        p->pcap_v.pcap_cnt = pcap_cnt;
    }
}

inline void PcapPacketCntReset(Packet *p)
{
    if (PcapPacketNumRunmodeCanAccess() && p != NULL) {
        p->pcap_v.pcap_cnt = 0;
    }
}