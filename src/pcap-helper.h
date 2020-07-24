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

#ifndef __SURICATA_PCAP_HELPER_H__
#define __SURICATA_PCAP_HELPER_H__

struct TimevalHelper {
    bpf_int32 tv_sec;
    bpf_int32 tv_usec;
};

struct PcapSfPktHdr {
    struct TimevalHelper ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
} __attribute__((packed));

void SplitPcapDump(u_char *user, struct pcap_pkthdr *libpcap_hdr,
        const u_char *p1, bpf_u_int32 p1_len, const u_char *p2,
        bpf_u_int32 p2_len);

#endif //SURICATA_PCAP_HELPER_H
