/* Copyright (C) 2020 Open Information Security Foundation
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

#include "suricata-common.h"
#include "pcap-helper.h"
#include "util-error.h"

void SplitPcapDump(u_char *user, struct pcap_pkthdr *libpcap_hdr,
        const u_char *p1, bpf_u_int32 p1_len, const u_char *p2,
        bpf_u_int32 p2_len) {
    /*
     * Check for overflow due to packet lengths.
     */
    if ((p1_len + p2_len) < p1_len) {
        SCLogError(SC_ERR_PCAPLEN_OVERFLOW,"Error in SplitPcapDump. Overflow "
                                           "due to packet lengths.");
        return;
    }
    register FILE *f;
    struct PcapSfPktHdr sf_hdr;
    size_t ret;
    f = (FILE *) user;

    /*
     * Better not try writing pcap files after 2038-01-19 03:14:07 UTC; switch
     * to pcapng.
     */
    sf_hdr.ts.tv_sec = libpcap_hdr->ts.tv_sec;
    sf_hdr.ts.tv_usec = libpcap_hdr->ts.tv_usec;
    sf_hdr.caplen = p1_len + p2_len;
    sf_hdr.len = p1_len + p2_len;

    /*
     * Write libpcap header.
     */
    ret = fwrite(&sf_hdr, sizeof(sf_hdr), 1, f);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error writing libpcap header. Error: %s",
                strerror(errno));
        return;
    }
    /*
     * Write the first part of the packet. In our use case this is the
     * separately tracked packet header.
     */
    ret = fwrite(p1, p1_len, 1, f);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error writing first portion of packet. "
                                  "Error %s", strerror(errno));
        return;
    }
    /*
     * Write the second part of the packet. In our use case this is the packet
     * payload.
     */
    ret = fwrite(p2, p2_len, 1, f);
    if (ret != 1) {
        SCLogError(SC_ERR_FWRITE, "Error writing second portion of packet. "
                                  "Error %s", strerror(errno));
    }
}

