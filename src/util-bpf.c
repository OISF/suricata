/* Copyright (C) 2018 Open Information Security Foundation
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


#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1
#define SC_PCAP_DONT_INCLUDE_PCAP_H 1

#include "suricata-common.h"
#include "util-bpf.h"

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif



int SCBPFCompile(int snaplen_arg, int linktype_arg, struct bpf_program *program,
                 const char *buf, int optimize, uint32_t mask)
{
    pcap_t *p;
    int ret;

    p = pcap_open_dead(linktype_arg, snaplen_arg);
    if (p == NULL)
        return (-1);
    ret = pcap_compile(p, program, buf, optimize, mask);
    if (ret == -1) {
        SCLogError(SC_ERR_BPF, "BPF compilation error: %s", pcap_geterr(p));
    }
    pcap_close(p);
    return (ret);
}

void SCBPFFree(struct bpf_program *program)
{
    if (program)
        pcap_freecode(program);
}
