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

#include "suricata-common.h"
#include "util-bpf.h"
#include "threads.h"
#include "conf.h"
#include "util-debug.h"

void ConfSetBPFFilter(
        ConfNode *if_root, ConfNode *if_default, const char *iface, const char **bpf_filter)
{
    if (*bpf_filter != NULL) {
        SCLogInfo("BPF filter already configured");
        return;
    }

    /* command line value has precedence */
    if (ConfGet("bpf-filter", bpf_filter) == 1) {
        if (strlen(*bpf_filter) > 0) {
            SCLogConfig("%s: using command-line provided bpf filter '%s'", iface, *bpf_filter);
        }
    } else if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", bpf_filter) ==
               1) { // reading from a file
        if (strlen(*bpf_filter) > 0) {
            SCLogConfig("%s: using file provided bpf filter %s", iface, *bpf_filter);
        }
    } else {
        SCLogDebug("No BPF filter found, skipping");
    }
}

/** protect bpf filter build, as it is not thread safe */
static SCMutex bpf_set_filter_lock = SCMUTEX_INITIALIZER;

void SCBPFFree(struct bpf_program *program)
{
    if (program)
        pcap_freecode(program);
}

int SCBPFCompile(int snaplen_arg, int linktype_arg, struct bpf_program *program,
                 const char *buf,
                 int optimize, uint32_t mask,
                 char *errbuf, size_t errbuf_len)
{
    pcap_t *p;
    int ret;

    p = pcap_open_dead(linktype_arg, snaplen_arg);
    if (p == NULL)
        return (-1);

    SCMutexLock(&bpf_set_filter_lock);
    ret = pcap_compile(p, program, buf, optimize, mask);
    if (ret == -1) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "%s", pcap_geterr(p));
        }
        pcap_close(p);
        SCMutexUnlock(&bpf_set_filter_lock);
        return (-1);
    }
    pcap_close(p);
    SCMutexUnlock(&bpf_set_filter_lock);

    if (program->bf_insns == NULL) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "Filter badly setup");
        }
        SCBPFFree(program);
        return (-1);
    }

    return (ret);
}
