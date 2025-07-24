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
 * PCAP File Info support structure
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-debug.h"
#include "source-pcap-file-info-helper.h"

PcapFileInfo *PcapFileInfoAddReference(PcapFileInfo *pfi)
{
    SCEnter();
    SCRunMode runmode = SCRunmodeGet();
    if (runmode != RUNMODE_PCAP_FILE && runmode != RUNMODE_UNIX_SOCKET) {
        SCReturnPtr(NULL, "PcapFileInfo *");
    }
    (void)SC_ATOMIC_ADD(pfi->ref, 1);
    SCReturnPtr(pfi, "PcapFileInfo *");
}

PcapFileInfo *PcapFileInfoInit(const char *filename)
{
    SCEnter();
    PcapFileInfo *pfi = SCCalloc(1, sizeof(PcapFileInfo));
    if (unlikely(pfi == NULL)) {
        SCLogError("Failed to allocate memory for PcapFileInfo");
        SCReturnPtr(NULL, "PcapFileInfo *");
    }

    pfi->filename = SCStrdup(filename);
    if (unlikely(pfi->filename == NULL)) {
        SCLogError("Failed to allocate memory for PcapFileInfo filename");
        SCFree(pfi);
        SCReturnPtr(NULL, "PcapFileInfo *");
    }

    SC_ATOMIC_INIT(pfi->ref);
    PcapFileInfoAddReference(pfi);

    SCReturnPtr(pfi, "PcapFileInfo *");
}

void PcapFileInfoDeref(PcapFileInfo **pfi)
{
    SCEnter();
    SCRunMode runmode = SCRunmodeGet();
    if (runmode != RUNMODE_PCAP_FILE && runmode != RUNMODE_UNIX_SOCKET) {
        SCReturn;
    }

    if (unlikely(pfi == NULL || *pfi == NULL)) {
        SCReturn;
    } else if (SC_ATOMIC_SUB((*pfi)->ref, 1) == 1) {
        if ((*pfi)->filename) {
            SCFree((*pfi)->filename);
        }
        SCFree(*pfi);
    }
    *pfi = NULL;
    SCReturn;
}
