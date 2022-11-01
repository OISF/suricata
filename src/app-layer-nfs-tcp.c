/* Copyright (C) 2015-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * NFS application layer detector and parser.
 *
 * This implements a application layer for the NFS protocol
 * running on port 2049.
 */

#include "suricata-common.h"

#include "app-layer-detect-proto.h"

#include "app-layer-nfs-tcp.h"

#include "rust.h"


static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

void RegisterNFSTCPParsers(void)
{
    const char *proto_name = "nfs";

    /* Check if NFSTCP TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        rs_nfs_init(&sfc);
        rs_nfs_register_parser();
    }
}
