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
 * NFS application layer detector and parser
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-nfs-udp.h"

#include "rust.h"

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert nfs any any -> any any (msg:"SURICATA NFS empty message"; \
 *    app-layer-event:nfs.empty_message; sid:X; rev:Y;)
 */
enum {
    NFS_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap nfs_udp_decoder_event_table[] = {
    {"EMPTY_MESSAGE", NFS_DECODER_EVENT_EMPTY_MESSAGE},
    { NULL, 0 }
};


static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

void RegisterNFSUDPParsers(void)
{
    rs_nfs_init(&sfc);
    rs_nfs_udp_register_parser();

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_NFS,
        NFSUDPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void NFSUDPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
