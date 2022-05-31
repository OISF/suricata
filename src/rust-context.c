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
#include "rust-context.h"
#include "app-layer-parser.h"
#include "app-layer-register.h"
#include "app-layer-htp-range.h"
#include "app-layer-htp-file.h"

const SuricataContext suricata_context = {
    SCLogMessage,
    DetectEngineStateFree,
    AppLayerDecoderEventsSetEventRaw,
    AppLayerDecoderEventsFreeEvents,
    AppLayerParserTriggerRawStreamReassembly,

    HttpRangeFreeBlock,
    HTPFileCloseHandleRange,

    FileOpenFileWithId,
    FileCloseFileById,
    FileAppendDataById,
    FileAppendGAPById,
    FileContainerRecycle,
    FilePrune,
    FileContainerSetTx,

    AppLayerRegisterParser,
};

const SuricataContext *SCGetContext(void)
{
    return &suricata_context;
}
