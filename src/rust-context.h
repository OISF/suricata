/* Copyright (C) 2017 Open Information Security Foundation
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

#ifndef SURICATA_RUST_CONTEXT_H
#define SURICATA_RUST_CONTEXT_H

#include "flow.h"
#include "detect.h"
#include "detect-engine-state.h" //DetectEngineState

#include "app-layer-ike.h" //IKEState, IKETransaction
#include "app-layer-tftp.h" //TFTPState, TFTPTransaction

#include "util-debug.h"
#include "util-file.h"

// hack for include orders cf SCSha256
typedef struct HttpRangeContainerBlock HttpRangeContainerBlock;

struct AppLayerParser;

typedef struct SuricataContext_ {
    SCError (*SCLogMessage)(const SCLogLevel, const char *, const unsigned int, const char *,
            const char *, const char *message);
    void (*DetectEngineStateFree)(DetectEngineState *);
    void (*AppLayerDecoderEventsSetEventRaw)(AppLayerDecoderEvents **,
            uint8_t);
    void (*AppLayerDecoderEventsFreeEvents)(AppLayerDecoderEvents **);
    void (*AppLayerParserTriggerRawStreamReassembly)(Flow *, int direction);

    void (*HttpRangeFreeBlock)(HttpRangeContainerBlock *);
    bool (*HTPFileCloseHandleRange)(const StreamingBufferConfig *sbcfg, FileContainer *,
            const uint16_t, HttpRangeContainerBlock *, const uint8_t *, uint32_t);

    int (*FileOpenFileWithId)(FileContainer *, const StreamingBufferConfig *,
        uint32_t track_id, const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags);
    int (*FileCloseFileById)(FileContainer *, const StreamingBufferConfig *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len, uint16_t flags);
    int (*FileAppendDataById)(FileContainer *, const StreamingBufferConfig *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len);
    int (*FileAppendGAPById)(FileContainer *, const StreamingBufferConfig *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len);
    void (*FileContainerRecycle)(FileContainer *ffc, const StreamingBufferConfig *);
} SuricataContext;

extern const SuricataContext suricata_context;

typedef struct SuricataFileContext_ {

    const StreamingBufferConfig *sbcfg;

} SuricataFileContext;

const SuricataContext *SCGetContext(void);

#endif /* !SURICATA_RUST_CONTEXT_H */
