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

#ifndef __RUST_CONTEXT_H__
#define __RUST_CONTEXT_H__

#include "detect-engine-state.h" //DetectEngineState
#include "app-layer-krb5.h" //KRB5State, KRB5Transaction
#include "app-layer-ikev2.h" //IKEV2State, IKEV2Transaction
#include "app-layer-ntp.h" //NTPState, NTPTransaction
#include "app-layer-snmp.h" //SNMPState, SNMPTransaction
#include "app-layer-tftp.h" //TFTPState, TFTPTransaction

// hack for include orders cf SCSha256
typedef struct HttpRangeContainerBlock HttpRangeContainerBlock;

typedef struct SuricataContext_ {
    SCError (*SCLogMessage)(const SCLogLevel, const char *, const unsigned int,
            const char *, const SCError, const char *message);
    void (*DetectEngineStateFree)(DetectEngineState *);
    void (*AppLayerDecoderEventsSetEventRaw)(AppLayerDecoderEvents **,
            uint8_t);
    void (*AppLayerDecoderEventsFreeEvents)(AppLayerDecoderEvents **);
    void (*AppLayerParserTriggerRawStreamReassembly)(Flow *, int direction);

    void (*HttpRangeFreeBlock)(HttpRangeContainerBlock *);
    void (*HTPFileCloseHandleRange)(
            FileContainer *, const uint16_t, HttpRangeContainerBlock *, const uint8_t *, uint32_t);

    int (*FileOpenFileWithId)(FileContainer *, const StreamingBufferConfig *,
        uint32_t track_id, const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags);
    int (*FileCloseFileById)(FileContainer *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len, uint16_t flags);
    int (*FileAppendDataById)(FileContainer *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len);
    int (*FileAppendGAPById)(FileContainer *, uint32_t track_id,
            const uint8_t *data, uint32_t data_len);
    void (*FileContainerRecycle)(FileContainer *ffc);
    void (*FilePrune)(FileContainer *ffc);
    void (*FileSetTx)(FileContainer *, uint64_t);

} SuricataContext;

extern SuricataContext suricata_context;

typedef struct SuricataFileContext_ {

    const StreamingBufferConfig *sbcfg;

} SuricataFileContext;

SuricataContext *SCGetContext(void);

#endif /* !__RUST_CONTEXT_H__ */
