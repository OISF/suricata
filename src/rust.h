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

#ifndef __RUST_H__
#define __RUST_H__

#include "detect-engine-state.h" //DetectEngineState
#include "app-layer-krb5.h" //KRB5State, KRB5Transaction
#include "app-layer-ikev2.h" //IKEV2State, IKEV2Transaction
#include "app-layer-ntp.h" //NTPState, NTPTransaction
#include "app-layer-snmp.h" //SNMPState, SNMPTransaction
#include "app-layer-tftp.h" //TFTPState, TFTPTransaction

/* If we don't have Lua, create a typedef for lua_State so the
 * exported Lua functions don't fail the build. */
#ifndef HAVE_LUA
typedef void lua_State;
#endif

typedef struct SuricataContext_ {
    SCError (*SCLogMessage)(const SCLogLevel, const char *, const unsigned int,
            const char *, const SCError, const char *message);
    void (*DetectEngineStateFree)(DetectEngineState *);
    void (*AppLayerDecoderEventsSetEventRaw)(AppLayerDecoderEvents **,
            uint8_t);
    void (*AppLayerDecoderEventsFreeEvents)(AppLayerDecoderEvents **);

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

typedef struct SuricataFileContext_ {

    const StreamingBufferConfig *sbcfg;

} SuricataFileContext;

struct _Store;
typedef struct _Store Store;

/** Opaque Rust types. */

#endif /* !__RUST_H__ */
