/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_DCERPC_H__
#define __APP_LAYER_DCERPC_H__

#include "app-layer-parser.h"

struct DCERPCState;

/*****linked list implementation*****/

/* we will think about moving it to its own file next */

struct List {
    void *head;
    void *tail;

    int index;
    int size;
};

#define ListNext void
#define ListPrev void

struct ListInterface {
    ListNext *next;
    ListPrev *prev;
};

/*****dcerpc specific*****/

enum DCERPCTxProgress {
    DCERPC_TX_IFACE = 0,
    DCERPC_TX_OPNUM,
    DCERPC_TX_STUB_BUFFERING,
    DCERPC_TX_DONE,
};

struct UUID {
    ListNext *next;
    ListPrev *prev;

    uint8_t uuid[16];
    uint32_t iv;
    uint16_t accepted;
    /* not a member of uuid, but rather related to the dcerpc context
     * associated with this iface */
    uint16_t context_id;
};

struct DCERPCTx {
    ListNext *next;
    ListPrev *prev;

    uint16_t opnum;
    struct UUID iface;
    uint32_t call_id;

    uint8_t *stub[2];
    uint16_t stub_len[2];

    /* the endianness of the pdu that was holding each stub */
    uint8_t bo[2];

    enum DCERPCTxProgress progress[2];
};

enum DCERPCStatus {
    DCERPC_OK = 0,
    DCERPC_ERROR,
    DCERPC_DATA,
    DCERPC_STOP,
};

struct DCERPCConnp {
    uint8_t rpc_vers_minor;
    uint8_t ptype;
    uint8_t pfc_flags;
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t call_id;

    /* we will need these 4 to create groups */
    uint32_t assoc_group_id;
    uint16_t p_context_id;
    uint8_t uuid[16];

    uint8_t bo;
    uint8_t in_state_progress;
    uint8_t tmp8[4];
    uint16_t tmp16[2];
    uint32_t tmp32[1];

    /* used if pdu is request/response */
    struct DCERPCTx *curr_tx;

    uint32_t pdu_bytes_processed;

    /* streaming parser context */
    void *spc;

    enum DCERPCStatus (*CurrState)(struct DCERPCState *);
};

struct DCERPCState {
    uint8_t curr_direction;
    struct DCERPCConnp connp[2];
    struct List transactions;
    struct List uuids;
};

void RegisterDCERPCParsers(void);
void DCERPCParserRegisterTests(void);

/* used by smb state */
int DCERPCParseRequest(Flow *f, void *alstate,
                      AppLayerParserState *pstate,
                      uint8_t *input, uint32_t input_len,
                      void *local_data,
                       AppLayerParserResult *output);
int DCERPCParseResponse(Flow *f, void *alstate,
                        AppLayerParserState *pstate,
                        uint8_t *input, uint32_t input_len,
                        void *local_data,
                        AppLayerParserResult *output);
void *DCERPCStateAlloc(void);
void DCERPCStateFree(void *s);

/* List Api */
int ListIndex(struct List *l);
int ListSize(struct List *l);
void ListReset(struct List *l, void Free(void *ptr));
void *ListGetAtIndex(int index, struct List *l);
void ListAppend(void *item, struct List *l);
void ListRemoveItem(void *item, struct List *l);

#endif /* __APP_LAYER_DCERPC_H__ */
