/*
 * Copyright (c) 2009 Open Information Security Foundation
 * app-layer-dcerpc.c
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */
#include "suricata-common.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-debug.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-binsearch.h"
#include "util-unittest.h"

#include "app-layer-dcerpc.h"


enum {
	DCERPC_FIELD_NONE = 0,
    DCERPC_PARSE_DCERPC_HEADER,
    DCERPC_PARSE_DCERPC_BIND,
    DCERPC_PARSE_DCERPC_BIND_ACK,
    DCERPC_PARSE_DCERPC_REQUEST,
	/* must be last */
	DCERPC_FIELD_MAX,
};

static int DCERPCParseCTXItem(Flow *f, void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SCEnter();
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;

    if (input_len) {
        if (sstate->item == NULL) {
            sstate->item = (struct entry *) malloc(sizeof(struct entry));
            if (sstate->item == NULL) {
                SCReturnInt(-1);
            }
        }

        switch(sstate->ctxbytesprocessed) {
            case 0:
                sstate->item->ctxid = *(p++);
                if (!(--input_len)) break;
            case 1:
                sstate->item->ctxid |= *(p++) << 8;
                if (!(--input_len)) break;
            case 2:
                /* num transact items */
                p++;
                if (!(--input_len)) break;
            case 3:
                /* reserved */
                p++;
                if (!(--input_len)) break;
            case 4:
                sstate->item->uuid[3] = *(p++);
                if (!(--input_len)) break;
            case 5:
                sstate->item->uuid[2] = *(p++);
                if (!(--input_len)) break;
            case 6:
                sstate->item->uuid[1] = *(p++);
                if (!(--input_len)) break;
            case 7:
                sstate->item->uuid[0] = *(p++);
                if (!(--input_len)) break;
            case 8:
                sstate->item->uuid[5] = *(p++);
                if (!(--input_len)) break;
            case 9:
                sstate->item->uuid[4] = *(p++);
                if (!(--input_len)) break;
            case 10:
                sstate->item->uuid[7] = *(p++);
                if (!(--input_len)) break;
            case 11:
                sstate->item->uuid[6] = *(p++);
                if (!(--input_len)) break;
            case 12:
                sstate->item->uuid[8] = *(p++);
                if (!(--input_len)) break;
            case 13:
                sstate->item->uuid[9] = *(p++);
                if (!(--input_len)) break;
            case 14:
                sstate->item->uuid[10] = *(p++);
                if (!(--input_len)) break;
            case 15:
                sstate->item->uuid[11] = *(p++);
                if (!(--input_len)) break;
            case 16:
                sstate->item->uuid[12] = *(p++);
                if (!(--input_len)) break;
            case 17:
                sstate->item->uuid[13] = *(p++);
                if (!(--input_len)) break;
            case 18:
                sstate->item->uuid[14] = *(p++);
                if (!(--input_len)) break;
            case 19:
                sstate->item->uuid[15] = *(p++);
#if 0
                int i = 0;
                for (i = 0; i < 16; i++) {
                    printf("%02x", sstate->item->uuid[i]);
                }
                printf("\n");
#endif
                //     TAILQ_INSERT_TAIL(&sstate->head, sstate->item, entries);
                if (!(--input_len)) break;
            case 20:
                p++;
                if (!(--input_len)) break;
            case 21:
                p++;
                if (!(--input_len)) break;
            case 22:
                p++;
                if (!(--input_len)) break;
            case 23:
                p++;
                if (!(--input_len)) break;
            case 24:
                p++;
                if (!(--input_len)) break;
            case 25:
                p++;
                if (!(--input_len)) break;
            case 26:
                p++;
                if (!(--input_len)) break;
            case 27:
                p++;
                if (!(--input_len)) break;
            case 28:
                p++;
                if (!(--input_len)) break;
            case 29:
                p++;
                if (!(--input_len)) break;
            case 30:
                p++;
                if (!(--input_len)) break;
            case 31:
                p++;
                if (!(--input_len)) break;
            case 32:
                p++;
                if (!(--input_len)) break;
            case 33:
                p++;
                if (!(--input_len)) break;
            case 34:
                p++;
                if (!(--input_len)) break;
            case 35:
                p++;
                if (!(--input_len)) break;
            case 36:
                p++;
                if (!(--input_len)) break;
            case 37:
                p++;
                if (!(--input_len)) break;
            case 38:
                p++;
                if (!(--input_len)) break;
            case 39:
                p++;
                if (!(--input_len)) break;
            case 40:
                p++;
                if (!(--input_len)) break;
            case 41:
                p++;
                if (!(--input_len)) break;
            case 42:
                p++;
                if (!(--input_len)) break;
            case 43:
                sstate->numctxitems--;
                p++;
                --input_len;
                break;
        }
    }
    sstate->ctxbytesprocessed += (p - input);
    sstate->bytesprocessed += (p - input);
    SCReturnInt(p - input);
}

static int DCERPCParseBIND(Flow *f, void *dcerpc_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SCEnter();
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    if (input_len) {
        switch (sstate->bytesprocessed) {
            case 16:
                sstate->numctxitems = 0;
                if (input_len >= 12) {
                    sstate->numctxitems = *(p+8);
                    sstate->bytesprocessed += 12;
                    SCReturnInt(12);
                } else {
                    /* max_xmit_frag */
                    p++;
                    if (!(--input_len)) break;
                }
            case 17:
                /* max_xmit_frag */
                p++;
                if (!(--input_len)) break;
            case 18:
                /* max_recv_frag */
                p++;
                if (!(--input_len)) break;
            case 19:
                /* max_recv_frag */
                p++;
                if (!(--input_len)) break;
            case 20:
                /* assoc_group_id */
                p++;
                if (!(--input_len)) break;
            case 21:
                /* assoc_group_id */
                p++;
                if (!(--input_len)) break;
            case 22:
                /* assoc_group_id */
                p++;
                if (!(--input_len)) break;
            case 23:
                /* assoc_group_id */
                p++;
                if (!(--input_len)) break;
            case 24:
                sstate->numctxitems = *(p++);
                //printf("numctxitems %d\n",sstate->numctxitems);
                //TAILQ_INIT(sstate.head);
                if (!(--input_len)) break;
            case 25:
                /* pad byte 1 */
                p++;
                if (!(--input_len)) break;
            case 26:
                /* pad byte 2 */
                p++;
                if (!(--input_len)) break;
            case 27:
                /* pad byte 3 */
                p++;
                --input_len;
                break;
        }
    }
    sstate->bytesprocessed += (p - input);
    SCReturnInt(p - input);
}

static int DCERPCParseBINDACK(Flow *f, void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SCEnter();
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    switch(sstate->bytesprocessed) {
        case 16:
            sstate->secondaryaddrlen = *(p++) << 8;
            if (!(--input_len)) break;
        case 17:
            sstate->secondaryaddrlen |= *(p++);
            --input_len;
            break;
    }

    if (sstate->bytesprocessed > 17) { /* WRONG FOR NOW */

        while (sstate->secondaryaddrlen && input_len) {
            p++;
            sstate->secondaryaddrlen--;
            --input_len;
        }
        if (sstate->secondaryaddrlen == 0) {

        }
        /* for padding we need to do bytesprocessed % 4 */
    }
    sstate->bytesprocessed += (p - input);
    SCReturnInt(p - input);
}

static int DCERPCParseHeader(Flow *f, void *dcerpc_state, AppLayerParserState
                            *pstate, uint8_t *input, uint32_t input_len,
                            AppLayerParserResult *output) {
    SCEnter();

    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    if (input_len) {
        switch (sstate->bytesprocessed) {
            case 0:
                if (input_len >= DCERPC_HDR_LEN) {
                    //if (*p != 5) SCReturnInt(1);
                    //if (!(*(p + 1 ) == 0 || (*(p + 1) == 1))) SCReturnInt(2);
                    sstate->dcerpc.rpc_vers = *p;
                    sstate->dcerpc.rpc_vers_minor = *(p + 1);
                    sstate->dcerpc.type = *(p + 2);
                    sstate->dcerpc.pfc_flags = *(p + 3);
                    sstate->dcerpc.packed_drep[0] = *(p + 4);
                    sstate->dcerpc.packed_drep[1] = *(p + 5);
                    sstate->dcerpc.packed_drep[2] = *(p + 6);
                    sstate->dcerpc.packed_drep[3] = *(p + 7);
                    if (sstate->dcerpc.packed_drep[0] == 0x10) {
                    sstate->dcerpc.frag_length = *(p + 8);
                    sstate->dcerpc.frag_length |= *(p + 9) << 8;
                    sstate->dcerpc.auth_length = *(p + 10);
                    sstate->dcerpc.auth_length |= *(p + 11) << 8;
                    } else {
                    sstate->dcerpc.frag_length = *(p + 8) << 8;
                    sstate->dcerpc.frag_length |= *(p + 9);
                    sstate->dcerpc.auth_length = *(p + 10) << 8;
                    sstate->dcerpc.auth_length |= *(p + 11);
                    }
                    sstate->dcerpc.call_id = *(p + 12) << 24;
                    sstate->dcerpc.call_id |= *(p + 13) << 16;
                    sstate->dcerpc.call_id |= *(p + 14) << 8;
                    sstate->dcerpc.call_id |= *(p + 15);
                    sstate->bytesprocessed = DCERPC_HDR_LEN;
                    SCReturnInt(DCERPC_HDR_LEN);
                    break;
                } else {
                    sstate->dcerpc.rpc_vers = *(p++);
                    // if (sstate->dcerpc.rpc_vers != 5) SCReturnInt(2);
                    if (!(--input_len)) break;
                }
            case 1:
                sstate->dcerpc.rpc_vers_minor = *(p++);
                if ((sstate->dcerpc.rpc_vers_minor != 0) ||
                        (sstate->dcerpc.rpc_vers_minor != 1)) SCReturnInt(3);
                if (!(--input_len)) break;
            case 2:
                sstate->dcerpc.type = *(p++);
                if (!(--input_len)) break;
            case 3:
                sstate->dcerpc.pfc_flags = *(p++);
                if (!(--input_len)) break;
            case 4:
                sstate->dcerpc.packed_drep[0] = *(p++);
                if (!(--input_len)) break;
            case 5:
                sstate->dcerpc.packed_drep[1] = *(p++);
                if (!(--input_len)) break;
            case 6:
                sstate->dcerpc.packed_drep[2] = *(p++);
                if (!(--input_len)) break;
            case 7:
                sstate->dcerpc.packed_drep[3] = *(p++);
                if (!(--input_len)) break;
            case 8:
                sstate->dcerpc.frag_length = *(p++) << 8;
                if (!(--input_len)) break;
            case 9:
                sstate->dcerpc.frag_length |= *(p++);
                if (!(--input_len)) break;
            case 10:
                sstate->dcerpc.auth_length = *(p++) << 8;
                if (!(--input_len)) break;
            case 11:
                sstate->dcerpc.auth_length |= *(p++);
                if (!(--input_len)) break;
            case 12:
                sstate->dcerpc.call_id = *(p++) << 24;
                if (!(--input_len)) break;
            case 13:
                sstate->dcerpc.call_id |= *(p++) << 16;
                if (!(--input_len)) break;
            case 14:
                sstate->dcerpc.call_id |= *(p++) << 8;
                if (!(--input_len)) break;
            case 15:
                sstate->dcerpc.call_id |= *(p++);
                --input_len;
                break;
            default: // SHOULD NEVER OCCUR
                SCLogDebug("Odd");
                SCReturnInt(8);
        }
    }
    sstate->bytesprocessed += (p - input);
    SCReturnInt(p - input);
}

static int DCERPCParse(Flow *f, void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SCEnter();

    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint32_t retval = 0;
    uint32_t parsed = 0;

    if (pstate == NULL)
        SCReturnInt(-1);

    while (sstate->bytesprocessed <  DCERPC_HDR_LEN && input_len) {
        retval = DCERPCParseHeader(f, dcerpc_state, pstate, input, input_len,
                output);
        parsed += retval;
        input_len -= retval;
    }

    switch (sstate->dcerpc.type) {
        case BIND:
        case ALTER_CONTEXT:
            while (sstate->bytesprocessed <  DCERPC_HDR_LEN + 12 &&
                    sstate->bytesprocessed < sstate->dcerpc.frag_length &&
                    input_len) {
                retval = DCERPCParseBIND(f, dcerpc_state, pstate, input + parsed, input_len,
                        output);
                parsed += retval;
                input_len -= retval;
            }
            while (sstate->numctxitems && sstate->bytesprocessed < sstate->dcerpc.frag_length &&
                    input_len) {
                retval = DCERPCParseCTXItem(f, dcerpc_state, pstate, input + parsed, input_len,
                        output);
                if (sstate->ctxbytesprocessed == 44) {
                    sstate->ctxbytesprocessed = 0;
                }
                parsed += retval;
                input_len -= retval;
            }
            break;
        case BIND_ACK:
        case ALTER_CONTEXT_RESP:
            while (sstate->bytesprocessed <  DCERPC_HDR_LEN + 12 && input_len) {
                retval = DCERPCParseBINDACK(f, dcerpc_state, pstate, input + parsed, input_len,
                        output);
                parsed += retval;
                input_len -= retval;
            }
            while (sstate->numctxitems && input_len) {
                retval = DCERPCParseCTXItem(f, dcerpc_state, pstate, input, input_len,
                        output);
                parsed += retval;
                input_len -= retval;
            }
            break;
    }
    pstate->parse_field = 0;
    pstate->flags |= APP_LAYER_PARSER_DONE;

    SCReturnInt(1);
}


static void *DCERPCStateAlloc(void) {
	void *s = malloc(sizeof(DCERPCState));
	if (s == NULL)
		return NULL;

	memset(s, 0, sizeof(DCERPCState));
	return s;
}

static void DCERPCStateFree(void *s) {
	if (s) {
		free(s);
		s = NULL;
	}
}

void RegisterDCERPCParsers(void) {
	AppLayerRegisterProto("dcerpc", ALPROTO_DCERPC, STREAM_TOSERVER, DCERPCParse);
	AppLayerRegisterProto("dcerpc", ALPROTO_DCERPC, STREAM_TOCLIENT, DCERPCParse);
	AppLayerRegisterParser("dcerpc.hdr", ALPROTO_DCERPC, DCERPC_PARSE_DCERPC_HEADER, DCERPCParseHeader, "dcerpc");
	AppLayerRegisterStateFuncs(ALPROTO_DCERPC, DCERPCStateAlloc, DCERPCStateFree);
}

/* UNITTESTS */
#ifdef UNITTESTS


int DCERPCParserTest01(void) {
    int result = 1;
//    uint8_t i = 0;
//    struct entry *item;

    Flow f;
    uint8_t dcerpcbuf[] = {
    0x05, 0x00,
    0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x3c, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x16,
    0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x32, 0x71,
    0xab, 0xa1, 0xc1, 0x2b, 0x7a, 0xda, 0xe9, 0x28,
    0xa9, 0x6c, 0x26, 0x75, 0xee, 0x33, 0x03, 0x00,
    0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x00, 0xeb, 0xb6, 0xaf, 0xaa, 0x87, 0x53,
    0x0c, 0x1b, 0x1d, 0xfa, 0x90, 0x9f, 0x04, 0x6c,
    0x9e, 0x37, 0x04, 0x00, 0x00, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0xcc, 0xd0,
    0x96, 0x50, 0xfe, 0xc5, 0x62, 0x41, 0xf2, 0x66,
    0x9e, 0x35, 0x93, 0xb3, 0xa3, 0x36, 0x06, 0x00,
    0x02, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x01, 0x00, 0xf7, 0x3c, 0x42, 0x42, 0x32, 0xe5,
    0x0a, 0x2d, 0x81, 0xf3, 0x9f, 0x77, 0x57, 0x82,
    0xe5, 0x66, 0x02, 0x00, 0x02, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x8d, 0xe3,
    0x3d, 0x0b, 0xe5, 0xd0, 0x91, 0x5e, 0x83, 0xe2,
    0xec, 0x91, 0x66, 0x20, 0x1c, 0xd4, 0x04, 0x00,
    0x02, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00,
    0x01, 0x00, 0x0e, 0xb9, 0xaa, 0x41, 0x6e, 0xb3,
    0x2b, 0xb1, 0x8b, 0xbd, 0x6b, 0xdc, 0xe7, 0xe2,
    0x4c, 0x91, 0x05, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0xfc, 0xae,
    0x72, 0xe2, 0x91, 0x76, 0x38, 0xf4, 0x96, 0x6c,
    0xdf, 0x70, 0x15, 0x97, 0x19, 0x5f, 0x06, 0x00,
    0x02, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00,
    0x01, 0x00, 0x67, 0x75, 0xe4, 0xca, 0x4b, 0xda,
    0xaf, 0x28, 0xf4, 0x4b, 0x85, 0xbd, 0xe6, 0xf5,
    0xaa, 0xb1, 0x04, 0x00, 0x00, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x60, 0xc5,
    0xc8, 0x81, 0x00, 0x24, 0x7b, 0xbc, 0xb1, 0xcc,
    0xb1, 0x72, 0xc4, 0xef, 0x8d, 0x4f, 0x02, 0x00,
    0x01, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00,
    0x01, 0x00, 0x11, 0x64, 0x1b, 0x63, 0x52, 0x04,
    0x44, 0xce, 0xa5, 0xec, 0x2c, 0xd8, 0x5e, 0xab,
    0xaf, 0x4c, 0x04, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0xec, 0xd9,
    0xa8, 0x20, 0xb5, 0xf9, 0xc6, 0xf4, 0x8b, 0x94,
    0x14, 0x33, 0xed, 0xc2, 0xcd, 0x22, 0x02, 0x00,
    0x01, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x01, 0x00, 0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1,
    0xd0, 0x11, 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9,
    0x2e, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0xf9, 0x25,
    0xf3, 0xf0, 0xc6, 0x9a, 0xd8, 0x0a, 0xb9, 0xe8,
    0x9b, 0xb3, 0xc6, 0x2a, 0xfc, 0x24, 0x06, 0x00,
    0x03, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x01, 0x00, 0xf3, 0x69, 0xcf, 0x88, 0xcc, 0xa9,
    0x2d, 0xd8, 0x29, 0x2b, 0x58, 0xcb, 0x13, 0x7b,
    0x9b, 0x29, 0x05, 0x00, 0x02, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x0e, 0x00, 0x01, 0x00, 0xe0, 0x5c,
    0xe6, 0x34, 0x98, 0xd1, 0xf0, 0x9f, 0x12, 0x03,
    0x65, 0xed, 0x20, 0x1b, 0x77, 0x12, 0x04, 0x00,
    0x02, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x00,
    0x01, 0x00, 0x12, 0xdb, 0xd3, 0x66, 0x28, 0xd0,
    0xe3, 0x60, 0x5c, 0x87, 0x55, 0xb2, 0xeb, 0xc6,
    0x27, 0x20, 0x01, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x8b, 0x56,
    0x01, 0xdc, 0x51, 0xc9, 0x42, 0x52, 0x27, 0x39,
    0xd7, 0x91, 0x05, 0x39, 0xc9, 0x7c, 0x06, 0x00,
    0x01, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x11, 0x00,
    0x01, 0x00, 0x6f, 0x31, 0xd2, 0x9e, 0x0b, 0x53,
    0xf3, 0x3e, 0xdb, 0x5c, 0xd9, 0xc2, 0x4e, 0xa2,
    0x5b, 0x77, 0x04, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0xfd, 0xf8,
    0x7c, 0xb9, 0xca, 0x86, 0xa8, 0xa9, 0x9a, 0x6d,
    0xe8, 0x61, 0x99, 0xbf, 0x66, 0x10, 0x04, 0x00,
    0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x13, 0x00,
    0x01, 0x00, 0xbe, 0x4e, 0x22, 0x46, 0x15, 0x56,
    0xb8, 0xaa, 0x0c, 0x3c, 0xbd, 0x64, 0x0e, 0x95,
    0x3b, 0xe4, 0x05, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0xcc, 0x35,
    0x9e, 0xa9, 0x0b, 0xb7, 0xcd, 0x00, 0x26, 0x6b,
    0xb5, 0xd6, 0x97, 0x25, 0x77, 0x60, 0x02, 0x00,
    0x01, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x15, 0x00,
    0x01, 0x00, 0xff, 0x18, 0x1a, 0x22, 0xcd, 0x5f,
    0xa2, 0x28, 0x63, 0x8c, 0x77, 0x5f, 0x70, 0xcb,
    0x27, 0x49, 0x06, 0x00, 0x01, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x16, 0x00, 0x01, 0x00, 0x93, 0x0d,
    0xd6, 0x59, 0xd8, 0xb7, 0xed, 0x1c, 0x0d, 0x2e,
    0x3b, 0x40, 0xd2, 0x52, 0x88, 0x7c, 0x01, 0x00,
    0x03, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x17, 0x00,
    0x01, 0x00, 0x53, 0x15, 0xa6, 0x63, 0x96, 0x75,
    0x42, 0x46, 0xac, 0x21, 0x7b, 0x37, 0xcb, 0xac,
    0x3f, 0x86, 0x02, 0x00, 0x00, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00 };
    uint32_t dcerpclen = sizeof(dcerpcbuf);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER|STREAM_EOF, dcerpcbuf, dcerpclen, FALSE);
    if (r != 0) {
        printf("dcerpc header check returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

//    printf("dcerpcbuf size %u\n", dcerpclen);
    DCERPCState *dcerpc_state = ssn.aldata[AlpGetStateIdx(ALPROTO_DCERPC)];
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        result = 0;
        goto end;
    }

    if (dcerpc_state->dcerpc.rpc_vers != 5) {
        printf("expected dcerpc version 0x05, got 0x%02x : ",
        dcerpc_state->dcerpc.rpc_vers);
        result = 0;
        goto end;
    }

    if (dcerpc_state->dcerpc.type != BIND) {
       printf("expected dcerpc type 0x%02x , got 0x%02x : ", BIND, dcerpc_state->dcerpc.type);
       result = 0;
       goto end;
    }

    if (dcerpc_state->dcerpc.frag_length != 1084) {
       printf("expected dcerpc frag_length 0x%02x , got 0x%02x : ", 1084, dcerpc_state->dcerpc.frag_length);
       result = 0;
       goto end;
    }
#if 0
    printf("UUID:\n");
    TAILQ_FOREACH(item, &dcerpc_state->head, entries) {
        printf("CTX Item %d\n", item->ctxid);
        for (i = 0; i < 16; i++) {
            printf("%02x", item->uuid[i]);
        }
        printf("\n");
    }
#endif
end:
    return result;
}

void DCERPCParserRegisterTests(void) {
    printf("DCERPCParserRegisterTests\n");
    UtRegisterTest("DCERPCParserTest01", DCERPCParserTest01, 1);
}
#endif

