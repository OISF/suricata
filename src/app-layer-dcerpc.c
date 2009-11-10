/*
 * Copyright (c) 2009 Open Information Security Foundation
 * app-layer-dcerpc.c
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */
#include "eidps-common.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

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

static int DCERPCParseBIND(void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    if (input_len) {
	switch (sstate->bytesprocessed) {
	case 16:
		/* max_xmit_frag */
		if (!(--input_len)) break;
	case 17:
		/* max_xmit_frag */
		if (!(--input_len)) break;
	case 18:
		/* max_recv_frag */
		if (!(--input_len)) break;
	case 19:
		/* max_recv_frag */
		if (!(--input_len)) break;
	case 20:
		/* assoc_group_id */
		if (!(--input_len)) break;
	case 21:
		/* assoc_group_id */
		if (!(--input_len)) break;
	case 22:
		/* assoc_group_id */
		if (!(--input_len)) break;
	case 23:
		/* assoc_group_id */
		if (!(--input_len)) break;

	}
    }
    return 0;
}

static int DCERPCParseBINDACK(void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    return 0;
}

static int DCERPCParseHeader(void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint8_t *p = input;
    //hexdump(p, input_len);
    if (input_len) {
        switch (sstate->bytesprocessed) {
            case 0:
                if (input_len >= DCERPC_HDR_LEN) {
                    //if (*p != 5) return 1;
                    //if (!(*(p + 1 ) == 0 || (*(p + 1) == 1))) return 2;
                    sstate->dcerpc.rpc_vers = *p;
                    sstate->dcerpc.rpc_vers_minor = *(p + 1);
                    sstate->dcerpc.type = *(p + 2);
                    sstate->dcerpc.pfc_flags = *(p + 3);
                    sstate->dcerpc.packed_drep[0] = *(p + 4);
                    sstate->dcerpc.packed_drep[1] = *(p + 5);
                    sstate->dcerpc.packed_drep[2] = *(p + 6);
                    sstate->dcerpc.packed_drep[3] = *(p + 7);
                    sstate->dcerpc.frag_length = *(p + 8) << 8;
                    sstate->dcerpc.frag_length |= *(p + 9);
                    sstate->dcerpc.auth_length = *(p + 10) << 8;
                    sstate->dcerpc.auth_length |= *(p + 11);
                    sstate->dcerpc.call_id = *(p + 12) << 24;
                    sstate->dcerpc.call_id |= *(p + 13) << 16;
                    sstate->dcerpc.call_id |= *(p + 14) << 8;
                    sstate->dcerpc.call_id |= *(p + 15);
		    sstate->bytesprocessed = 16;
                    return 1;
                    break;
                } else {
		    sstate->dcerpc.rpc_vers = *(p++);
                   // if (sstate->dcerpc.rpc_vers != 5) return 2;
                    if (!(--input_len)) break;
                }
            case 1:
                sstate->dcerpc.rpc_vers_minor = *(p++);
                if ((sstate->dcerpc.rpc_vers_minor != 0) ||
                 (sstate->dcerpc.rpc_vers_minor != 1)) return 3;
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
                printf("Odd\n");
                return 8;
        }
    }
    sstate->bytesprocessed += (p - input);
    return 0;
}

static int DCERPCParse(void *dcerpc_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
   // DCERPCState *sstate = (DCERPCState *)dcerpc_state;
    uint16_t max_fields = 3;
    uint16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {
        printf("DCERPCParse: u %" PRIu32 "\n", u);
        switch(u) {
            case 0:
                {
                    int r = AlpParseFieldBySize(output, pstate, DCERPC_PARSE_DCERPC_HEADER, DCERPC_HDR_LEN, input, input_len, &offset);

                    if (r == 0) {
                        pstate->parse_field = 0;
                        return 0;
                    }
                    break;
                }
        }
    }



    pstate->parse_field = 0;
    pstate->flags |= APP_LAYER_PARSER_DONE;

    return 1;
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
    Flow f;
    uint8_t dcerpcbuf[] = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"
    "\x00\x00\x00\x00\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
    "\x01\x00\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57"
    "\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
    "\x48\x60\x02\x00\x00\x00";

    uint32_t dcerpclen = sizeof(dcerpcbuf) - 1;
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

end:
    return result;
}

void DCERPCParserRegisterTests(void) {
    printf("DCERPCParserRegisterTests\n");
    UtRegisterTest("DCERPCParserTest01", DCERPCParserTest01, 1);
}
#endif

