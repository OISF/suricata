/* Copyright (c) 2009,2010 Open Information Security Foundation */

/**
 * \file
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_DCERPC_COMMON_H__
#define __APP_LAYER_DCERPC_COMMON_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

void RegisterDCERPCParsers(void);
void DCERPCParserTests(void);
void DCERPCParserRegisterTests(void);

// http://www.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06
#define REQUEST 0
#define PING    1
#define RESPONSE 2
#define FAULT   3
#define WORKING 4
#define NOCALL  5
#define REJECT  6
#define ACK     7
#define CL_CANCEL   8
#define FACK 9
#define CANCEL_ACK 10
#define BIND 11
#define BIND_ACK 12
#define BIND_NAK 13
#define ALTER_CONTEXT 14
#define ALTER_CONTEXT_RESP 15
#define SHUTDOWN 17
#define CO_CANCEL 18
#define ORPHANED 19
#if 0
typedef struct {
    uint8_t rpc_vers; /* 4 RPC protocol major version (4 LSB only)*/
    uint8_t ptype;      /* Packet type (5 LSB only) */
    uint8_t flags1;     /* Packet flags */
    uint8_t flags2;     /* Packet flags */
    uint8_t drep[3];    /* Data representation format label */
    uint8_t serial_hi;  /* High byte of serial number */
    uuid_t         object;     /* Object identifier */
    uuid_t         if_id;      /* Interface identifier */
    uuid_t         act_id;     /* Activity identifier */
    unsigned long  server_boot;/* Server boot time */
    unsigned long  if_vers;    /* Interface version */
    unsigned long  seqnum;     /* Sequence number */
    unsigned short opnum;      /* Operation number */
    unsigned short ihint;      /* Interface hint */
    unsigned short ahint;      /* Activity hint */
    unsigned short len;        /* Length of packet body */
    unsigned short fragnum;    /* Fragment number */
    unsigned small auth_proto; /* Authentication protocol identifier*/
    unsigned small serial_lo;  /* Low byte of serial number */
} dc_rpc_cl_pkt_hdr_t;
#endif

#define RESERVED_01 0x01
#define LASTFRAG 0x02
#define FRAG 0x04
#define NOFACK 0x08
#define MAYBE 0x10
#define IDEMPOTENT 0x20
#define BROADCAST 0x40
#define RESERVED_80 0x80

#define CANCEL_PENDING 0x02
#define RESERVED_04 0x04
#define RESERVED_10 0x10
#define RESERVED_20 0x20
#define RESERVED_40 0x40
#define RESERVED_80 0x80

typedef struct DCERPCHdr_ {
    uint8_t rpc_vers;       /**< 00:01 RPC version should be 5 */
    uint8_t rpc_vers_minor; /**< 01:01 minor version */
    uint8_t type;           /**< 02:01 packet type */
    uint8_t pfc_flags;      /**< 03:01 flags (see PFC_... ) */
    uint8_t packed_drep[4]; /**< 04:04 NDR data representation format label */
    uint16_t frag_length;   /**< 08:02 total length of fragment */
    uint16_t auth_length;   /**< 10:02 length of auth_value */
    uint32_t call_id;       /**< 12:04 call identifier */
} DCERPCHdr;

#define DCERPC_HDR_LEN 16

typedef struct DCERPCUuidEntry_ {
    uint16_t ctxid;
    uint16_t result;
    uint8_t uuid[16];
    uint16_t version;
    uint16_t versionminor;
    TAILQ_ENTRY(DCERPCUuidEntry_) next;
} DCERPCUuidEntry;

typedef struct DCERPCBindBindAck_ {
    uint8_t numctxitems;
    uint8_t numctxitemsleft;
    uint8_t ctxbytesprocessed;
    uint16_t ctxid;
    uint8_t uuid[16];
    uint16_t version;
    uint16_t versionminor;
    DCERPCUuidEntry *uuid_entry;
    TAILQ_HEAD(, DCERPCUuidEntry_) uuid_list;
    uint16_t secondaryaddrlen;
    uint16_t secondaryaddrlenleft;
    uint16_t result;
} DCERPCBindBindAck;

typedef struct DCERPCRequest_ {
    uint16_t opnum;
    uint8_t *stub_data;
} DCERPCRequest;


typedef struct DCERPC_ {
	DCERPCHdr dcerpchdr;
	DCERPCBindBindAck dcerpcbindbindack;
	DCERPCRequest dcerpcrequest;
	uint16_t bytesprocessed;
	uint8_t pad;
	uint8_t padleft;
} DCERPC;


/** First fragment */
#define PFC_FIRST_FRAG           0x01
/** Last fragment */
#define PFC_LAST_FRAG            0x02
/** Cancel was pending at sender */
#define PFC_PENDING_CANCEL       0x04
#define PFC_RESERVED_1           0x08
/** supports concurrent multiplexing of a single connection. */
#define PFC_CONC_MPX             0x10
/** only meaningful on `fault' packet; if true, guaranteed
 *  call did not execute. */
#define PFC_DID_NOT_EXECUTE      0x20
/** `maybe' call semantics requested */
#define PFC_MAYBE                0x40
/** if true, a non-nil object UUID was specified in the handle, and
 *  is present in the optional object field. If false, the object field
 * is omitted. */
#define PFC_OBJECT_UUID          0x80

#define REASON_NOT_SPECIFIED            0
#define TEMPORARY_CONGESTION            1
#define LOCAL_LIMIT_EXCEEDED            2
#define CALLED_PADDR_UNKNOWN            3 /* not used */
#define PROTOCOL_VERSION_NOT_SUPPORTED  4
#define DEFAULT_CONTEXT_NOT_SUPPORTED   5 /* not used */
#define USER_DATA_NOT_READABLE          6 /* not used */
#define NO_PSAP_AVAILABLE               7 /* not used */

int32_t DCERPCParser(DCERPC *dcerpc, uint8_t *input, uint32_t input_len);
void hexdump(const void *buf, size_t len);
void printUUID(char *type, DCERPCUuidEntry *uuid);

#endif /* __APP_LAYER_DCERPC_COMMON_H__ */

