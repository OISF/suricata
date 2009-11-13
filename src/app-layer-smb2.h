/*
 * Copyright (c) 2009 Open Information Security Foundation
 * app-layer-smb2.h
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef APPLAYERSMB2_H_
#define APPLAYERSMB2_H_
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-nbss.h"
#include "flow.h"
#include "stream.h"
#include <stdint.h>

typedef struct smb2_hdr {
	uint32_t Protocol; // Contains 0xFE,'SMB'
	uint16_t StructureSize;
	uint16_t CreditCharge;
	uint32_t Status;
	uint16_t Command;
	uint16_t CreditRequestResponse;
	uint32_t Flags;
	uint32_t NextCommand;
	uint64_t MessageId;
	uint32_t ProcessId;
	uint32_t TreeId;
	uint64_t SessionId;
	uint8_t Signature[16];
}smb2_hdr_t, *psmb2_hdr_t;

#define SMB2_HDR_LEN 64

typedef struct SMB2State_ {
	nbss_hdr_t nbss;
	smb2_hdr_t smb2;
	uint16_t bytesprocessed;
}SMB2State;

/* http://msdn.microsoft.com/en-us/library/cc246528(PROT.13).aspx */
#define SMB2_NEGOTIATE	 0x0000
#define SMB2_SESSION_SETUP	 0x0001
#define SMB2_LOGOFF	 0x0002
#define SMB2_TREE_CONNECT	 0x0003
#define SMB2_TREE_DISCONNECT	 0x0004
#define SMB2_CREATE	 0x0005
#define SMB2_CLOSE	 0x0006
#define SMB2_FLUSH	 0x0007
#define SMB2_READ	 0x0008
#define SMB2_WRITE	 0x0009
#define SMB2_LOCK	 0x000A
#define SMB2_IOCTL	 0x000B
#define SMB2_CANCEL	 0x000C
#define SMB2_ECHO	 0x000D
#define SMB2_QUERY_DIRECTORY	 0x000E
#define SMB2_CHANGE_NOTIFY	 0x000F
#define SMB2_QUERY_INFO	 0x0010
#define SMB2_SET_INFO	 0x0011
#define SMB2_OPLOCK_BREAK	 0x0012

void RegisterSMB2Parsers(void);
void SMB2ParserRegisterTests(void);


#endif /* APPLAYERSMB2_H_ */
