/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_SMB2_H__
#define __APP_LAYER_SMB2_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-nbss.h"
#include "flow.h"
#include "stream.h"

typedef struct SMB2Hdr {
    uint32_t Protocol;              /**< Contains 0xFE,'SMB' */
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
} SMB2Hdr;

#define SMB2_HDR_LEN 64

typedef struct SMB2State_ {
    NBSSHdr nbss;
    SMB2Hdr smb2;
    uint16_t bytesprocessed;
} SMB2State;

/** from http://msdn.microsoft.com/en-us/library/cc246528(PROT.13).aspx */
#define SMB2_NEGOTIATE          0x0000
#define SMB2_SESSION_SETUP      0x0001
#define SMB2_LOGOFF             0x0002
#define SMB2_TREE_CONNECT       0x0003
#define SMB2_TREE_DISCONNECT    0x0004
#define SMB2_CREATE             0x0005
#define SMB2_CLOSE              0x0006
#define SMB2_FLUSH              0x0007
#define SMB2_READ               0x0008
#define SMB2_WRITE              0x0009
#define SMB2_LOCK               0x000A
#define SMB2_IOCTL              0x000B
#define SMB2_CANCEL             0x000C
#define SMB2_ECHO               0x000D
#define SMB2_QUERY_DIRECTORY    0x000E
#define SMB2_CHANGE_NOTIFY      0x000F
#define SMB2_QUERY_INFO         0x0010
#define SMB2_SET_INFO           0x0011
#define SMB2_OPLOCK_BREAK       0x0012

void RegisterSMB2Parsers(void);
void SMB2ParserRegisterTests(void);

#endif /* __APP_LAYER_SMB2_H__ */

