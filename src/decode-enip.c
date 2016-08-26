/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * Decode EtherNet/IP
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"
#include "pkt-var.h"
#include "util-profiling.h"
#include "decode-enip.h"


/**
 * EtherNet/IP decoding entry point,  decode the Encapsulation Header
 */
int DecodeENIP(Packet *p, ENIP_DATA *enip_data)
{
	int ret = 1;

	if ((p->payload == NULL) || (p->payload_len == 0))
	{
		SCLogDebug("DecodeENIP: no data in packet\n");
		return 0;
	}

	if (p->payload_len < sizeof(ENIP_ENCAP_HEADER))
	{
		SCLogDebug("DecodeENIP: Malformed ENIP packet\n");
		return 0;
	}

	uint16_t offset = 0; //byte offset

	//Decode Encapsulation Header
	uint16_t cmd;
	uint16_t len;
	uint32_t session;
	uint32_t status;
	uint64_t context;
	uint32_t option;
	ENIPExtractUint16(&cmd, p->payload, &offset);
	ENIPExtractUint16(&len, p->payload, &offset);
	ENIPExtractUint32(&session, p->payload, &offset);
	ENIPExtractUint32(&status, p->payload, &offset);
	ENIPExtractUint64(&context, p->payload, &offset);
	ENIPExtractUint32(&option, p->payload, &offset);

	enip_data->header.command = cmd;
	enip_data->header.length = len;
	enip_data->header.session = session;
	enip_data->header.status = status;
	enip_data->header.context = context;
	enip_data->header.option = option;


	switch (enip_data->header.command)
	{
		case NOP:
			SCLogDebug("DecodeENIP - NOP\n");
			break;
		case LIST_SERVICES:
			SCLogDebug("DecodeENIP - LIST_SERVICES\n");
			break;
		case LIST_IDENTITY:
			SCLogDebug("DecodeENIP - LIST_IDENTITY\n");
			break;
		case LIST_INTERFACES:
			SCLogDebug("DecodeENIP - LIST_INTERFACES\n");
			break;
		case REGISTER_SESSION:
			SCLogDebug("DecodeENIP - REGISTER_SESSION\n");
			break;
		case UNREGISTER_SESSION:
			SCLogDebug("DecodeENIP - UNREGISTER_SESSION\n");
			break;
		case SEND_RR_DATA:
			SCLogDebug("DecodeENIP - SEND_RR_DATA - parse Common Packet Format\n");
			ret = DecodeCommonPacketFormat(p, enip_data, offset);
			break;
		case SEND_UNIT_DATA:
			SCLogDebug("DecodeENIP - SEND UNIT DATA - parse Common Packet Format\n");
			ret = DecodeCommonPacketFormat(p, enip_data, offset);
			break;
		case INDICATE_STATUS:
			SCLogDebug("DecodeENIP - INDICATE_STATUS\n");
			break;
		case CANCEL:
			SCLogDebug("DecodeENIP - CANCEL\n");
			break;
		default:
			SCLogDebug("DecodeENIP - UNSUPPORTED COMMAND 0x%x\n",
					enip_data->header.command);
	}

	return ret;
}


/**
 * Decode the Common Packet Format
 */
int DecodeCommonPacketFormat(Packet *p, ENIP_DATA *enip_data, uint16_t offset)
{
	int ret = 1;


	if (enip_data->header.length < sizeof(ENIP_ENCAP_DATA_HEADER))
	{
		SCLogDebug("DecodeCommonPacketFormat: Malformed ENIP packet\n");
		return 0;
	}

	uint32_t handle;
	uint16_t timeout;
	uint16_t count;
	ENIPExtractUint32(&handle, p->payload, &offset);
	ENIPExtractUint16(&timeout, p->payload, &offset);
	ENIPExtractUint16(&count, p->payload, &offset);

	enip_data->encap_data_header.interface_handle = handle;
	enip_data->encap_data_header.timeout = timeout;
	enip_data->encap_data_header.item_count = count;

	uint16_t address_type;
	uint16_t address_length; //length of connection id in bytes
	uint32_t address_connectionid = 0;
	uint32_t address_sequence = 0;

	ENIPExtractUint16(&address_type, p->payload, &offset);
	ENIPExtractUint16(&address_length, p->payload, &offset);

	//depending on addr type, get connection id, sequence if needed.  Can also use addr length too?
	if (address_type == CONNECTION_BASED)
	{ //get 4 byte connection id
			ENIPExtractUint32(&address_connectionid, p->payload, &offset);
	} else if (address_type == SEQUENCE_ADDR_ITEM) { // get 4 byte connection id and 4 byte sequence
			ENIPExtractUint32(&address_connectionid, p->payload, &offset);
			ENIPExtractUint32(&address_sequence, p->payload, &offset);
	}

	enip_data->encap_addr_item.type = address_type;
	enip_data->encap_addr_item.length = address_length;
	enip_data->encap_addr_item.conn_id = address_connectionid;
	enip_data->encap_addr_item.sequence_num = address_sequence;

	uint16_t data_type;
	uint16_t data_length; //length of data in bytes
	uint16_t data_sequence_count;

	ENIPExtractUint16(&data_type, p->payload, &offset);
	ENIPExtractUint16(&data_length, p->payload, &offset);

	enip_data->encap_data_item.type = data_type;
	enip_data->encap_data_item.length = data_length;

	if (enip_data->encap_data_item.type == CONNECTED_DATA_ITEM)
	{ //connected data items have seq number
		ENIPExtractUint16(&data_sequence_count, p->payload, &offset);
		enip_data->encap_data_item.sequence_count = data_sequence_count;
	}

	switch (enip_data->encap_data_item.type)
	{
		case CONNECTED_DATA_ITEM:
			SCLogDebug("DecodeCommonPacketFormat - CONNECTED DATA ITEM - parse CIP\n");
			ret = DecodeCIP(p, enip_data, offset);
			break;
		case UNCONNECTED_DATA_ITEM:
			SCLogDebug("DecodeCommonPacketFormat - UNCONNECTED DATA ITEM\n");
			ret = DecodeCIP(p, enip_data, offset);
			break;
		default:
			SCLogDebug("DecodeCommonPacketFormat - UNKNOWN TYPE 0x%x\n\n",
					enip_data->encap_data_item.type);
			return 0;
	}

	return ret;

}


#ifdef UNITTESTS
/** ENIPTestMatch
 *  \brief Valid CIP packet
 *  \retval 1 Packet match signature
 */

int ENIPTestMatch(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
                      uint32_t sid)
{
    int result = 0;
    FlowInitConfig(FLOW_QUIET);
    Packet *p = UTHBuildPacketFromEth(raw_eth_pkt, pktsize);
    result = UTHPacketMatchSig(p, sig);
    PACKET_RECYCLE(p);
    FlowShutdown();
    return result;
}


static int DecodeENIPTest01 (void)
{
    /* List Identity */
    uint8_t raw_eth_pkt[] = {
    		0x00, 0x0f, 0x73, 0x02, 0xfd, 0xa8, 0x00, 0xe0,
    		0xed, 0x0d, 0x1e, 0xe4, 0x08, 0x00, 0x45, 0x00,
    		0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0xff, 0x11,
    		0x37, 0x68, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
    		0x01, 0xff, 0xaf, 0x12, 0xaf, 0x12, 0x00, 0x20,
    		0xba, 0x37, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00,
    		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    		0x00, 0x00
    };

    char *sig = "alert udp any any -> any any (msg:\"Nothing..\"; enip_command:99; sid:1;)";

    return ENIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}
#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeENIPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeENIPTest01", DecodeENIPTest01, 1);
#endif /* UNITTESTS */
}
/**
 * @}
 */
