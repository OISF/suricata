/* Copyright (C) 2015 Open Information Security Foundation
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
 * App-layer parser for ENIP protocol common code
 *
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"
#include "pkt-var.h"
#include "util-profiling.h"

#include "app-layer-enip-common.h"




/**
 * \brief Extract 8 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint8(uint8_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    *res = *(input + *offset);
    *offset += sizeof(uint8_t);
    SCReturn;
}

/**
 * \brief Extract 16 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint16(uint16_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint16(res, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint16_t);
    SCReturn;
}

/**
 * \brief Extract 32 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint32(uint32_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint32(res, BYTE_LITTLE_ENDIAN, sizeof(uint32_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint32_t);
    SCReturn;
}

/**
 * \brief Extract 64 bits and move up the offset
 * @param res
 * @param input
 * @param offset
 */
void ENIPExtractUint64(uint64_t *res, uint8_t *input, uint16_t *offset)
{
    SCEnter();
    ByteExtractUint64(res, BYTE_LITTLE_ENDIAN, sizeof(uint64_t),
            (const uint8_t *) (input + *offset));
    *offset += sizeof(uint64_t);
    SCReturn;
}


/**
 * \brief Create service entry, add to transaction
 * @param tx Transaction
 * @return service entry
 */
static CIPServiceEntry *CIPServiceAlloc(ENIPTransaction *tx)
{

    CIPServiceEntry *svc = (CIPServiceEntry *) SCCalloc(1,
            sizeof(CIPServiceEntry));
    if (unlikely(svc == NULL))
        return NULL;

    memset(svc, 0x00, sizeof(CIPServiceEntry));

    TAILQ_INIT(&svc->segment_list);
    TAILQ_INIT(&svc->attrib_list);

    TAILQ_INSERT_TAIL(&tx->service_list, svc, next);
    // svc->service = 75;

    return svc;

}


/**
 * \brief Delete service entry
 */

void CIPServiceFree(void *s)
{
    SCEnter();
    if (s)
    {
        CIPServiceEntry *svc = (CIPServiceEntry *) s;

        SegmentEntry *seg = NULL;
        while ((seg = TAILQ_FIRST(&svc->segment_list)))
        {
            TAILQ_REMOVE(&svc->segment_list, seg, next);
            SCFree(seg);
        }

        AttributeEntry *attr = NULL;
        while ((attr = TAILQ_FIRST(&svc->attrib_list)))
        {
            TAILQ_REMOVE(&svc->attrib_list, attr, next);
            SCFree(attr);
        }

        SCFree(s);
    }
    SCReturn;
}



/**
 * \brief Decode ENIP Encapsulation Header
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeENIPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data)
{
    int ret = 1;

    uint16_t offset = 0; //byte offset

    //Decode Encapsulation Header
    uint16_t cmd;
    uint16_t len;
    uint32_t session;
    uint32_t status;
    uint64_t context;
    uint32_t option;
    ENIPExtractUint16(&cmd, input, &offset);
    ENIPExtractUint16(&len, input, &offset);
    ENIPExtractUint32(&session, input, &offset);
    ENIPExtractUint32(&status, input, &offset);
    ENIPExtractUint64(&context, input, &offset);
    ENIPExtractUint32(&option, input, &offset);

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
            SCLogDebug(
                    "DecodeENIP - SEND_RR_DATA - parse Common Packet Format\n");
            ret = DecodeCommonPacketFormatPDU(input, input_len, enip_data,
                    offset);
            break;
        case SEND_UNIT_DATA:
            SCLogDebug(
                    "DecodeENIP - SEND UNIT DATA - parse Common Packet Format\n");
            ret = DecodeCommonPacketFormatPDU(input, input_len, enip_data,
                    offset);
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
 * \brief Decode Common Packet Format
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCommonPacketFormatPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{

    if (enip_data->header.length < sizeof(ENIPEncapDataHdr))
    {
        SCLogDebug("DecodeCommonPacketFormat: Malformed ENIP packet\n");
        return 0;
    }

    if (offset >= (input_len - (sizeof(uint32_t) + sizeof(uint16_t)*4)))
    {
            SCLogDebug("DecodeCommonPacketFormat: Parsing beyond payload length\n");
            return 0;
    }

    uint32_t handle;
    uint16_t timeout;
    uint16_t count;
    ENIPExtractUint32(&handle, input, &offset);
    ENIPExtractUint16(&timeout, input, &offset);
    ENIPExtractUint16(&count, input, &offset);

    enip_data->encap_data_header.interface_handle = handle;
    enip_data->encap_data_header.timeout = timeout;
    enip_data->encap_data_header.item_count = count;

    uint16_t address_type;
    uint16_t address_length; //length of connection id in bytes
    uint32_t address_connectionid = 0;
    uint32_t address_sequence = 0;

    ENIPExtractUint16(&address_type, input, &offset);
    ENIPExtractUint16(&address_length, input, &offset);

    //depending on addr type, get connection id, sequence if needed.  Can also use addr length too?
    if (address_type == CONNECTION_BASED)
    { //get 4 byte connection id
	if (offset >= (input_len - sizeof(uint32_t)))
    	{
            SCLogDebug("DecodeCommonPacketFormat: Parsing beyond payload length\n");
            return 0;
	}
        ENIPExtractUint32(&address_connectionid, input, &offset);
    } else if (address_type == SEQUENCE_ADDR_ITEM)
    { // get 4 byte connection id and 4 byte sequence
	if (offset >= (input_len - sizeof(uint32_t)*2))
    	{
            SCLogDebug("DecodeCommonPacketFormat: Parsing beyond payload length\n");
            return 0;
	}
        ENIPExtractUint32(&address_connectionid, input, &offset);
        ENIPExtractUint32(&address_sequence, input, &offset);
    }

    enip_data->encap_addr_item.type = address_type;
    enip_data->encap_addr_item.length = address_length;
    enip_data->encap_addr_item.conn_id = address_connectionid;
    enip_data->encap_addr_item.sequence_num = address_sequence;

    uint16_t data_type;
    uint16_t data_length; //length of data in bytes
    uint16_t data_sequence_count;

    if (offset >= (input_len - sizeof(uint16_t)*2))
    {
        SCLogDebug("DecodeCommonPacketFormat: Parsing beyond payload length\n");
        return 0;
    }
    ENIPExtractUint16(&data_type, input, &offset);
    ENIPExtractUint16(&data_length, input, &offset);

    enip_data->encap_data_item.type = data_type;
    enip_data->encap_data_item.length = data_length;

    if (enip_data->encap_data_item.type == CONNECTED_DATA_ITEM)
    { //connected data items have seq number
        if (offset >= (input_len - sizeof(uint16_t)))
        {
            SCLogDebug("DecodeCommonPacketFormat: Parsing beyond payload length\n");
            return 0;
        }
        ENIPExtractUint16(&data_sequence_count, input, &offset);
        enip_data->encap_data_item.sequence_count = data_sequence_count;
    }

    switch (enip_data->encap_data_item.type)
    {
        case CONNECTED_DATA_ITEM:
            SCLogDebug(
                    "DecodeCommonPacketFormat - CONNECTED DATA ITEM - parse CIP\n");
            DecodeCIPPDU(input, input_len, enip_data, offset);
            break;
        case UNCONNECTED_DATA_ITEM:
            SCLogDebug("DecodeCommonPacketFormat - UNCONNECTED DATA ITEM\n");
            DecodeCIPPDU(input, input_len, enip_data, offset);
            break;
        default:
            SCLogDebug("DecodeCommonPacketFormat - UNKNOWN TYPE 0x%x\n\n",
                    enip_data->encap_data_item.type);
            return 0;
    }

    return 1;

}



/**
 * \brief Decode CIP packet
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */

int DecodeCIPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{
    int ret = 1;

    if (enip_data->encap_data_item.length == 0)
    {
        SCLogDebug("DecodeCIP: No CIP Data\n");
        return 0;
    }

    if (offset > input_len)
    {
        SCLogDebug("DecodeCIP: Parsing beyond payload length\n");
        return 0;
    }

    uint8_t service = 0;
    service = *(input + offset);

    //SCLogDebug("CIP Service 0x%x\n", service);

    //use service code first bit to determine request/response, no need to save or push offset
    if (service >> 7)
    {
        ret = DecodeCIPResponsePDU(input, input_len, enip_data, offset);
    } else
    {
        ret = DecodeCIPRequestPDU(input, input_len, enip_data, offset);
    }

    return ret;
}



/**
 * \brief Decode CIP Request
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPRequestPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{
    int ret = 1;

    if (enip_data->encap_data_item.length < sizeof(CIPReqHdr))
    {
        SCLogDebug("DecodeCIPRequest - Malformed CIP Data\n");
        return 0;
    }

    uint8_t service; //<-----CIP SERVICE
    uint8_t path_size;
    if (offset >= (input_len - sizeof(uint8_t)*2))
    {
        SCLogDebug("DecodeCIPRequest: Parsing beyond payload length\n");
        return 0;
    }
    ENIPExtractUint8(&service, input, &offset);
    ENIPExtractUint8(&path_size, input, &offset);

    if (service > MAX_CIP_SERVICE)
    { // service codes of value 0x80 or greater are not permitted because in the CIP protocol the highest order bit is used to flag request(0)/response(1)
        SCLogDebug("DecodeCIPRequest - INVALID CIP SERVICE 0x%x\n", service);
        return 0;
    }

    //save CIP data
    CIPServiceEntry *node = CIPServiceAlloc(enip_data);
    node->direction = 0;
    node->service = service;
    node->request.path_size = path_size;
    node->request.path_offset = offset;
    // SCLogDebug("DecodeCIPRequestPDU: service 0x%x size %d\n", node->service,
    //         node->request.path_size);

    DecodeCIPRequestPathPDU(input, input_len, node, offset);

    offset += path_size * sizeof(uint16_t); //move offset past pathsize

    //list of CIP services is large and can be vendor specific, store CIP service  anyways and let the rule decide the action
    switch (service)
    {
        case CIP_RESERVED:
            SCLogDebug("DecodeCIPRequest - CIP_RESERVED\n");
            break;
        case CIP_GET_ATTR_ALL:
            SCLogDebug("DecodeCIPRequest - CIP_GET_ATTR_ALL\n");
            break;
        case CIP_GET_ATTR_LIST:
            SCLogDebug("DecodeCIPRequest - CIP_GET_ATTR_LIST\n");
            break;
        case CIP_SET_ATTR_LIST:
            SCLogDebug("DecodeCIPRequest - CIP_SET_ATTR_LIST\n");
            break;
        case CIP_RESET:
            SCLogDebug("DecodeCIPRequest - CIP_RESET\n");
            break;
        case CIP_START:
            SCLogDebug("DecodeCIPRequest - CIP_START\n");
            break;
        case CIP_STOP:
            SCLogDebug("DecodeCIPRequest - CIP_STOP\n");
            break;
        case CIP_CREATE:
            SCLogDebug("DecodeCIPRequest - CIP_CREATE\n");
            break;
        case CIP_DELETE:
            SCLogDebug("DecodeCIPRequest - CIP_DELETE\n");
            break;
        case CIP_MSP:
            SCLogDebug("DecodeCIPRequest - CIP_MSP\n");
            DecodeCIPRequestMSPPDU(input, input_len, enip_data, offset);
            break;
        case CIP_APPLY_ATTR:
            SCLogDebug("DecodeCIPRequest - CIP_APPLY_ATTR\n");
            break;
        case CIP_KICK_TIMER:
            SCLogDebug("DecodeCIPRequest - CIP_KICK_TIMER\n");
            break;
        case CIP_OPEN_CONNECTION:
            SCLogDebug("DecodeCIPRequest - CIP_OPEN_CONNECTION\n");
            break;
        case CIP_CHANGE_START:
            SCLogDebug("DecodeCIPRequest - CIP_CHANGE_START\n");
            break;
        case CIP_GET_STATUS:
            SCLogDebug("DecodeCIPRequest - CIP_GET_STATUS\n");
            break;
        default:
            SCLogDebug("DecodeCIPRequest - CIP SERVICE 0x%x\n", service);
    }

    return ret;
}


/**
 * \brief Deocde CIP Request Path
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @param cipserviced the cip service rule
 * @return 1 Packet matches
 * @return 0 Packet not match
 */
int DecodeCIPRequestPathPDU(uint8_t *input, uint32_t input_len,
        CIPServiceEntry *node, uint16_t offset)
{

    //SCLogDebug("DecodeCIPRequestPath: service 0x%x size %d length %d\n",
    //        node->service, node->request.path_size, input_len);

    if (node->request.path_size < 1)
    {
        //SCLogDebug("DecodeCIPRequestPath: empty path or CIP Response\n");
        return 0;
    }

    int bytes_remain = node->request.path_size;

    uint8_t segment;
    uint8_t reserved; //unused byte reserved by ODVA

    //8 bit fields
    uint8_t req_path_class8;
    uint8_t req_path_instance8;
    uint8_t req_path_attr8;

    //16 bit fields
    uint16_t req_path_class16;
    uint16_t req_path_instance16;

    uint16_t class = 0;  

    SegmentEntry *seg = NULL;

    while (bytes_remain > 0)
    {

        ENIPExtractUint8(&segment, input, &offset);
        switch (segment)
        { //assume order is class then instance.  Can have multiple
            case PATH_CLASS_8BIT:
                ENIPExtractUint8(&req_path_class8, input, &offset);
                class = (uint16_t) req_path_class8;
                SCLogDebug("DecodeCIPRequestPath: 8bit class 0x%x\n", class);

                seg = SCMalloc(sizeof(SegmentEntry));
                if (unlikely(seg == NULL))
                    return 0;
                seg->segment = segment;
                seg->value = class;
                TAILQ_INSERT_TAIL(&node->segment_list, seg, next);

                bytes_remain--;
                break;
            case PATH_INSTANCE_8BIT:
                ENIPExtractUint8(&req_path_instance8, input, &offset);
                //skip instance, don't need to store
                bytes_remain--;
                break;
            case PATH_ATTR_8BIT: //single attribute
                ENIPExtractUint8(&req_path_attr8, input, &offset);
                //uint16_t attrib = (uint16_t) req_path_attr8;
                //SCLogDebug("DecodeCIPRequestPath: 8bit attr 0x%x\n", attrib);

                seg = SCMalloc(sizeof(SegmentEntry));
                if (unlikely(seg == NULL))
                    return 0;
                seg->segment = segment;
                seg->value = class;
                TAILQ_INSERT_TAIL(&node->segment_list, seg, next);

                bytes_remain--;
                break;
            case PATH_CLASS_16BIT:
                ENIPExtractUint8(&reserved, input, &offset); //skip reserved
                ENIPExtractUint16(&req_path_class16, input, &offset);
                class = req_path_class16;
                SCLogDebug("DecodeCIPRequestPath: 16bit class 0x%x\n", class);

                seg = SCMalloc(sizeof(SegmentEntry));
                if (unlikely(seg == NULL))
                    return 0;
                seg->segment = segment;
                seg->value = class;
                TAILQ_INSERT_TAIL(&node->segment_list, seg, next);

                bytes_remain = bytes_remain - 2;
                break;
            case PATH_INSTANCE_16BIT:
                ENIPExtractUint8(&reserved, input, &offset); // skip reserved
                ENIPExtractUint16(&req_path_instance16, input, &offset);
                //skip instance, don't need to store
                bytes_remain = bytes_remain - 2;
                break;
            default:
                SCLogDebug(
                        "DecodeCIPRequestPath: UNKNOWN SEGMENT 0x%x service 0x%x\n",
                        segment, node->service);
                return 0;
        }
    }

    if ((node->service == CIP_SET_ATTR_LIST) || (node->service
            == CIP_GET_ATTR_LIST))
    {
        uint16_t attr_list_count;
        uint16_t attribute;
        //parse get/set attribute list
        ENIPExtractUint16(&attr_list_count, input, &offset);
        SCLogDebug("DecodeCIPRequestPathPDU: attribute list count %d\n",
                attr_list_count);
        for (int i = 0; i < attr_list_count; i++)
        {
            ENIPExtractUint16(&attribute, input, &offset);
            SCLogDebug("DecodeCIPRequestPathPDU: attribute %d\n", attribute);
            //save attrs
            AttributeEntry *attr = SCMalloc(sizeof(AttributeEntry));
            if (unlikely(attr == NULL))
                return 0;
            attr->attribute = attribute;
            TAILQ_INSERT_TAIL(&node->attrib_list, attr, next);

        }
    }

    return 1;

}


/**
 * \brief Decode CIP Response
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPResponsePDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{
    int ret = 1;

    if (enip_data->encap_data_item.length < sizeof(CIPRespHdr))
    {
        SCLogDebug("DecodeCIPResponse - Malformed CIP Data\n");
        return 0;
    }

    uint8_t service; //<----CIP SERVICE
    uint8_t reserved; //unused byte reserved by ODVA
    uint16_t status;

    ENIPExtractUint8(&service, input, &offset);
    ENIPExtractUint8(&reserved, input, &offset);
    ENIPExtractUint16(&status, input, &offset);

    //SCLogDebug("DecodeCIPResponse: service 0x%x\n",service);
    service &= 0x7f; //strip off top bit to get service code.  Responses have first bit as 1

    SCLogDebug("CIP service 0x%x status 0x%x\n", service, status);

    //save CIP data
    CIPServiceEntry *node = CIPServiceAlloc(enip_data);
    node->direction = 1;
    node->service = service;
    node->response.status = status;

    SCLogDebug("DecodeCIPResponsePDU: service 0x%x size %d\n", node->service,
            node->request.path_size);

    //list of CIP services is large and can be vendor specific, store CIP service  anyways and let the rule decide the action
    switch (service)
    {
        case CIP_RESERVED:
            SCLogDebug("DecodeCIPResponse - CIP_RESERVED\n");
            break;
        case CIP_GET_ATTR_ALL:
            SCLogDebug("DecodeCIPResponse - CIP_GET_ATTR_ALL\n");
            break;
        case CIP_GET_ATTR_LIST:
            SCLogDebug("DecodeCIPResponse - CIP_GET_ATTR_LIST\n");
            break;
        case CIP_SET_ATTR_LIST:
            SCLogDebug("DecodeCIPResponse - CIP_SET_ATTR_LIST\n");
            break;
        case CIP_RESET:
            SCLogDebug("DecodeCIPResponse - CIP_RESET\n");
            break;
        case CIP_START:
            SCLogDebug("DecodeCIPResponse - CIP_START\n");
            break;
        case CIP_STOP:
            SCLogDebug("DecodeCIPResponse - CIP_STOP\n");
            break;
        case CIP_CREATE:
            SCLogDebug("DecodeCIPResponse - CIP_CREATE\n");
            break;
        case CIP_DELETE:
            SCLogDebug("DecodeCIPResponse - CIP_DELETE\n");
            break;
        case CIP_MSP:
            SCLogDebug("DecodeCIPResponse - CIP_MSP\n");
            DecodeCIPResponseMSPPDU(input, input_len, enip_data, offset);
            break;
        case CIP_APPLY_ATTR:
            SCLogDebug("DecodeCIPResponse - CIP_APPLY_ATTR\n");
            break;
        case CIP_KICK_TIMER:
            SCLogDebug("DecodeCIPResponse - CIP_KICK_TIMER\n");
            break;
        case CIP_OPEN_CONNECTION:
            SCLogDebug("DecodeCIPResponse - CIP_OPEN_CONNECTION\n");
            break;
        case CIP_CHANGE_START:
            SCLogDebug("DecodeCIPResponse - CIP_CHANGE_START\n");
            break;
        case CIP_GET_STATUS:
            SCLogDebug("DecodeCIPResponse - CIP_GET_STATUS\n");
            break;
        default:
            SCLogDebug("DecodeCIPResponse - CIP SERVICE 0x%x\n", service);
    }

    return ret;
}


/**
 * \brief Decode CIP Request Multi Service Packet
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPRequestMSPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{
    int ret = 1;

    //use temp_offset just to grab the service offset, don't want to use and push offset
    uint16_t temp_offset = offset;
    uint16_t num_services;
    ByteExtractUint16(&num_services, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (input + temp_offset));
    temp_offset += sizeof(uint16_t);
    //SCLogDebug("DecodeCIPRequestMSP number of services %d\n",num_services);

    for (int svc = 1; svc < num_services + 1; svc++)
    {

        if (temp_offset >= (input_len - sizeof(uint16_t)))
        {
            SCLogDebug("DecodeCIPRequestMSP: Parsing beyond payload length\n");
            return 0;
        }

        uint16_t svc_offset; //read set of service offsets
        ByteExtractUint16(&svc_offset, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
                (const uint8_t *) (input + temp_offset));
        temp_offset += sizeof(uint16_t);
        //SCLogDebug("parseCIPRequestMSP service %d offset %d\n",svc, svc_offset);

        DecodeCIPPDU(input, input_len, enip_data, offset + svc_offset); //parse CIP at found offset
    }

    return ret;
}



/**
 * \brief Decode CIP Response MultiService Packet.
 * @param input, input_len data stream
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPResponseMSPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset)
{
    int ret = 1;

    //use temp_offset just to grab the service offset, don't want to use and push offset
    uint16_t temp_offset = offset;
    uint16_t num_services;
    ByteExtractUint16(&num_services, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (input + temp_offset));
    temp_offset += sizeof(uint16_t);
    //SCLogDebug("DecodeCIPResponseMSP number of services %d\n", num_services);

    for (int svc = 0; svc < num_services; svc++)
    {

        if (temp_offset >= (input_len - sizeof(uint16_t)))
        {
            SCLogDebug("DecodeCIPResponseMSP: Parsing beyond payload length\n");
            return 0;
        }

        uint16_t svc_offset; //read set of service offsets
        ByteExtractUint16(&svc_offset, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
                (const uint8_t *) (input + temp_offset));
        temp_offset += sizeof(uint16_t);
        //SCLogDebug("parseCIPResponseMSP service %d offset %d\n", svc, svc_offset);

        DecodeCIPPDU(input, input_len, enip_data, offset + svc_offset); //parse CIP at found offset
    }

    return ret;
}

