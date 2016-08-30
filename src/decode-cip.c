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
 * Decode CIP
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"
#include "pkt-var.h"
#include "util-profiling.h"
#include "decode-cip.h"


/**
 * \brief Decode CIP packet
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIP(Packet *p, ENIPData *enip_data, uint16_t offset)
{
    int ret = 1;

    if (enip_data->encap_data_item.length == 0)
    {
        SCLogDebug("DecodeCIP: No CIP Data\n");
        return 0;
    }

    if (offset > p->payload_len)
    {
        SCLogDebug("DecodeCIP: Parsing beyond payload length\n");
        return 0;
    }

    uint8_t service = 0;
    service = *(p->payload + offset);

    SCLogDebug("CIP Service 0x%x\n", service);

    //use service code first bit to determine request/response, no need to save or push offset
    if (service >> 7)
    {
        ret = DecodeCIPResponse(p, enip_data, offset);
    } else
    {
        ret = DecodeCIPRequest(p, enip_data, offset);
    }

    return ret;
}

/**
 * \brief Decode CIP Request
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPRequest(Packet *p, ENIPData *enip_data, uint16_t offset)
{
    int ret = 1;

    if (enip_data->encap_data_item.length < sizeof(CIPReqHdr))
    {
        SCLogDebug("DecodeCIPRequest - Malformed CIP Data\n");
        return 0;
    }

    uint8_t service; //<-----CIP SERVICE
    uint8_t path_size;

    ENIPExtractUint8(&service, p->payload, &offset);
    ENIPExtractUint8(&path_size, p->payload, &offset);

    if (service > MAX_CIP_SERVICE)
    { // service codes of value 0x80 or greater are not permitted because in the CIP protocol the highest order bit is used to flag request(0)/response(1)
        SCLogDebug("DecodeCIPRequest - INVALID CIP SERVICE 0x%x\n", service);
        return 0;
    }

    //save CIP data
    CIPServiceData *node = CreateCIPServiceData(enip_data);
    node->service = service;
    node->request.path_size = path_size;
    node->request.path_offset = offset;

    SCLogDebug("DecodeCIPRequestPath: service 0x%x size %d\n", node->service,
            node->request.path_size);

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
            DecodeCIPRequestMSP(p, enip_data, offset);
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
 * \brief Deocde CIP Request Path and compare with rule
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @param cipserviced the cip service rule
 * @return 1 Packet matches
 * @return 0 Packet not match
 */
int DecodeCIPRequestPath(Packet *p, CIPServiceData *node, uint16_t offset,
        DetectCipServiceData *cipserviced)
{

    if (node->request.path_size < 1)
    {
        //SCLogDebug("DecodeCIPRequestPath: empty path or CIP Response\n");
        return 0;
    }

    SCLogDebug("DecodeCIPRequestPath: service 0x%x size %d length %d\n",
            node->service, node->request.path_size, p->payload_len);
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
    uint16_t attrib = 0;
    int found_class = 0;

    while (bytes_remain > 0)
    {

        ENIPExtractUint8(&segment, p->payload, &offset);
        switch (segment)
        { //assume order is class then instance.  Can have multiple
            case PATH_CLASS_8BIT:
                ENIPExtractUint8(&req_path_class8, p->payload, &offset);
                class = (uint16_t) req_path_class8;
                SCLogDebug("DecodeCIPRequestPath: 8bit class 0x%x\n", class);

                if (cipserviced->cipclass == class)
                {
                    if (cipserviced->tokens == 2)
                    {// if rule only has class
                        return 1;
                    } else
                    {
                        found_class = 1;
                    }
                }
                bytes_remain--;
                break;
            case PATH_INSTANCE_8BIT:
                ENIPExtractUint8(&req_path_instance8, p->payload, &offset);
                SCLogDebug("DecodeCIPRequestPath: 8bit instance 0x%x\n",
                        req_path_instance8);
                bytes_remain--;
                break;
            case PATH_ATTR_8BIT: //single attribute
                ENIPExtractUint8(&req_path_attr8, p->payload, &offset);
                attrib = (uint16_t) req_path_attr8;
                SCLogDebug("DecodeCIPRequestPath: 8bit attribute 0x%x\n",
                        attrib);

                if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                        == class) && (cipserviced->cipattribute == attrib) && (cipserviced->matchattribute == 1))
                { // if rule has class & attribute, matched all here
                    return 1;
                }
                if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                        == class)  && (cipserviced->matchattribute == 0))
                { // for negation rule on attribute
                    return 1;
                }

                bytes_remain--;
                break;
            case PATH_CLASS_16BIT:
                ENIPExtractUint8(&reserved, p->payload, &offset); //skip reserved
                ENIPExtractUint16(&req_path_class16, p->payload, &offset);
                class = req_path_class16;
                SCLogDebug("DecodeCIPRequestPath: 16bit class 0x%x\n", class);

                if (cipserviced->cipclass == class)
                {
                    if (cipserviced->tokens == 2)
                    {// if rule only has class
                        return 1;
                    } else
                    {
                        found_class = 1;
                    }
                }
                bytes_remain = bytes_remain - 2;
                break;
            case PATH_INSTANCE_16BIT:
                ENIPExtractUint8(&reserved, p->payload, &offset); // skip reserved
                ENIPExtractUint16(&req_path_instance16, p->payload, &offset);
                SCLogDebug("DecodeCIPRequestPath: 16bit instance 0x%x\n",
                        attrib);
                bytes_remain = bytes_remain - 2;
                break;
            default:
                SCLogDebug(
                        "DecodeCIPRequestPath: UNKNOWN SEGMENT 0x%x service 0x%x\n",
                        segment, node->service);
                return 0;
        }
    }

    if (found_class == 0)
    { // if haven't matched class yet, no need to check attribute
        return 0;
    }

    if ((node->service == CIP_SET_ATTR_LIST) || (node->service
            == CIP_GET_ATTR_LIST))
    {
        uint16_t attr_list_count;
        uint16_t attribute;
        //parse get/set attribute list
        ENIPExtractUint16(&attr_list_count, p->payload, &offset);
        SCLogDebug("DecodeCIPRequestPath: attribute list count %d\n",
                attr_list_count);
        for (int i = 0; i < attr_list_count; i++)
        {
            ENIPExtractUint16(&attribute, p->payload, &offset);
            SCLogDebug("DecodeCIPRequestPath: attribute %d\n", attribute);

            if (cipserviced->matchattribute == 1) //if matching on attribute
            {
                if (cipserviced->cipattribute == attribute)
                {
                    return 1;
                }
            }else { //if want all except attribute
                if (cipserviced->cipattribute != attribute)
                {
                    return 1;
                }

            }

        }
    }

    return 0;
}

/**
 * \brief Decode CIP Response
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPResponse(Packet *p, ENIPData *enip_data, uint16_t offset)
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

    ENIPExtractUint8(&service, p->payload, &offset);
    ENIPExtractUint8(&reserved, p->payload, &offset);
    ENIPExtractUint16(&status, p->payload, &offset);

    //SCLogDebug("DecodeCIPResponse: service 0x%x\n",service);
    service &= 0x7f; //strip off top bit to get service code.  Responses have first bit as 1

    SCLogDebug("CIP service 0x%x status 0x%x\n", service, status);

    //save CIP data
    CIPServiceData *node = CreateCIPServiceData(enip_data);
    node->service = service;
    node->response.status = status;

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
            DecodeCIPResponseMSP(p, enip_data, offset);
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
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPRequestMSP(Packet *p, ENIPData *enip_data, uint16_t offset)
{
    int ret = 1;

    //use temp_offset just to grab the service offset, don't want to use and push offset
    uint16_t temp_offset = offset;
    uint16_t num_services;
    ByteExtractUint16(&num_services, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (p->payload + temp_offset));
    temp_offset += sizeof(uint16_t);
    //SCLogDebug("DecodeCIPRequestMSP number of services %d\n",num_services);

    for (int svc = 1; svc < num_services + 1; svc++)
    {
        if (temp_offset > p->payload_len)
        {
            SCLogDebug("DecodeCIPRequestMSP: Parsing beyond payload length\n");
            return 0;
        }

        uint16_t svc_offset; //read set of service offsets
        ByteExtractUint16(&svc_offset, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
                (const uint8_t *) (p->payload + temp_offset));
        temp_offset += sizeof(uint16_t);
        //SCLogDebug("parseCIPRequestMSP service %d offset %d\n",svc, svc_offset);

        DecodeCIP(p, enip_data, offset + svc_offset); //parse CIP at found offset
    }

    return ret;
}

/**
 * \brief Decode CIP Response MultiService Packet.
 * @param p Packet
 * @param enip_data stores data from Packet
 * @param offset current point in the packet
 * @return 1 Packet ok
 * @return 0 Packet has errors
 */
int DecodeCIPResponseMSP(Packet *p, ENIPData *enip_data, uint16_t offset)
{
    int ret = 1;

    //use temp_offset just to grab the service offset, don't want to use and push offset
    uint16_t temp_offset = offset;
    uint16_t num_services;
    ByteExtractUint16(&num_services, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
            (const uint8_t *) (p->payload + temp_offset));
    temp_offset += sizeof(uint16_t);
    //SCLogDebug("DecodeCIPResponseMSP number of services %d\n", num_services);

    for (int svc = 0; svc < num_services; svc++)
    {

        if (temp_offset > p->payload_len)
        {
            SCLogDebug("DecodeCIPResponseMSP: Parsing beyond payload length\n");
            return 0;
        }

        uint16_t svc_offset; //read set of service offsets
        ByteExtractUint16(&svc_offset, BYTE_LITTLE_ENDIAN, sizeof(uint16_t),
                (const uint8_t *) (p->payload + temp_offset));
        temp_offset += sizeof(uint16_t);
        //SCLogDebug("parseCIPResponseMSP service %d offset %d\n", svc, svc_offset);

        DecodeCIP(p, enip_data, offset + svc_offset); //parse CIP at found offset
    }

    return ret;
}

#ifdef UNITTESTS
/**
 * \brief Test if packet matches signature
 */
int CIPTestMatch(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
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

/**
 * \brief Test Get Attribute All
 */
static int DecodeCIPTest01 (void)
{
    /* Single Get Attribute All */
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x5c, 0x81, 0xb9, 0x40, 0x00, 0x80, 0x06,
        0xe2, 0xb0, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x04, 0x4e, 0xaf, 0x12, 0x46, 0xb6,
        0xaf, 0x0e, 0x91, 0xb1, 0x1f, 0x2a, 0x50, 0x18,
        0xfd, 0xae, 0x96, 0x80, 0x00, 0x00, 0x70, 0x00,
        0x1c, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x29, 0x83, 0x00, 0xb1, 0x00,
        0x08, 0x00, 0x26, 0x00, 0x01, 0x02, 0x20, 0x02,
        0x24, 0x01
    };

    char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\"; cip_service:1; sid:1;)";

    return CIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt),
            sig, 1);
}

/**
 * \brief Test Multi Service Packet with Get Attribute List
 */
static int DecodeCIPTest02 (void)
{
    /* Multi Service Packet with Get Attribute Lists*/
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x9c, 0x81, 0x95, 0x40, 0x00, 0x80, 0x06,
        0xe2, 0x94, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x04, 0x4e, 0xaf, 0x12, 0x46, 0xb6,
        0xa6, 0xc3, 0x91, 0xb1, 0x15, 0xfb, 0x50, 0x18,
        0xfb, 0x56, 0x96, 0xc0, 0x00, 0x00, 0x70, 0x00,
        0x5c, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x29, 0x83, 0x00, 0xb1, 0x00,
        0x48, 0x00, 0x05, 0x00, 0x0a, 0x02, 0x20, 0x02,
        0x24, 0x01, 0x05, 0x00, 0x0c, 0x00, 0x16, 0x00,
        0x22, 0x00, 0x2c, 0x00, 0x36, 0x00, 0x03, 0x02,
        0x20, 0x8e, 0x24, 0x01, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x02, 0x20, 0x64, 0x24, 0x01, 0x02, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x02, 0x20, 0x01,
        0x24, 0x01, 0x01, 0x00, 0x05, 0x00, 0x03, 0x02,
        0x20, 0x69, 0x24, 0x00, 0x01, 0x00, 0x0b, 0x00,
        0x03, 0x02, 0x20, 0x69, 0x24, 0x01, 0x01, 0x00,
        0x0a, 0x00
    };

    char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\"; cip_service:3; sid:1;)";

    return CIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}

/**
 * \brief Test Change Time
 */
static int DecodeCIPTest03 (void)
{
    /* Set Attribute List Change Time*/
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x68, 0x5e, 0x7d, 0x40, 0x00, 0x80, 0x06,
        0x05, 0xe1, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x0b, 0xd9, 0xaf, 0x12, 0xcf, 0xce,
        0x17, 0xe7, 0x8d, 0xf5, 0x35, 0x00, 0x50, 0x18,
        0xfa, 0xd2, 0x96, 0x8c, 0x00, 0x00, 0x70, 0x00,
        0x28, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x0b, 0x7c, 0x00, 0xb1, 0x00,
        0x14, 0x00, 0xb2, 0x04, 0x04, 0x02, 0x20, 0x8b,
        0x24, 0x01, 0x01, 0x00, 0x06, 0x00, 0xc0, 0x32,
        0x5c, 0xff, 0xf3, 0x59, 0x04, 0x00
    };

    char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\"; cip_service:4,139,6; sid:1;)";

    return CIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}

#endif /* UNITTESTS */

/**
 * \brief Register CIP Tests
 */
void DecodeCIPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeCIPTest01", DecodeCIPTest01, 1);
    UtRegisterTest("DecodeCIPTest02", DecodeCIPTest02, 1);
    UtRegisterTest("DecodeCIPTest02", DecodeCIPTest03, 1);
#endif /* UNITTESTS */
}
/**
 * @}
 */
