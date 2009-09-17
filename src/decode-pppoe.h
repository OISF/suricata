/**
 * \file Copyright (c) 2009 Open Infosec Foundation
 * \author James Riden <jamesr@europe.com>
 *
 * PPPOE Decoder header file
 */

#ifndef __DECODE_PPPOE_H__
#define __DECODE_PPPOE_H__

#include "decode.h"
#include "threadvars.h"

#define PPPOE_SESSION_HEADER_LEN 8
#define PPPOE_DISCOVERY_HEADER_MIN_LEN 6

typedef struct PPPOESessionHdr_
{
    unsigned pppoe_version : 4;
    unsigned pppoe_type : 4;
    uint8_t pppoe_code;
    uint16_t session_id;
    uint16_t pppoe_length;
    uint16_t protocol;
} PPPOESessionHdr;

typedef struct PPPOEDiscoveryTag_
{
    uint16_t  pppoe_tag_type;
    uint16_t  pppoe_tag_length;
} PPPOEDiscoveryTag;

typedef struct PPPOEDiscoveryHdr_
{
    unsigned pppoe_version : 4;
    unsigned pppoe_type : 4;
    uint8_t pppoe_code;
    uint16_t discovery_id;
    uint16_t pppoe_length;
} PPPOEDiscoveryHdr;

/* see RFC 2516 - discovery codes */
#define PPPOE_CODE_PADI 0x09
#define PPPOE_CODE_PADO 0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7

/* see RFC 2516 Appendix A */
#define PPPOE_TAG_END_OF_LIST         0x0000 /* End-Of-List */
#define PPPOE_TAG_SERVICE_NAME        0x0101 /* Service-Name */
#define PPPOE_TAG_AC_NAME             0x0102 /* AC-Name */
#define PPPOE_TAG_HOST_UNIQ           0x0103 /* Host-Uniq */
#define PPPOE_TAG_AC_COOKIE           0x0104 /* AC-Cookie */
#define PPPOE_TAG_VENDOR_SPECIFIC     0x0105 /* Vendor-Specific */
#define PPPOE_TAG_RELAY_SESSION_ID    0x0110 /* Relay-Session-Id */
#define PPPOE_TAG_SERVICE_NAME_ERROR  0x0201 /* Service-Name-Error */
#define PPPOE_TAG_AC_SYS_ERROR        0x0202 /* AC-System Error */
#define PPPOE_TAG_GEN_ERROR           0x0203 /* Generic-Error */

void DecodePPPOERegisterTests(void);

#endif /* __DECODE_PPPOE_H__ */

