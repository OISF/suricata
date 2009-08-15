/**
 * \file Copyright (c) 2009 Open Infosec Foundation
 * \author James Riden <jamesr@europe.com>
 *
 * PPPoE Decoder header file
 */

#ifndef __DECODE_PPPOE_H__
#define __DECODE_PPPOE_H__

#include <sys/types.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include "decode.h"
#include "threadvars.h"

#define PPPOE_HEADER_LEN 6

typedef struct _PPPoEHdr
{
	unsigned pppoe_version :4;
	unsigned pppoe_type :4;
	u_int8_t pppoe_code;
	u_int16_t sessin_id;
	u_int16_t pppoe_length;
} PPPoEHdr;

#define PPPOE_CODE_PADI 0x09
#define PPPOE_CODE_PADO 0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7

void DecodePPPoERegisterTests(void);

#endif /* __DECODE_PPPOE_H__ */
