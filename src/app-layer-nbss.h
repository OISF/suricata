/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_NBSS_H__
#define __APP_LAYER_NBSS_H__

#include "suricata-common.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream.h"

/*
 http://ubiqx.org/cifs/rfc-draft/rfc1002.html#s4.3
 All session packets are of the following general structure:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      TYPE     |     FLAGS     |            LENGTH             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /               TRAILER (Packet Type Dependent)                 /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The TYPE, FLAGS, and LENGTH fields are present in every session
   packet.
*/

#define NBSS_SESSION_MESSAGE            0x00
#define NBSS_SESSION_REQUEST            0x81
#define NBSS_POSITIVE_SESSION_RESPONSE  0x82
#define NBSS_NEGATIVE_SESSION_RESPONSE  0x83
#define NBSS_RETARGET_SESSION_RESPONSE  0x84
#define NBSS_SESSION_KEEP_ALIVE         0x85

typedef struct NBSSHdr_ {
	uint8_t type;
	uint8_t flags;
	uint32_t length;
} NBSSHdr;

#define NBSS_HDR_LEN 4

#endif /* __APP_LAYER_NBSS_H__ */
