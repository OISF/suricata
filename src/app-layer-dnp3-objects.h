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
 * \author Jason Ish <jason.ish@oisf.net>
 *
 * This file contains the types (definitions) of the DNP3 objects.
 */

#ifndef __APP_LAYER_DNP3_OBJECTS_H__
#define __APP_LAYER_DNP3_OBJECTS_H__

#define DNP3_OBJECT_CODE(group, variation) (group << 8 | variation)

typedef struct DNP3ObjectG1V1_ {

    /* UINT1. */
    uint8_t state:1;
} DNP3ObjectG1V1,
    DNP3ObjectG10V1,
    DNP3ObjectG80V1;

typedef struct DNP3ObjectG1V2_ {

    /* BSTR8. */
    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  chatter_filter:1;
    uint8_t  reserved:1;
    uint8_t  state:1;
} DNP3ObjectG1V2,
    DNP3ObjectG2V1;

typedef struct DNP3ObjectG2V2_ {

    /* BSTR8. */
    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  chatter_filter:1;
    uint8_t  reserved:1;
    uint8_t  state:1;

    uint64_t timestamp;
} DNP3ObjectG2V2;

typedef struct DNP3ObjectG3V1_ {
    /* UINT2. */
    uint8_t state:2;
} DNP3ObjectG3V1;

typedef struct DNP3ObjectG3V2_ {

    /* BSTR8. */
    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  chatter_filter:1;
    uint8_t  state:2;
} DNP3ObjectG3V2,
    DNP3ObjectG4V1;

/* Identical layout to G1V2. */
typedef struct DNP3ObjectG10V2_ {

    /* BSTR8. */
    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  reserved0:1;
    uint8_t  reserved1:1;
    uint8_t  state:1;
} DNP3ObjectG10V2;

typedef struct DNP3ObjectG12V1_ {

    uint8_t  op_type:4;
    uint8_t  qu:1;
    uint8_t  cr:1;
    uint8_t  tcc:2;
    uint8_t  count;
    uint32_t on_time;
    uint32_t off_time;
    uint8_t  status_code:7;
    uint8_t  reserved:1;
} DNP3ObjectG12V1;

typedef struct DNP3ObjectG12V2_ {

    uint8_t  op_type;
    uint8_t  qu;
    uint8_t  cr;
    uint8_t  tcc;
    uint8_t  count;
    uint32_t on_time;
    uint32_t off_time;
    uint8_t  status_code;
    uint8_t  res;
} DNP3ObjectG12V2;

typedef struct DNP3ObjectG20V1_ {

    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  rollover:1;
    uint8_t  discontinuity:1;
    uint8_t  reserved:1;

    uint32_t count;
} DNP3ObjectG20V1,
    DNP3ObjectG21V1,
    DNP3ObjectG22V1;

typedef struct DNP3ObjectG22V2_ {

    /* BSTR8. */
    uint8_t online:1;
    uint8_t restart:1;
    uint8_t comm_lost:1;
    uint8_t remote_forced:1;
    uint8_t local_forced:1;
    uint8_t rollover:1;
    uint8_t discontinuity:1;
    uint8_t reserved:1;

    /* UINT16. */
    uint16_t count;
} DNP3ObjectG22V2,
    DNP3ObjectG20V2,
    DNP3ObjectG21V2;

typedef struct DNP3ObjectG30V1_ {

    /* BSTR8. */
    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  over_range:1;
    uint8_t  reference_err:1;
    uint8_t  reserved:1;

    int32_t  value;
} DNP3ObjectG30V1,
    DNP3ObjectG32V1,
    DNP3ObjectG40V1;

typedef struct DNP3ObjectG30V2_ {

    uint8_t online:1;
    uint8_t restart:1;
    uint8_t comm_lost:1;
    uint8_t remote_forced:1;
    uint8_t local_forced:1;
    uint8_t over_range:1;
    uint8_t reference_err:1;
    uint8_t reserved:1;

    int16_t value;
} DNP3ObjectG30V2,
    DNP3ObjectG32V2,
    DNP3ObjectG40V2;

typedef struct DNP3ObjectG30V4_ {
    int16_t  value;
} DNP3ObjectG30V4;

typedef struct DNP3ObjectG30V5_ {

    /* BSTR8. */
    uint8_t online:1;
    uint8_t restart:1;
    uint8_t comm_lost:1;
    uint8_t remote_forced:1;
    uint8_t local_forced:1;
    uint8_t over_range:1;
    uint8_t reference_err:1;
    uint8_t reserved:1;

    /* FLT32. */
    float value;
} DNP3ObjectG30V5,
    DNP3ObjectG32V5;

typedef struct DNP3ObjectG32V3_ {

    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  over_range:1;
    uint8_t  reference_err:1;
    uint8_t  reserved:1;

    int32_t  value;
    uint64_t timestamp;
} DNP3ObjectG32V3;

typedef struct DNP3ObjectG32V7_ {

    uint8_t  online:1;
    uint8_t  restart:1;
    uint8_t  comm_lost:1;
    uint8_t  remote_forced:1;
    uint8_t  local_forced:1;
    uint8_t  over_range:1;
    uint8_t  reference_err:1;
    uint8_t  reserved:1;

    float    value;
    uint64_t timestamp;
} DNP3ObjectG32V7;

typedef struct DNP3ObjectG34V1_ {

    /* UINT16. */
    uint16_t deadband_value;
} DNP3ObjectG34V1;

typedef struct DNP3ObjectG50V1_ {

    uint64_t timestamp;
} DNP3ObjectG50V1,
    DNP3ObjectG50V3;

typedef struct DNP3ObjectG52V1_ {

    uint16_t delay_ms;
} DNP3ObjectG52V1,
    DNP3ObjectG52V2;

typedef struct DNP3ObjectG70V3_ {
    uint16_t filename_offset;
    uint16_t filename_size;
    uint64_t created;
    uint16_t permissions;
    uint32_t authentication_key;
    uint32_t file_size;
    uint16_t operational_mode;
    uint16_t maximum_block_size;
    uint16_t request_id;

    char filename[0xffff];       /*<< Filename. */
} DNP3ObjectG70V3;

int DNP3DecodeObject(int group, int variation, const uint8_t **buf,
    uint32_t *len, uint8_t prefix_code, uint32_t start,
    uint32_t count, DNP3PointList *);
DNP3PointList *DNP3PointListAlloc(void);
void DNP3FreeObjectPointList(DNP3PointList *);

#endif /* __APP_LAYER_DNP3_OBJECTS_H__ */
