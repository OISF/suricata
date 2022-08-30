/* Copyright (C) 2022 Open Information Security Foundation
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
 * This file contains the DNP3 object decoders.
 */

#include "suricata-common.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

void DNP3FreeObjectPoint(int group, int variation, void *point);

#if 0
static void DNP3HexDump(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
}
#endif

/**
 * \brief Allocate a list for DNP3 points.
 */
DNP3PointList *DNP3PointListAlloc(void)
{
    DNP3PointList *items = SCCalloc(1, sizeof(*items));
    if (unlikely(items == NULL)) {
        return NULL;
    }
    TAILQ_INIT(items);
    return items;
}

/**
 * \brief Free a DNP3PointList.
 */
void DNP3FreeObjectPointList(int group, int variation, DNP3PointList *list)
{
    DNP3Point *point;
    while ((point = TAILQ_FIRST(list)) != NULL) {
        TAILQ_REMOVE(list, point, next);
        if (point->data != NULL) {
            DNP3FreeObjectPoint(group, variation, point->data);
        }
        SCFree(point);
    }
    SCFree(list);
}

/**
 * \brief Read an uint8_t from a buffer.
 *
 * Reads a uint8_t from a buffer advancing the pointer and
 * decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadUint8(const uint8_t **buf, uint32_t *len, uint8_t *out)
{
    if (*len < (int)sizeof(*out)) {
        return 0;
    }
    *out = *(uint8_t *)(*buf);
    *buf += sizeof(*out);
    *len -= sizeof(*out);
    return 1;
}

/**
 * \brief Read an uint16_t from a buffer.
 *
 * Reads an uint16_t from a buffer advancing the pointer and
 * decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadUint16(const uint8_t **buf, uint32_t *len, uint16_t *out)
{
    if (*len < (int)sizeof(*out)) {
        return 0;
    }
    *out = DNP3_SWAP16(*(uint16_t *)(*buf));
    *buf += sizeof(*out);
    *len -= sizeof(*out);
    return 1;
}

/**
 * \brief Read an unsigned 24 bit integer from a buffer.
 *
 * Reads an an unsigned 24 bit integer from a buffer advancing the
 * pointer and decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadUint24(const uint8_t **buf, uint32_t *len, uint32_t *out)
{
    if (*len < (int)(sizeof(uint8_t) * 3)) {
        return 0;
    }

#if __BYTE_ORDER__ == __BIG_ENDIAN
    *out = ((uint32_t)(*buf)[0] << 16) | ((uint32_t)(*buf)[1] << 8) |
           (uint32_t)(*buf)[2];
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    *out = ((uint64_t)(*buf)[0]) | ((uint64_t)(*buf)[1] << 8) |
           ((uint64_t)(*buf)[2] << 16);
#endif

    *buf += 3;
    *len -= 3;

    return 1;
}

/**
 * \brief Read an uint32_t from a buffer.
 *
 * Reads an uint32_t from a buffer advancing the pointer and
 * decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadUint32(const uint8_t **buf, uint32_t *len, uint32_t *out)
{
    if (*len < (int)sizeof(*out)) {
        return 0;
    }
    *out = DNP3_SWAP32(*(uint32_t *)(*buf));
    *buf += sizeof(*out);
    *len -= sizeof(*out);
    return 1;
}

/**
 * \brief Read an unsigned 48 bit integer from a buffer.
 *
 * Reads an an unsigned 48 bit integer from a buffer advancing the
 * pointer and decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadUint48(const uint8_t **buf, uint32_t *len, uint64_t *out)
{
    if (*len < (int)(sizeof(uint8_t) * 6)) {
        return 0;
    }

#if __BYTE_ORDER__ == __BIG_ENDIAN
    *out = ((uint64_t)(*buf)[0] << 40) | ((uint64_t)(*buf)[1] << 32) |
           ((uint64_t)(*buf)[2] << 24) | ((uint64_t)(*buf)[3] << 16) |
           ((uint64_t)(*buf)[4] << 8) | (uint64_t)(*buf)[5];
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    *out = ((uint64_t)(*buf)[0]) | ((uint64_t)(*buf)[1] << 8) |
           ((uint64_t)(*buf)[2] << 16) | ((uint64_t)(*buf)[3] << 24) |
           ((uint64_t)(*buf)[4] << 32) | ((uint64_t)(*buf)[5] << 40);
#endif

    *buf += 6;
    *len -= 6;

    return 1;
}

/**
 * \brief Read a 32 bit float from a buffer.
 *
 * Reads an 32 bit float from a buffer advancing the pointer and
 * decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadFloat32(const uint8_t **buf, uint32_t *len, float *out)
{
    if (*len < 4) {
        return 0;
    }

#if __BYTE_ORDER == __LITTLE_ENDIAN
    *((uint8_t *)out + 0) = (*buf)[0];
    *((uint8_t *)out + 1) = (*buf)[1];
    *((uint8_t *)out + 2) = (*buf)[2];
    *((uint8_t *)out + 3) = (*buf)[3];
#else
    *((uint8_t *)out + 3) = (*buf)[0];
    *((uint8_t *)out + 2) = (*buf)[1];
    *((uint8_t *)out + 1) = (*buf)[2];
    *((uint8_t *)out + 0) = (*buf)[3];
#endif
    *len -= 4;
    *buf += 4;

    return 1;
}

/**
 * \brief Read a 64 bit float from a buffer.
 *
 * Reads an 64 bit float from a buffer advancing the pointer and
 * decrementing the length.
 *
 * \param buf A pointer to the buffer to read from.
 * \param len A pointer to the buffer length.
 * \param out A pointer to where the value will be stored.
 *
 * \retval Returns 1 if there was enough space in the buffer to read from,
 *    otherwise 0 is returned.
 */
static int DNP3ReadFloat64(const uint8_t **buf, uint32_t *len, double *out)
{
    if (*len < 8) {
        return 0;
    }

#if __BYTE_ORDER == __LITTLE_ENDIAN
    *((uint8_t *)out + 0) = (*buf)[0];
    *((uint8_t *)out + 1) = (*buf)[1];
    *((uint8_t *)out + 2) = (*buf)[2];
    *((uint8_t *)out + 3) = (*buf)[3];
    *((uint8_t *)out + 4) = (*buf)[4];
    *((uint8_t *)out + 5) = (*buf)[5];
    *((uint8_t *)out + 6) = (*buf)[6];
    *((uint8_t *)out + 7) = (*buf)[7];
#else
    *((uint8_t *)out + 7) = (*buf)[0];
    *((uint8_t *)out + 6) = (*buf)[1];
    *((uint8_t *)out + 5) = (*buf)[2];
    *((uint8_t *)out + 4) = (*buf)[3];
    *((uint8_t *)out + 3) = (*buf)[4];
    *((uint8_t *)out + 2) = (*buf)[5];
    *((uint8_t *)out + 1) = (*buf)[6];
    *((uint8_t *)out + 0) = (*buf)[7];
#endif
    *len -= 8;
    *buf += 8;

    return 1;
}

/**
 * \brief Get the prefix value and advance the buffer.
 */
static int DNP3ReadPrefix(
    const uint8_t **buf, uint32_t *len, uint8_t prefix_code, uint32_t *out)
{
    uint8_t prefix_len = 0;

    switch (prefix_code) {
        case 0x01:
        case 0x04:
            prefix_len = 1;
            break;
        case 0x02:
        case 0x05:
            prefix_len = 2;
            break;
        case 0x03:
        case 0x06:
            prefix_len = 4;
        default:
            break;
    }

    if (*len < (uint32_t)prefix_len) {
        return 0;
    }

    switch (prefix_len) {
        case sizeof(uint32_t):
            if (!DNP3ReadUint32(buf, len, out)) {
                return 0;
            }
            break;
        case sizeof(uint16_t): {
            /* Temp value for strict-aliasing. */
            uint16_t val = 0;
            if (!DNP3ReadUint16(buf, len, &val)) {
                return 0;
            }
            *out = val;
            break;
        }
        case sizeof(uint8_t): {
            /* Temp value for strict-aliasing. */
            uint8_t val = 0;
            if (!DNP3ReadUint8(buf, len, &val)) {
                return 0;
            }
            *out = val;
            break;
        }
        default:
            *out = 0;
            break;
    }

    return 1;
}

/**
 * \brief Add an object to a DNP3PointList.
 *
 * \retval 1 if successfull, 0 on failure.
 */
static int DNP3AddPoint(DNP3PointList *list, void *object, uint32_t point_index,
    uint8_t prefix_code, uint32_t prefix)
{
    DNP3Point *point = SCCalloc(1, sizeof(*point));
    if (unlikely(point == NULL)) {
        return 0;
    }
    TAILQ_INSERT_TAIL(list, point, next);
    point->data = object;
    point->prefix = prefix;
    point->index = point_index;
    switch (prefix_code) {
        case 0x00:
            break;
        case 0x01:
        case 0x02:
        case 0x03:
            point->index = prefix;
            break;
        case 0x04:
        case 0x05:
        case 0x06:
            point->size = prefix;
            break;
        default:
            break;
    }

    return 1;
}

/* START GENERATED CODE */

/* Code generated by:
 *     ./scripts/dnp3-gen/dnp3-gen.py
 */

static int DNP3DecodeObjectG1V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG1V1 *object = NULL;
    uint32_t bytes = (count / 8) + 1;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (uint32_t i = 0; i < bytes; i++) {

        uint8_t octet;

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j = j + 1) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x1;

            if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
                goto error;
            }

            object = NULL;
            count--;
            point_index++;
        }

    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG1V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG1V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->reserved = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG2V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG2V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &object->state)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG2V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG2V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->reserved = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG2V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG2V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->reserved = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG3V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG3V1 *object = NULL;
    uint32_t bytes = (count / 8) + 1;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (uint32_t i = 0; i < bytes; i++) {

        uint8_t octet;

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j = j + 2) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x3;

            if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
                goto error;
            }

            object = NULL;
            count--;
            point_index++;
        }

    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG3V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG3V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->state = (octet >> 6) & 0x3;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG4V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG4V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->state = (octet >> 6) & 0x3;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG4V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG4V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->state = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG4V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG4V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->chatter_filter = (octet >> 5) & 0x1;
            object->state = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint16(buf, len, &object->relative_time_ms)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG10V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG10V1 *object = NULL;
    uint32_t bytes = (count / 8) + 1;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (uint32_t i = 0; i < bytes; i++) {

        uint8_t octet;

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j = j + 1) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x1;

            if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
                goto error;
            }

            object = NULL;
            count--;
            point_index++;
        }

    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG10V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG10V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->reserved1 = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG11V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG11V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->reserved1 = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG11V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG11V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->reserved1 = (octet >> 6) & 0x1;
            object->state = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG12V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG12V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->op_type = (octet >> 0) & 0xf;
            object->qu = (octet >> 4) & 0x1;
            object->cr = (octet >> 5) & 0x1;
            object->tcc = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint8(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->ontime)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->offtime)) {
            goto error;
        }
        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG12V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG12V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->op_type = (octet >> 0) & 0xf;
            object->qu = (octet >> 4) & 0x1;
            object->cr = (octet >> 5) & 0x1;
            object->tcc = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint8(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->ontime)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->offtime)) {
            goto error;
        }
        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG12V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG12V3 *object = NULL;
    uint32_t bytes = (count / 8) + 1;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (uint32_t i = 0; i < bytes; i++) {

        uint8_t octet;

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j = j + 1) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->point = (octet >> j) & 0x1;

            if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
                goto error;
            }

            object = NULL;
            count--;
            point_index++;
        }

    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG13V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG13V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->commanded_state = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG13V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG13V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->commanded_state = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG20V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG20V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V9(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V9 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V10(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V10 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V11(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V11 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG21V12(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG21V12 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG22V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG22V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG23V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG23V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->rollover = (octet >> 5) & 0x1;
            object->reserved0 = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG30V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG30V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG31V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG31V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG32V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG32V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG33V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG33V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG34V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG34V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->deadband_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG34V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG34V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->deadband_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG34V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG34V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadFloat32(buf, len, &object->deadband_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG40V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG40V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG40V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG40V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG40V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG40V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG40V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG40V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG41V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG41V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->control_status)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG41V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG41V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->control_status)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG41V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG41V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->control_status)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG41V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG41V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->control_status)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG42V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG42V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->over_range = (octet >> 5) & 0x1;
            object->reference_err = (octet >> 6) & 0x1;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->commanded_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->commanded_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->commanded_value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->commanded_value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->commanded_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->commanded_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat32(buf, len, &object->commanded_value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG43V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG43V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->status_code = (octet >> 0) & 0x7f;
            object->reserved0 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadFloat64(buf, len, &object->commanded_value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG50V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG50V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG50V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG50V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->interval)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG50V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG50V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG50V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG50V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->interval_count)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->interval_units)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG51V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG51V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG51V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG51V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG52V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG52V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->delay_secs)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG52V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG52V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->delay_ms)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->filename_size)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->filetype_code)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->attribute_code)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->start_record)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->end_record)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->file_size)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->created_timestamp)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->permission)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->file_id)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->owner_id)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->group_id)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->file_function_code)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->status_code)) {
            goto error;
        }
        if (object->filename_size > 0) {
            if (*len < object->filename_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->filename, *buf, object->filename_size);
            *buf += object->filename_size;
            *len -= object->filename_size;
        }
        object->filename[object->filename_size] = '\0';
        if (!DNP3ReadUint16(buf, len, &object->data_size)) {
            goto error;
        }
        if (object->data_size > 0) {
            if (*len < object->data_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->data, *buf, object->data_size);
            *buf += object->data_size;
            *len -= object->data_size;
        }
        object->data[object->data_size] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->username_offset)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->username_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->password_offset)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->password_size)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->authentication_key)) {
            goto error;
        }
        if (object->username_size > 0) {
            if (*len < object->username_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->username, *buf, object->username_size);
            *buf += object->username_size;
            *len -= object->username_size;
        }
        object->username[object->username_size] = '\0';
        if (object->password_size > 0) {
            if (*len < object->password_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->password, *buf, object->password_size);
            *buf += object->password_size;
            *len -= object->password_size;
        }
        object->password[object->password_size] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->filename_offset)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->filename_size)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->created)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->permissions)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->authentication_key)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->file_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->operational_mode)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->maximum_block_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->request_id)) {
            goto error;
        }
        if (object->filename_size > 0) {
            if (*len < object->filename_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->filename, *buf, object->filename_size);
            *buf += object->filename_size;
            *len -= object->filename_size;
        }
        object->filename[object->filename_size] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (!DNP3PrefixIsSize(prefix_code)) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->file_handle)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->file_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->maximum_block_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->request_id)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->status_code)) {
            goto error;
        }
        if (prefix - (offset - *len) >= 255 || prefix < (offset - *len)) {
            goto error;
        }
        object->optional_text_len = (uint8_t)(prefix - (offset - *len));
        if (object->optional_text_len > 0) {
            if (*len < object->optional_text_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->optional_text, *buf, object->optional_text_len);
            *buf += object->optional_text_len;
            *len -= object->optional_text_len;
        }
        object->optional_text[object->optional_text_len] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (!DNP3PrefixIsSize(prefix_code)) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->file_handle)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->block_number)) {
            goto error;
        }
        if (prefix - (offset - *len) >= 255 || prefix < (offset - *len)) {
            goto error;
        }
        object->file_data_len = (uint8_t)(prefix - (offset - *len));
        if (object->file_data_len > 0) {
            if (*len < object->file_data_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->file_data, *buf, object->file_data_len);
            *buf += object->file_data_len;
            *len -= object->file_data_len;
        }
        object->file_data[object->file_data_len] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (!DNP3PrefixIsSize(prefix_code)) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->file_handle)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->block_number)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->status_code)) {
            goto error;
        }
        if (prefix - (offset - *len) >= 255 || prefix < (offset - *len)) {
            goto error;
        }
        object->optional_text_len = (uint8_t)(prefix - (offset - *len));
        if (object->optional_text_len > 0) {
            if (*len < object->optional_text_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->optional_text, *buf, object->optional_text_len);
            *buf += object->optional_text_len;
            *len -= object->optional_text_len;
        }
        object->optional_text[object->optional_text_len] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->filename_offset)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->filename_size)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->file_type)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->file_size)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->created_timestamp)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->permissions)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->request_id)) {
            goto error;
        }
        if (object->filename_size > 0) {
            if (*len < object->filename_size) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->filename, *buf, object->filename_size);
            *buf += object->filename_size;
            *len -= object->filename_size;
        }
        object->filename[object->filename_size] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG70V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG70V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (prefix - (offset - *len) >= 65535 || prefix < (offset - *len)) {
            goto error;
        }
        object->file_specification_len = (uint16_t)(prefix - (offset - *len));
        if (object->file_specification_len > 0) {
            if (*len < object->file_specification_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->file_specification, *buf, object->file_specification_len);
            *buf += object->file_specification_len;
            *len -= object->file_specification_len;
        }
        object->file_specification[object->file_specification_len] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG80V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG80V1 *object = NULL;
    uint32_t bytes = (count / 8) + 1;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (uint32_t i = 0; i < bytes; i++) {

        uint8_t octet;

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j = j + 1) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x1;

            if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
                goto error;
            }

            object = NULL;
            count--;
            point_index++;
        }

    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG81V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG81V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->fill_percentage = (octet >> 0) & 0x7f;
            object->overflow_state = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint8(buf, len, &object->group)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->variation)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG83V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG83V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (*len < 4) {
            goto error;
        }
        memcpy(object->vendor_code, *buf, 4);
        object->vendor_code[4] = '\0';
        *buf += 4;
        *len -= 4;
        if (!DNP3ReadUint16(buf, len, &object->object_id)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->length)) {
            goto error;
        }
        if (object->length > 0) {
            if (*len < object->length) {
                /* Not enough data. */
                goto error;
            }
            object->data_objects = SCCalloc(1, object->length);
            if (unlikely(object->data_objects == NULL)) {
                goto error;
            }
            memcpy(object->data_objects, *buf, object->length);
            *buf += object->length;
            *len -= object->length;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->data_objects != NULL) {
            SCFree(object->data_objects);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG86V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG86V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->rd = (octet >> 0) & 0x1;
            object->wr = (octet >> 1) & 0x1;
            object->st = (octet >> 2) & 0x1;
            object->ev = (octet >> 3) & 0x1;
            object->df = (octet >> 4) & 0x1;
            object->padding0 = (octet >> 5) & 0x1;
            object->padding1 = (octet >> 6) & 0x1;
            object->padding2 = (octet >> 7) & 0x1;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG102V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG102V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &object->value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->csq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->usr)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->mal)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->reason)) {
            goto error;
        }
        if (prefix < (offset - *len)) {
            goto error;
        }
        object->challenge_data_len = (uint16_t)(prefix - (offset - *len));
        if (object->challenge_data_len > 0) {
            if (*len < object->challenge_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->challenge_data = SCCalloc(1, object->challenge_data_len);
            if (unlikely(object->challenge_data == NULL)) {
                goto error;
            }
            memcpy(object->challenge_data, *buf, object->challenge_data_len);
            *buf += object->challenge_data_len;
            *len -= object->challenge_data_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->challenge_data != NULL) {
            SCFree(object->challenge_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->csq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->usr)) {
            goto error;
        }
        if (prefix < (offset - *len)) {
            goto error;
        }
        object->mac_value_len = (uint16_t)(prefix - (offset - *len));
        if (object->mac_value_len > 0) {
            if (*len < object->mac_value_len) {
                /* Not enough data. */
                goto error;
            }
            object->mac_value = SCCalloc(1, object->mac_value_len);
            if (unlikely(object->mac_value == NULL)) {
                goto error;
            }
            memcpy(object->mac_value, *buf, object->mac_value_len);
            *buf += object->mac_value_len;
            *len -= object->mac_value_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->mac_value != NULL) {
            SCFree(object->mac_value);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V3 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->csq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_number)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V4 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->user_number)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V5 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->ksq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_number)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->key_wrap_alg)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->key_status)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->mal)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->challenge_data_len)) {
            goto error;
        }
        if (object->challenge_data_len > 0) {
            if (*len < object->challenge_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->challenge_data = SCCalloc(1, object->challenge_data_len);
            if (unlikely(object->challenge_data == NULL)) {
                goto error;
            }
            memcpy(object->challenge_data, *buf, object->challenge_data_len);
            *buf += object->challenge_data_len;
            *len -= object->challenge_data_len;
        }
        if (prefix < (offset - *len)) {
            goto error;
        }
        object->mac_value_len = (uint16_t)(prefix - (offset - *len));
        if (object->mac_value_len > 0) {
            if (*len < object->mac_value_len) {
                /* Not enough data. */
                goto error;
            }
            object->mac_value = SCCalloc(1, object->mac_value_len);
            if (unlikely(object->mac_value == NULL)) {
                goto error;
            }
            memcpy(object->mac_value, *buf, object->mac_value_len);
            *buf += object->mac_value_len;
            *len -= object->mac_value_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->challenge_data != NULL) {
            SCFree(object->challenge_data);
        }
        if (object->mac_value != NULL) {
            SCFree(object->mac_value);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V6(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V6 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint24(buf, len, &object->ksq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->usr)) {
            goto error;
        }
        if (prefix < (offset - *len)) {
            goto error;
        }
        object->wrapped_key_data_len = (uint16_t)(prefix - (offset - *len));
        if (object->wrapped_key_data_len > 0) {
            if (*len < object->wrapped_key_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->wrapped_key_data = SCCalloc(1, object->wrapped_key_data_len);
            if (unlikely(object->wrapped_key_data == NULL)) {
                goto error;
            }
            memcpy(object->wrapped_key_data, *buf, object->wrapped_key_data_len);
            *buf += object->wrapped_key_data_len;
            *len -= object->wrapped_key_data_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->wrapped_key_data != NULL) {
            SCFree(object->wrapped_key_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V7 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint32(buf, len, &object->sequence_number)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->usr)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->association_id)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->error_code)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->time_of_error)) {
            goto error;
        }
        if (prefix - (offset - *len) >= 65535 || prefix < (offset - *len)) {
            goto error;
        }
        object->error_text_len = (uint16_t)(prefix - (offset - *len));
        if (object->error_text_len > 0) {
            if (*len < object->error_text_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->error_text, *buf, object->error_text_len);
            *buf += object->error_text_len;
            *len -= object->error_text_len;
        }
        object->error_text[object->error_text_len] = '\0';

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V8(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V8 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (!DNP3ReadUint8(buf, len, &object->key_change_method)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->certificate_type)) {
            goto error;
        }
        if (prefix < (offset - *len)) {
            goto error;
        }
        object->certificate_len = (uint16_t)(prefix - (offset - *len));
        if (object->certificate_len > 0) {
            if (*len < object->certificate_len) {
                /* Not enough data. */
                goto error;
            }
            object->certificate = SCCalloc(1, object->certificate_len);
            if (unlikely(object->certificate == NULL)) {
                goto error;
            }
            memcpy(object->certificate, *buf, object->certificate_len);
            *buf += object->certificate_len;
            *len -= object->certificate_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->certificate != NULL) {
            SCFree(object->certificate);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V9(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V9 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (prefix < (offset - *len)) {
            goto error;
        }
        object->mac_value_len = (uint16_t)(prefix - (offset - *len));
        if (object->mac_value_len > 0) {
            if (*len < object->mac_value_len) {
                /* Not enough data. */
                goto error;
            }
            object->mac_value = SCCalloc(1, object->mac_value_len);
            if (unlikely(object->mac_value == NULL)) {
                goto error;
            }
            memcpy(object->mac_value, *buf, object->mac_value_len);
            *buf += object->mac_value_len;
            *len -= object->mac_value_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->mac_value != NULL) {
            SCFree(object->mac_value);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V10(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V10 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &object->key_change_method)) {
            goto error;
        }
        if (!DNP3ReadUint8(buf, len, &object->operation)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->scs)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_role)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_role_expiry_interval)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->username_len)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_public_key_len)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->certification_data_len)) {
            goto error;
        }
        if (object->username_len > 0) {
            if (*len < object->username_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->username, *buf, object->username_len);
            *buf += object->username_len;
            *len -= object->username_len;
        }
        object->username[object->username_len] = '\0';
        if (object->user_public_key_len > 0) {
            if (*len < object->user_public_key_len) {
                /* Not enough data. */
                goto error;
            }
            object->user_public_key = SCCalloc(1, object->user_public_key_len);
            if (unlikely(object->user_public_key == NULL)) {
                goto error;
            }
            memcpy(object->user_public_key, *buf, object->user_public_key_len);
            *buf += object->user_public_key_len;
            *len -= object->user_public_key_len;
        }
        if (object->certification_data_len > 0) {
            if (*len < object->certification_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->certification_data = SCCalloc(1, object->certification_data_len);
            if (unlikely(object->certification_data == NULL)) {
                goto error;
            }
            memcpy(object->certification_data, *buf, object->certification_data_len);
            *buf += object->certification_data_len;
            *len -= object->certification_data_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->user_public_key != NULL) {
            SCFree(object->user_public_key);
        }
        if (object->certification_data != NULL) {
            SCFree(object->certification_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V11(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V11 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &object->key_change_method)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->username_len)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->master_challenge_data_len)) {
            goto error;
        }
        if (object->username_len > 0) {
            if (*len < object->username_len) {
                /* Not enough data. */
                goto error;
            }
            memcpy(object->username, *buf, object->username_len);
            *buf += object->username_len;
            *len -= object->username_len;
        }
        object->username[object->username_len] = '\0';
        if (object->master_challenge_data_len > 0) {
            if (*len < object->master_challenge_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->master_challenge_data = SCCalloc(1, object->master_challenge_data_len);
            if (unlikely(object->master_challenge_data == NULL)) {
                goto error;
            }
            memcpy(object->master_challenge_data, *buf, object->master_challenge_data_len);
            *buf += object->master_challenge_data_len;
            *len -= object->master_challenge_data_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->master_challenge_data != NULL) {
            SCFree(object->master_challenge_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V12(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V12 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->ksq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_number)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->challenge_data_len)) {
            goto error;
        }
        if (object->challenge_data_len > 0) {
            if (*len < object->challenge_data_len) {
                /* Not enough data. */
                goto error;
            }
            object->challenge_data = SCCalloc(1, object->challenge_data_len);
            if (unlikely(object->challenge_data == NULL)) {
                goto error;
            }
            memcpy(object->challenge_data, *buf, object->challenge_data_len);
            *buf += object->challenge_data_len;
            *len -= object->challenge_data_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->challenge_data != NULL) {
            SCFree(object->challenge_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V13(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V13 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->ksq)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->user_number)) {
            goto error;
        }
        if (!DNP3ReadUint16(buf, len, &object->encrypted_update_key_len)) {
            goto error;
        }
        if (object->encrypted_update_key_len > 0) {
            if (*len < object->encrypted_update_key_len) {
                /* Not enough data. */
                goto error;
            }
            object->encrypted_update_key_data = SCCalloc(1, object->encrypted_update_key_len);
            if (unlikely(object->encrypted_update_key_data == NULL)) {
                goto error;
            }
            memcpy(object->encrypted_update_key_data, *buf, object->encrypted_update_key_len);
            *buf += object->encrypted_update_key_len;
            *len -= object->encrypted_update_key_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->encrypted_update_key_data != NULL) {
            SCFree(object->encrypted_update_key_data);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V14(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V14 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (prefix < (offset - *len)) {
            goto error;
        }
        object->digital_signature_len = (uint16_t)(prefix - (offset - *len));
        if (object->digital_signature_len > 0) {
            if (*len < object->digital_signature_len) {
                /* Not enough data. */
                goto error;
            }
            object->digital_signature = SCCalloc(1, object->digital_signature_len);
            if (unlikely(object->digital_signature == NULL)) {
                goto error;
            }
            memcpy(object->digital_signature, *buf, object->digital_signature_len);
            *buf += object->digital_signature_len;
            *len -= object->digital_signature_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->digital_signature != NULL) {
            SCFree(object->digital_signature);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG120V15(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG120V15 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;
    uint32_t offset;

    if (prefix_code != 5) {
        goto error;
    }

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        offset = *len;

        if (prefix < (offset - *len)) {
            goto error;
        }
        object->mac_len = (uint16_t)(prefix - (offset - *len));
        if (object->mac_len > 0) {
            if (*len < object->mac_len) {
                /* Not enough data. */
                goto error;
            }
            object->mac = SCCalloc(1, object->mac_len);
            if (unlikely(object->mac == NULL)) {
                goto error;
            }
            memcpy(object->mac, *buf, object->mac_len);
            *buf += object->mac_len;
            *len -= object->mac_len;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        if (object->mac != NULL) {
            SCFree(object->mac);
        }
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG121V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG121V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->association_id)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->count_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG122V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG122V1 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->association_id)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->count_value)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}

static int DNP3DecodeObjectG122V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *points)
{
    DNP3ObjectG122V2 *object = NULL;
    uint32_t prefix = 0;
    uint32_t point_index = start;

    if (*len < count/8) {
        goto error;
    }
    while (count--) {

        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->online = (octet >> 0) & 0x1;
            object->restart = (octet >> 1) & 0x1;
            object->comm_lost = (octet >> 2) & 0x1;
            object->remote_forced = (octet >> 3) & 0x1;
            object->local_forced = (octet >> 4) & 0x1;
            object->reserved0 = (octet >> 5) & 0x1;
            object->discontinuity = (octet >> 6) & 0x1;
            object->reserved1 = (octet >> 7) & 0x1;
        }
        if (!DNP3ReadUint16(buf, len, &object->association_id)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->count_value)) {
            goto error;
        }
        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddPoint(points, object, point_index, prefix_code, prefix)) {
            goto error;
        }

        object = NULL;
        point_index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }

    return 0;
}


void DNP3FreeObjectPoint(int group, int variation, void *point)
{
    switch(DNP3_OBJECT_CODE(group, variation)) {
        case DNP3_OBJECT_CODE(83, 1): {
            DNP3ObjectG83V1 *object = (DNP3ObjectG83V1 *) point;
            if (object->data_objects != NULL) {
                SCFree(object->data_objects);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 1): {
            DNP3ObjectG120V1 *object = (DNP3ObjectG120V1 *) point;
            if (object->challenge_data != NULL) {
                SCFree(object->challenge_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 2): {
            DNP3ObjectG120V2 *object = (DNP3ObjectG120V2 *) point;
            if (object->mac_value != NULL) {
                SCFree(object->mac_value);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 5): {
            DNP3ObjectG120V5 *object = (DNP3ObjectG120V5 *) point;
            if (object->challenge_data != NULL) {
                SCFree(object->challenge_data);
            }
            if (object->mac_value != NULL) {
                SCFree(object->mac_value);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 6): {
            DNP3ObjectG120V6 *object = (DNP3ObjectG120V6 *) point;
            if (object->wrapped_key_data != NULL) {
                SCFree(object->wrapped_key_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 8): {
            DNP3ObjectG120V8 *object = (DNP3ObjectG120V8 *) point;
            if (object->certificate != NULL) {
                SCFree(object->certificate);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 9): {
            DNP3ObjectG120V9 *object = (DNP3ObjectG120V9 *) point;
            if (object->mac_value != NULL) {
                SCFree(object->mac_value);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 10): {
            DNP3ObjectG120V10 *object = (DNP3ObjectG120V10 *) point;
            if (object->user_public_key != NULL) {
                SCFree(object->user_public_key);
            }
            if (object->certification_data != NULL) {
                SCFree(object->certification_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 11): {
            DNP3ObjectG120V11 *object = (DNP3ObjectG120V11 *) point;
            if (object->master_challenge_data != NULL) {
                SCFree(object->master_challenge_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 12): {
            DNP3ObjectG120V12 *object = (DNP3ObjectG120V12 *) point;
            if (object->challenge_data != NULL) {
                SCFree(object->challenge_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 13): {
            DNP3ObjectG120V13 *object = (DNP3ObjectG120V13 *) point;
            if (object->encrypted_update_key_data != NULL) {
                SCFree(object->encrypted_update_key_data);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 14): {
            DNP3ObjectG120V14 *object = (DNP3ObjectG120V14 *) point;
            if (object->digital_signature != NULL) {
                SCFree(object->digital_signature);
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 15): {
            DNP3ObjectG120V15 *object = (DNP3ObjectG120V15 *) point;
            if (object->mac != NULL) {
                SCFree(object->mac);
            }
            break;
        }
        default:
            break;
    }
    SCFree(point);
}

/**
 * \brief Decode a DNP3 object.
 *
 * \retval 0 on success. On failure a positive integer corresponding
 *     to a DNP3 application layer event will be returned.
 */
int DNP3DecodeObject(int group, int variation, const uint8_t **buf,
    uint32_t *len, uint8_t prefix_code, uint32_t start,
    uint32_t count, DNP3PointList *points)
{
    int rc = 0;

    switch (DNP3_OBJECT_CODE(group, variation)) {
        case DNP3_OBJECT_CODE(1, 1):
            rc = DNP3DecodeObjectG1V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(1, 2):
            rc = DNP3DecodeObjectG1V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(2, 1):
            rc = DNP3DecodeObjectG2V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(2, 2):
            rc = DNP3DecodeObjectG2V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(2, 3):
            rc = DNP3DecodeObjectG2V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(3, 1):
            rc = DNP3DecodeObjectG3V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(3, 2):
            rc = DNP3DecodeObjectG3V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(4, 1):
            rc = DNP3DecodeObjectG4V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(4, 2):
            rc = DNP3DecodeObjectG4V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(4, 3):
            rc = DNP3DecodeObjectG4V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(10, 1):
            rc = DNP3DecodeObjectG10V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(10, 2):
            rc = DNP3DecodeObjectG10V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(11, 1):
            rc = DNP3DecodeObjectG11V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(11, 2):
            rc = DNP3DecodeObjectG11V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(12, 1):
            rc = DNP3DecodeObjectG12V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(12, 2):
            rc = DNP3DecodeObjectG12V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(12, 3):
            rc = DNP3DecodeObjectG12V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(13, 1):
            rc = DNP3DecodeObjectG13V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(13, 2):
            rc = DNP3DecodeObjectG13V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 1):
            rc = DNP3DecodeObjectG20V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 2):
            rc = DNP3DecodeObjectG20V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 3):
            rc = DNP3DecodeObjectG20V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 4):
            rc = DNP3DecodeObjectG20V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 5):
            rc = DNP3DecodeObjectG20V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 6):
            rc = DNP3DecodeObjectG20V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 7):
            rc = DNP3DecodeObjectG20V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(20, 8):
            rc = DNP3DecodeObjectG20V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 1):
            rc = DNP3DecodeObjectG21V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 2):
            rc = DNP3DecodeObjectG21V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 3):
            rc = DNP3DecodeObjectG21V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 4):
            rc = DNP3DecodeObjectG21V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 5):
            rc = DNP3DecodeObjectG21V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 6):
            rc = DNP3DecodeObjectG21V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 7):
            rc = DNP3DecodeObjectG21V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 8):
            rc = DNP3DecodeObjectG21V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 9):
            rc = DNP3DecodeObjectG21V9(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 10):
            rc = DNP3DecodeObjectG21V10(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 11):
            rc = DNP3DecodeObjectG21V11(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(21, 12):
            rc = DNP3DecodeObjectG21V12(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 1):
            rc = DNP3DecodeObjectG22V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 2):
            rc = DNP3DecodeObjectG22V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 3):
            rc = DNP3DecodeObjectG22V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 4):
            rc = DNP3DecodeObjectG22V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 5):
            rc = DNP3DecodeObjectG22V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 6):
            rc = DNP3DecodeObjectG22V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 7):
            rc = DNP3DecodeObjectG22V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(22, 8):
            rc = DNP3DecodeObjectG22V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 1):
            rc = DNP3DecodeObjectG23V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 2):
            rc = DNP3DecodeObjectG23V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 3):
            rc = DNP3DecodeObjectG23V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 4):
            rc = DNP3DecodeObjectG23V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 5):
            rc = DNP3DecodeObjectG23V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 6):
            rc = DNP3DecodeObjectG23V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 7):
            rc = DNP3DecodeObjectG23V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(23, 8):
            rc = DNP3DecodeObjectG23V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 1):
            rc = DNP3DecodeObjectG30V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 2):
            rc = DNP3DecodeObjectG30V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 3):
            rc = DNP3DecodeObjectG30V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 4):
            rc = DNP3DecodeObjectG30V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 5):
            rc = DNP3DecodeObjectG30V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(30, 6):
            rc = DNP3DecodeObjectG30V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 1):
            rc = DNP3DecodeObjectG31V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 2):
            rc = DNP3DecodeObjectG31V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 3):
            rc = DNP3DecodeObjectG31V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 4):
            rc = DNP3DecodeObjectG31V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 5):
            rc = DNP3DecodeObjectG31V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 6):
            rc = DNP3DecodeObjectG31V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 7):
            rc = DNP3DecodeObjectG31V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(31, 8):
            rc = DNP3DecodeObjectG31V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 1):
            rc = DNP3DecodeObjectG32V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 2):
            rc = DNP3DecodeObjectG32V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 3):
            rc = DNP3DecodeObjectG32V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 4):
            rc = DNP3DecodeObjectG32V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 5):
            rc = DNP3DecodeObjectG32V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 6):
            rc = DNP3DecodeObjectG32V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 7):
            rc = DNP3DecodeObjectG32V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(32, 8):
            rc = DNP3DecodeObjectG32V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 1):
            rc = DNP3DecodeObjectG33V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 2):
            rc = DNP3DecodeObjectG33V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 3):
            rc = DNP3DecodeObjectG33V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 4):
            rc = DNP3DecodeObjectG33V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 5):
            rc = DNP3DecodeObjectG33V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 6):
            rc = DNP3DecodeObjectG33V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 7):
            rc = DNP3DecodeObjectG33V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(33, 8):
            rc = DNP3DecodeObjectG33V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(34, 1):
            rc = DNP3DecodeObjectG34V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(34, 2):
            rc = DNP3DecodeObjectG34V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(34, 3):
            rc = DNP3DecodeObjectG34V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(40, 1):
            rc = DNP3DecodeObjectG40V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(40, 2):
            rc = DNP3DecodeObjectG40V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(40, 3):
            rc = DNP3DecodeObjectG40V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(40, 4):
            rc = DNP3DecodeObjectG40V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(41, 1):
            rc = DNP3DecodeObjectG41V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(41, 2):
            rc = DNP3DecodeObjectG41V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(41, 3):
            rc = DNP3DecodeObjectG41V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(41, 4):
            rc = DNP3DecodeObjectG41V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 1):
            rc = DNP3DecodeObjectG42V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 2):
            rc = DNP3DecodeObjectG42V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 3):
            rc = DNP3DecodeObjectG42V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 4):
            rc = DNP3DecodeObjectG42V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 5):
            rc = DNP3DecodeObjectG42V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 6):
            rc = DNP3DecodeObjectG42V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 7):
            rc = DNP3DecodeObjectG42V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(42, 8):
            rc = DNP3DecodeObjectG42V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 1):
            rc = DNP3DecodeObjectG43V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 2):
            rc = DNP3DecodeObjectG43V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 3):
            rc = DNP3DecodeObjectG43V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 4):
            rc = DNP3DecodeObjectG43V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 5):
            rc = DNP3DecodeObjectG43V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 6):
            rc = DNP3DecodeObjectG43V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 7):
            rc = DNP3DecodeObjectG43V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(43, 8):
            rc = DNP3DecodeObjectG43V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(50, 1):
            rc = DNP3DecodeObjectG50V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(50, 2):
            rc = DNP3DecodeObjectG50V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(50, 3):
            rc = DNP3DecodeObjectG50V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(50, 4):
            rc = DNP3DecodeObjectG50V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(51, 1):
            rc = DNP3DecodeObjectG51V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(51, 2):
            rc = DNP3DecodeObjectG51V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(52, 1):
            rc = DNP3DecodeObjectG52V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(52, 2):
            rc = DNP3DecodeObjectG52V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 1):
            rc = DNP3DecodeObjectG70V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 2):
            rc = DNP3DecodeObjectG70V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 3):
            rc = DNP3DecodeObjectG70V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 4):
            rc = DNP3DecodeObjectG70V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 5):
            rc = DNP3DecodeObjectG70V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 6):
            rc = DNP3DecodeObjectG70V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 7):
            rc = DNP3DecodeObjectG70V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(70, 8):
            rc = DNP3DecodeObjectG70V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(80, 1):
            rc = DNP3DecodeObjectG80V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(81, 1):
            rc = DNP3DecodeObjectG81V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(83, 1):
            rc = DNP3DecodeObjectG83V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(86, 2):
            rc = DNP3DecodeObjectG86V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(102, 1):
            rc = DNP3DecodeObjectG102V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 1):
            rc = DNP3DecodeObjectG120V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 2):
            rc = DNP3DecodeObjectG120V2(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 3):
            rc = DNP3DecodeObjectG120V3(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 4):
            rc = DNP3DecodeObjectG120V4(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 5):
            rc = DNP3DecodeObjectG120V5(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 6):
            rc = DNP3DecodeObjectG120V6(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 7):
            rc = DNP3DecodeObjectG120V7(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 8):
            rc = DNP3DecodeObjectG120V8(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 9):
            rc = DNP3DecodeObjectG120V9(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 10):
            rc = DNP3DecodeObjectG120V10(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 11):
            rc = DNP3DecodeObjectG120V11(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 12):
            rc = DNP3DecodeObjectG120V12(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 13):
            rc = DNP3DecodeObjectG120V13(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 14):
            rc = DNP3DecodeObjectG120V14(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(120, 15):
            rc = DNP3DecodeObjectG120V15(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(121, 1):
            rc = DNP3DecodeObjectG121V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(122, 1):
            rc = DNP3DecodeObjectG122V1(buf, len, prefix_code, start, count,
                points);
            break;
        case DNP3_OBJECT_CODE(122, 2):
            rc = DNP3DecodeObjectG122V2(buf, len, prefix_code, start, count,
                points);
            break;
        default:
            return DNP3_DECODER_EVENT_UNKNOWN_OBJECT;
    }

    return rc ? 0 : DNP3_DECODER_EVENT_MALFORMED;
}

/* END GENERATED CODE */
