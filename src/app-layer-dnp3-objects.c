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
 * This file contains the DNP3 object decoders.
 */

#include "suricata-common.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

/**
 * \brief Generic object definition for objects consisting of a single
 *     UINT16.
 */
typedef struct DNP3Object_UINT16_ {
    uint16_t value0;
} DNP3Object_UINT16;

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
void DNP3FreeObjectPointList(DNP3PointList *list)
{
    DNP3Point *point;
    while ((point = TAILQ_FIRST(list)) != NULL) {
        TAILQ_REMOVE(list, point, next);
        if (point->data != NULL) {
            SCFree(point->data);
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
static int DNP3ReadUint8(const uint8_t **buf, uint32_t *len,
    uint8_t *out)
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
static inline int DNP3ReadUint16(const uint8_t **buf, uint32_t *len,
    uint16_t *out)
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
static inline int DNP3ReadUint32(const uint8_t **buf, uint32_t *len,
    uint32_t *out)
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
static inline int DNP3ReadUint48(const uint8_t **buf, uint32_t *len,
    uint64_t *out)
{
    if (*len < (int)(sizeof(uint8_t) * 6)) {
        return 0;
    }

#if __BYTE_ORDER__ == __BIG_ENDIAN
    *out = ((uint64_t)(*buf)[0] << 40) |
        ((uint64_t)(*buf)[1] << 32) |
        ((uint64_t)(*buf)[2] << 24) |
        ((uint64_t)(*buf)[3] << 16) |
        ((uint64_t)(*buf)[4] << 8) |
        (uint64_t)(*buf)[5];
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    *out = ((uint64_t)(*buf)[0]) |
        ((uint64_t)(*buf)[1] << 8) |
        ((uint64_t)(*buf)[2] << 16) |
        ((uint64_t)(*buf)[3] << 24) |
        ((uint64_t)(*buf)[4] << 32) |
        ((uint64_t)(*buf)[5] << 40);
#endif

    *buf += 6;
    *len -= 6;

    return 1;
}

/**
 * \brief Get the prefix value and advance the buffer.
 */
static inline int DNP3ReadPrefix(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t *out)
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
            DNP3ReadUint32(buf, len, out);
            break;
        case sizeof(uint16_t):
            DNP3ReadUint16(buf, len, (uint16_t *)out);
            break;
        case sizeof(uint8_t):
            DNP3ReadUint8(buf, len, (uint8_t *)out);
            break;
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
static int DNP3AddItem(DNP3PointList *list, void *object,
    uint32_t index, uint8_t prefix_code, uint32_t prefix)
{
    DNP3Point *point = SCCalloc(1, sizeof(*point));
    if (unlikely(point == NULL)) {
        return 0;
    }
    TAILQ_INSERT_TAIL(list, point, next);
    point->data = object;
    point->prefix = prefix;
    point->index = index;
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

/**
 * \brief Generic decoder for objects matching the signature of
 *     DNP3Object_UINT16.
 */
static int DNP3DecodeObject_UINT16(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3Object_UINT16 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint16(buf, len, &object->value0)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

/**
 * \brief Decoder for object 1:1.
 *
 * Object 1:1 is a list of bits where each bit is a point value.
 */
static int DNP3DecodeObjectG1V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG1V1 *object = NULL;
    int bytes = (count / 8) + 1;
    uint32_t prefix;
    uint8_t octet;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 8 && count; j++) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x1;

            if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
                goto error;
            }

            count--;
            index++;
        }
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

/**
 * \brief Decode object 1:2 and similar objects.
 */
static int DNP3DecodeObjectG1V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG1V2 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t flag;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }

        object->online = flag & 0x1;
        object->restart = (flag >> 1) & 0x1;
        object->comm_lost = (flag >> 2) & 0x1;
        object->remote_forced = (flag >> 3) & 0x1;
        object->local_forced = (flag >> 4) & 0x1;
        object->chatter_filter = (flag >> 5) & 0x1;
        object->reserved = (flag >> 6) & 0x1;
        object->state = (flag >> 7) & 0x3;

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
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
    DNP3PointList *items)
{
    DNP3ObjectG2V2 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t flag;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }

        object->online = flag & 0x1;
        object->restart = (flag >> 1) & 0x1;
        object->comm_lost = (flag >> 2) & 0x1;
        object->remote_forced = (flag >> 3) & 0x1;
        object->local_forced = (flag >> 4) & 0x1;
        object->chatter_filter = (flag >> 5) & 0x1;
        object->reserved = (flag >> 6) & 0x1;
        object->state = (flag >> 7) & 0x3;

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
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
    DNP3PointList *items)
{
    DNP3ObjectG3V1 *object = NULL;
    int bytes = (count / 4) + 1;
    uint32_t prefix;
    uint8_t octet;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        for (int j = 0; j < 4 && count; j += 2) {

            object = SCCalloc(1, sizeof(*object));
            if (unlikely(object == NULL)) {
                goto error;
            }

            object->state = (octet >> j) & 0x2;

            if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
                goto error;
            }

            count--;
            index++;
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
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG3V2 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t flag;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }

        object->online = flag & 0x1;
        object->restart = (flag >> 1) & 0x1;
        object->comm_lost = (flag >> 2) & 0x1;
        object->remote_forced = (flag >> 3) & 0x1;
        object->local_forced = (flag >> 4) & 0x1;
        object->chatter_filter = (flag >> 5) & 0x1;
        object->state = (flag >> 6) & 0x3;

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG12V1(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG12V1 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t flag;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        /* The first byte contains a couple values. */
        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }
        object->op_type = flag & 0xf;
        object->qu = (flag >> 4) & 0x1;
        object->cr = (flag >> 5) & 0x1;
        object->tcc = (flag >> 6) & 0x3;

        if (!DNP3ReadUint8(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->on_time)) {
            goto error;
        }

        if (!DNP3ReadUint32(buf, len, &object->off_time)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }
        object->status_code = flag & 0x7f;
        object->reserved = (flag >> 7) & 0x1;

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG20V1(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG20V1 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t octet;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        object->online = octet & 0x1;
        object->restart = (octet >> 1) & 0x1;
        object->comm_lost = (octet >> 2) & 0x1;
        object->remote_forced = (octet >> 3) & 0x1;
        object->local_forced = (octet >> 4) & 0x1;
        object->rollover = (octet >> 4) & 0x1;
        object->discontinuity = (octet >> 6) & 0x1;
        object->reserved = (octet >> 7) & 0x1;

        if (!DNP3ReadUint32(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG22V2(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG22V2 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t octet;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        object->online = octet & 0x1;
        object->restart = (octet >> 1) & 0x1;
        object->comm_lost = (octet >> 2) & 0x1;
        object->remote_forced = (octet >> 3) & 0x1;
        object->local_forced = (octet >> 4) & 0x1;
        object->rollover = (octet >> 4) & 0x1;
        object->discontinuity = (octet >> 6) & 0x1;
        object->reserved = (octet >> 7) & 0x1;

        if (!DNP3ReadUint16(buf, len, &object->count)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG30V2(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG30V2 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t flag;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &flag)) {
            goto error;
        }

        object->online = flag & 0x1;
        object->restart = (flag >> 1) & 0x1;
        object->comm_lost = (flag >> 2) & 0x1;
        object->remote_forced = (flag >> 3) & 0x1;
        object->local_forced = (flag >> 4) & 0x1;
        object->over_range = (flag >> 4) & 0x1;
        object->reference_err = (flag >> 6) & 0x1;
        object->reserved = (flag >> 7) & 0x1;

        if (!DNP3ReadUint16(buf, len, (uint16_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index++, prefix_code, prefix)) {
            goto error;
        }
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG30V4(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG30V4 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;

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

        if (!DNP3AddItem(items, object, index++, prefix_code, prefix)) {
            goto error;
        }
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

static int DNP3DecodeObjectG30V5(const uint8_t **buf, uint32_t *len,
    uint32_t prefix_code, uint32_t start, uint32_t count, DNP3PointList *items)
{
    DNP3ObjectG30V5 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t octet;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        object->online = octet & 0x1;
        object->restart = (octet >> 1) & 0x1;
        object->comm_lost = (octet >> 2) & 0x1;
        object->remote_forced = (octet >> 3) & 0x1;
        object->local_forced = (octet >> 4) & 0x1;
        object->over_range = (octet >> 5) & 0x1;
        object->reference_err = (octet >> 6) & 0x1;
        object->reserved = (octet >> 7) & 0x1;

        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index++, prefix_code, prefix)) {
            goto error;
        }
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
    DNP3PointList *items)
{
    DNP3ObjectG32V7 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;
    uint8_t octet;

    while (count--) {
        object = SCCalloc(1, sizeof(*object));
        if (unlikely(object == NULL)) {
            goto error;
        }

        if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
            goto error;
        }

        if (!DNP3ReadUint8(buf, len, &octet)) {
            goto error;
        }

        object->online = octet & 0x1;
        object->restart = (octet >> 1) & 0x1;
        object->comm_lost = (octet >> 2) & 0x1;
        object->remote_forced = (octet >> 3) & 0x1;
        object->local_forced = (octet >> 4) & 0x1;
        object->over_range = (octet >> 4) & 0x1;
        object->reference_err = (octet >> 6) & 0x1;
        object->reserved = (octet >> 7) & 0x1;

        if (!DNP3ReadUint32(buf, len, (uint32_t *)&object->value)) {
            goto error;
        }

        if (!DNP3ReadUint48(buf, len, &object->timestamp)) {
            goto error;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
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
    DNP3PointList *items)
{
    DNP3ObjectG50V1 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;

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

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
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
    DNP3PointList *items)
{
    DNP3ObjectG70V3 *object = NULL;
    uint32_t prefix;
    uint32_t index = start;

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

        if (object->filename_size) {
            memcpy(object->filename, *buf, object->filename_size);
            *buf += object->filename_size;
            *len -= object->filename_size;
        }

        if (!DNP3AddItem(items, object, index, prefix_code, prefix)) {
            goto error;
        }

        index++;
    }

    return 1;
error:
    if (object != NULL) {
        SCFree(object);
    }
    return 0;
}

/**
 * \brief Decode a DNP3 object.
 *
 * \retval 0 on success. On failure a positive integer corresponding
 *     to a DNP3 application layer event will be returned.
 */
int DNP3DecodeObject(int group, int variation, const uint8_t **buf,
    uint32_t *len, uint8_t prefix_code, uint32_t start,
    uint32_t count, DNP3PointList *items)
{
    int rc = 0;

    SCLogDebug("Decoding object %d:%d (buf=%p; len=%d, "
        "start=%"PRIu32", count=%"PRIu32")", group, variation, *buf, *len,
        start, count);

    switch (DNP3_OBJECT_CODE(group, variation)) {

        case DNP3_OBJECT_CODE(34, 1):
        case DNP3_OBJECT_CODE(52, 1):
        case DNP3_OBJECT_CODE(52, 2):
            rc = DNP3DecodeObject_UINT16(buf, len, prefix_code, start, count,
                items);
            break;

        case DNP3_OBJECT_CODE(1, 1):
        case DNP3_OBJECT_CODE(10, 1):
        case DNP3_OBJECT_CODE(80, 1):
            rc = DNP3DecodeObjectG1V1(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(1, 2):
        case DNP3_OBJECT_CODE(2, 1):
        case DNP3_OBJECT_CODE(10, 2):
            rc = DNP3DecodeObjectG1V2(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(2, 2):
            rc = DNP3DecodeObjectG2V2(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(3, 1):
            rc = DNP3DecodeObjectG3V1(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(3, 2):
        case DNP3_OBJECT_CODE(4, 1):
            rc = DNP3DecodeObjectG3V2(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(12, 1):
            rc = DNP3DecodeObjectG12V1(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(20, 1):
        case DNP3_OBJECT_CODE(21, 1):
        case DNP3_OBJECT_CODE(22, 1):
            rc = DNP3DecodeObjectG20V1(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(20, 2):
        case DNP3_OBJECT_CODE(21, 2):
        case DNP3_OBJECT_CODE(22, 2):
            rc = DNP3DecodeObjectG22V2(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(30, 1):
        case DNP3_OBJECT_CODE(30, 5):
        case DNP3_OBJECT_CODE(32, 1):
        case DNP3_OBJECT_CODE(32, 5):
        case DNP3_OBJECT_CODE(40, 1):
            rc = DNP3DecodeObjectG30V5(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(30, 2):
        case DNP3_OBJECT_CODE(32, 2):
        case DNP3_OBJECT_CODE(40, 2):
            rc = DNP3DecodeObjectG30V2(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(30, 4):
            rc = DNP3DecodeObjectG30V4(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(32, 3):
        case DNP3_OBJECT_CODE(32, 7):
            rc = DNP3DecodeObjectG32V3(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(50, 1):
        case DNP3_OBJECT_CODE(50, 3):
            rc = DNP3DecodeObjectG50V1(buf, len, prefix_code, start, count,
                items);
            break;
        case DNP3_OBJECT_CODE(60, 0):
        case DNP3_OBJECT_CODE(60, 1):
        case DNP3_OBJECT_CODE(60, 2):
        case DNP3_OBJECT_CODE(60, 3):
        case DNP3_OBJECT_CODE(60, 4):
            /* No data. */
            rc = 1;
            break;
        case DNP3_OBJECT_CODE(70, 3):
            rc = DNP3DecodeObjectG70V3(buf, len, prefix_code, start, count,
                items);
            break;
        default:
            return DNP3_DECODER_EVENT_UNKNOWN_OBJECT;
    }

    return rc ? 0 : DNP3_DECODER_EVENT_MALFORMED;
}
