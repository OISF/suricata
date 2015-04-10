
static int DNP3DecodeObjectG1V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG1V1 *object = NULL;
    int bytes = (count / 8) + 1;
    uint32_t prefix;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

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

static int DNP3DecodeObjectG1V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG1V2 *object = NULL;
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

static int DNP3DecodeObjectG2V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG2V1 *object = NULL;
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
    int bytes = (count / 8) + 1;
    uint32_t prefix;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

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
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG3V2 *object = NULL;
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

static int DNP3DecodeObjectG4V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG4V1 *object = NULL;
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

static int DNP3DecodeObjectG10V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG10V1 *object = NULL;
    int bytes = (count / 8) + 1;
    uint32_t prefix;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

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

static int DNP3DecodeObjectG10V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG10V2 *object = NULL;
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
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG12V1 *object = NULL;
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

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->opype = (octet >> 0) & 0xf;
            object->qu = (octet >> 4) & 0x1;
            object->cr = (octet >> 5) & 0x1;
            object->tcc = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint8(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->onime)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->offime)) {
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

static int DNP3DecodeObjectG12V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG12V2 *object = NULL;
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

        {
            uint8_t octet;
            if (!DNP3ReadUint8(buf, len, &octet)) {
                goto error;
            }
            object->opype = (octet >> 0) & 0xf;
            object->qu = (octet >> 4) & 0x1;
            object->cr = (octet >> 5) & 0x1;
            object->tcc = (octet >> 6) & 0x3;
        }
        if (!DNP3ReadUint8(buf, len, &object->count)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->onime)) {
            goto error;
        }
        if (!DNP3ReadUint32(buf, len, &object->offime)) {
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
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG20V1 *object = NULL;
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

static int DNP3DecodeObjectG21V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG21V1 *object = NULL;
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

static int DNP3DecodeObjectG22V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG22V1 *object = NULL;
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
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG22V2 *object = NULL;
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
            object->reserved = (octet >> 7) & 0x1;
        }
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

static int DNP3DecodeObjectG20V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG20V2 *object = NULL;
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
            object->reserved = (octet >> 7) & 0x1;
        }
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

static int DNP3DecodeObjectG21V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG21V2 *object = NULL;
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
            object->reserved = (octet >> 7) & 0x1;
        }
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

static int DNP3DecodeObjectG30V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG30V1 *object = NULL;
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
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG30V2 *object = NULL;
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

static int DNP3DecodeObjectG30V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG30V5 *object = NULL;
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

static int DNP3DecodeObjectG30V4(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
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

static int DNP3DecodeObjectG32V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG32V1 *object = NULL;
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

static int DNP3DecodeObjectG32V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG32V2 *object = NULL;
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

static int DNP3DecodeObjectG32V5(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG32V5 *object = NULL;
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

static int DNP3DecodeObjectG32V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG32V3 *object = NULL;
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

static int DNP3DecodeObjectG32V7(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG32V7 *object = NULL;
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

static int DNP3DecodeObjectG34V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG34V1 *object = NULL;
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

        if (!DNP3ReadUint16(buf, len, &object->deadband_value)) {
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

static int DNP3DecodeObjectG40V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG40V1 *object = NULL;
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

static int DNP3DecodeObjectG40V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG40V2 *object = NULL;
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

static int DNP3DecodeObjectG50V3(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG50V3 *object = NULL;
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

static int DNP3DecodeObjectG52V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG52V1 *object = NULL;
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

        if (!DNP3ReadUint16(buf, len, &object->delay_secs)) {
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

static int DNP3DecodeObjectG52V2(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG52V2 *object = NULL;
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

        if (!DNP3ReadUint16(buf, len, &object->delay_ms)) {
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
        if (object->filename_size > 0) {
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

static int DNP3DecodeObjectG80V1(const uint8_t **buf, uint32_t *len,
    uint8_t prefix_code, uint32_t start, uint32_t count,
    DNP3PointList *items)
{
    DNP3ObjectG80V1 *object = NULL;
    int bytes = (count / 8) + 1;
    uint32_t prefix;
    int index = start;

    if (!DNP3ReadPrefix(buf, len, prefix_code, &prefix)) {
        goto error;
    }

    for (int i = 0; i < bytes; i++) {

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


int DNP3DecodeObject2(int group, int variation, const uint8_t **buf,
    uint32_t *len, uint8_t prefix_code, uint32_t start,
    uint32_t count, DNP3PointList *items)
{
    int rc = 0;

    switch (DNP3_OBJECT_CODE(group, variation)) {
        case DNP3_OBJECT_CODE(1, 1):
            rc = DNP3DecodeObjectG1V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(1, 2):
            rc = DNP3DecodeObjectG1V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(2, 1):
            rc = DNP3DecodeObjectG2V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(2, 2):
            rc = DNP3DecodeObjectG2V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(3, 1):
            rc = DNP3DecodeObjectG3V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(3, 2):
            rc = DNP3DecodeObjectG3V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(4, 1):
            rc = DNP3DecodeObjectG4V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(10, 1):
            rc = DNP3DecodeObjectG10V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(10, 2):
            rc = DNP3DecodeObjectG10V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(12, 1):
            rc = DNP3DecodeObjectG12V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(12, 2):
            rc = DNP3DecodeObjectG12V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(20, 1):
            rc = DNP3DecodeObjectG20V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(21, 1):
            rc = DNP3DecodeObjectG21V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(22, 1):
            rc = DNP3DecodeObjectG22V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(22, 2):
            rc = DNP3DecodeObjectG22V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(20, 2):
            rc = DNP3DecodeObjectG20V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(21, 2):
            rc = DNP3DecodeObjectG21V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(30, 1):
            rc = DNP3DecodeObjectG30V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(30, 2):
            rc = DNP3DecodeObjectG30V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(30, 5):
            rc = DNP3DecodeObjectG30V5(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(30, 4):
            rc = DNP3DecodeObjectG30V4(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(32, 1):
            rc = DNP3DecodeObjectG32V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(32, 2):
            rc = DNP3DecodeObjectG32V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(32, 5):
            rc = DNP3DecodeObjectG32V5(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(32, 3):
            rc = DNP3DecodeObjectG32V3(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(32, 7):
            rc = DNP3DecodeObjectG32V7(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(34, 1):
            rc = DNP3DecodeObjectG34V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(40, 1):
            rc = DNP3DecodeObjectG40V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(40, 2):
            rc = DNP3DecodeObjectG40V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(50, 1):
            rc = DNP3DecodeObjectG50V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(50, 3):
            rc = DNP3DecodeObjectG50V3(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(52, 1):
            rc = DNP3DecodeObjectG52V1(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(52, 2):
            rc = DNP3DecodeObjectG52V2(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(70, 3):
            rc = DNP3DecodeObjectG70V3(buf,
                len, prefix_code, start, count, items);
            break;
        case DNP3_OBJECT_CODE(80, 1):
            rc = DNP3DecodeObjectG80V1(buf,
                len, prefix_code, start, count, items);
            break;
        default:
            return DNP3_DECODER_EVENT_UNKNOWN_OBJECT;
    }

    return rc ? 0 : DNP3_DECODER_EVENT_MALFORMED;
}
