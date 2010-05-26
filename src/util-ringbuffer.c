#include "suricata-common.h"
#include "util-ringbuffer.h"

/* Multi Reader, Single Writer */

RingBufferMrSw *RingBufferMrSwInit(void) {
    RingBufferMrSw *rb = SCMalloc(sizeof(RingBufferMrSw));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrSw));

    return rb;
}

void RingBufferMrSwDestroy(RingBufferMrSw *rb) {
    if (rb == NULL) {
        SCFree(rb);
    }
}

void *RingBufferMrSwGet(RingBufferMrSw *rb) {
    void *ptr;
    /* counter for data races. If __sync_bool_compare_and_swap (CAS) fails,
     * we increase cnt, get a new ptr and try to do CAS again. We init it to
     * -1 so it's 0 when first used the do { } while() loop. */
    unsigned short readp = -1;
    /* buffer is empty, wait... */
retry:
    while (rb->read == rb->write) {
        usleep(1);
    }

    /* atomically update rb->read */
    readp += rb->read;
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
        if (rb->read == rb->write)
            goto retry;

        readp++;
        ptr = rb->array[readp];
    } while (!(__sync_bool_compare_and_swap(&rb->read, readp, (readp + 1))));

    SCLogDebug("ptr %p", ptr);
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer
 */
void RingBufferMrSwPut(RingBufferMrSw *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
    while ((rb->write + 1) == rb->read) {
        usleep(1);
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
}


/* Single Reader, Single Writer */

RingBufferSrSw *RingBufferSrSwInit(void) {
    RingBufferSrSw *rb = SCMalloc(sizeof(RingBufferSrSw));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferSrSw));

    return rb;
}

void RingBufferSrSwDestroy(RingBufferSrSw *rb) {
    if (rb == NULL) {
        SCFree(rb);
    }
}

void *RingBufferSrSwGet(RingBufferSrSw *rb) {
    void *ptr = NULL;

    /* buffer is empty, wait... */
    while (rb->read == rb->write) {
    }

    ptr = rb->array[rb->read];
    __sync_fetch_and_add(&rb->read, 1);

    return ptr;
}

void RingBufferSrSwPut(RingBufferSrSw *rb, void *ptr) {
    /* buffer is full, wait... */
    while ((rb->write + 1) == rb->read) {
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
}

