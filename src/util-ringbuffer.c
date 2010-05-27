#include "suricata-common.h"
#include "suricata.h"
#include "util-ringbuffer.h"

/* suricata engine control flags */
extern uint8_t suricata_ctl_flags;

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
    if (rb != NULL) {
        SCFree(rb);
    }
}

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 */
void *RingBufferMrSwGet(RingBufferMrSw *rb) {
    void *ptr;
    /** local pointer for data races. If __sync_bool_compare_and_swap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
    while (rb->read == rb->write) {
        /* break out if the engine wants to shutdown */
        if (suricata_ctl_flags != 0)
            return NULL;

        usleep(1);
    }

    /* atomically update rb->read */
    readp = rb->read - 1;
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
int RingBufferMrSwPut(RingBufferMrSw *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
    while ((rb->write + 1) == rb->read) {
        /* break out if the engine wants to shutdown */
        if (suricata_ctl_flags != 0)
            return -1;

        usleep(1);
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    return 0;
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
    if (rb != NULL) {
        SCFree(rb);
    }
}

void *RingBufferSrSwGet(RingBufferSrSw *rb) {
    void *ptr = NULL;

    /* buffer is empty, wait... */
    while (rb->read == rb->write) {
        /* break out if the engine wants to shutdown */
        if (suricata_ctl_flags != 0)
            return NULL;

        usleep(1);
    }

    ptr = rb->array[rb->read];
    __sync_fetch_and_add(&rb->read, 1);

    return ptr;
}

int RingBufferSrSwPut(RingBufferSrSw *rb, void *ptr) {
    /* buffer is full, wait... */
    while ((rb->write + 1) == rb->read) {
        /* break out if the engine wants to shutdown */
        if (suricata_ctl_flags != 0)
            return -1;

        usleep(1);
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    return 0;
}

