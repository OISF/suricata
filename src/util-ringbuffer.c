#include "suricata-common.h"
#include "suricata.h"
#include "util-ringbuffer.h"

/* Multi Reader, Single Writer, 8 bits */

RingBufferMrSw8 *RingBufferMrSw8Init(void) {
    RingBufferMrSw8 *rb = SCMalloc(sizeof(RingBufferMrSw8));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrSw8));
    return rb;
}

void RingBufferMrSw8Destroy(RingBufferMrSw8 *rb) {
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
void *RingBufferMrSw8Get(RingBufferMrSw8 *rb) {
    void *ptr;
    /** local pointer for data races. If __sync_bool_compare_and_swap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
    while (rb->read == rb->write) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
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
int RingBufferMrSw8Put(RingBufferMrSw8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
    while ((rb->write + 1) == rb->read) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(1);
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    return 0;
}

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
        if (rb->shutdown != 0)
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
        if (rb->shutdown != 0)
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
        if (rb->shutdown != 0)
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
        if (rb->shutdown != 0)
            return -1;

        usleep(1);
    }

    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    return 0;
}

/* Multi Reader, Multi Writer, 8 bits */

RingBufferMrMw8 *RingBufferMrMw8Init(void) {
    RingBufferMrMw8 *rb = SCMalloc(sizeof(RingBufferMrMw8));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrMw8));

    SCSpinInit(&rb->spin, 0);
    return rb;
}

void RingBufferMrMw8Destroy(RingBufferMrMw8 *rb) {
    if (rb != NULL) {
        SCSpinDestroy(&rb->spin);
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
void *RingBufferMrMw8Get(RingBufferMrMw8 *rb) {
    void *ptr;
    /** local pointer for data races. If __sync_bool_compare_and_swap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
    while (rb->read == rb->write) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
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
 *  \brief put a ptr in the RingBuffer.
 *
 *  As we support multiple writers we need to protect 2 things:
 *   1. writing the ptr to the array
 *   2. incrementing the rb->write idx
 *
 *  We can't do both at the same time in one atomic operation, so
 *  we need to (spin) lock it. We do increment rb->write atomically
 *  after that, so that we don't need to use the lock in our *Get
 *  function.
 *
 *  \param rb the ringbuffer
 *  \param ptr ptr to store
 *
 *  \retval 0 ok
 *  \retval -1 wait loop interrupted because of engine flags
 */
int RingBufferMrMw8Put(RingBufferMrMw8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
retry:
    while ((rb->write + 1) == rb->read) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(1);
    }

    /* get our lock */
    SCSpinLock(&rb->spin);
    /* if while we got our lock the buffer changed, we need to retry */
    if ((rb->write + 1) == rb->read) {
        SCSpinUnlock(&rb->spin);
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", rb->write, ptr);

    /* update the ring buffer */
    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    SCSpinUnlock(&rb->spin);
    SCLogDebug("ptr %p, done", ptr);
    return 0;
}

/* Multi Reader, Multi Writer, 16 bits */

RingBufferMrMw *RingBufferMrMwInit(void) {
    RingBufferMrMw *rb = SCMalloc(sizeof(RingBufferMrMw));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrMw));

    SCSpinInit(&rb->spin, 0);
    return rb;
}

void RingBufferMrMwDestroy(RingBufferMrMw *rb) {
    if (rb != NULL) {
        SCSpinDestroy(&rb->spin);
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
void *RingBufferMrMwGet(RingBufferMrMw *rb) {
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
        if (rb->shutdown != 0)
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
 *  \brief put a ptr in the RingBuffer.
 *
 *  As we support multiple writers we need to protect 2 things:
 *   1. writing the ptr to the array
 *   2. incrementing the rb->write idx
 *
 *  We can't do both at the same time in one atomic operation, so
 *  we need to (spin) lock it. We do increment rb->write atomically
 *  after that, so that we don't need to use the lock in our *Get
 *  function.
 *
 *  \param rb the ringbuffer
 *  \param ptr ptr to store
 *
 *  \retval 0 ok
 *  \retval -1 wait loop interrupted because of engine flags
 */
int RingBufferMrMwPut(RingBufferMrMw *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
retry:
    while ((rb->write + 1) == rb->read) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(1);
    }

    /* get our lock */
    SCSpinLock(&rb->spin);
    /* if while we got our lock the buffer changed, we need to retry */
    if ((rb->write + 1) == rb->read) {
        SCSpinUnlock(&rb->spin);
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", rb->write, ptr);

    /* update the ring buffer */
    rb->array[rb->write] = ptr;
    __sync_fetch_and_add(&rb->write, 1);
    SCSpinUnlock(&rb->spin);
    SCLogDebug("ptr %p, done", ptr);
    return 0;
}

