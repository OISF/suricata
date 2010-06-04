/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Ringbuffer implementation that is lockless for the most part IF atomic
 * operations are available.
 *
 * Two sizes are implemented currently: 256 and 65536. Those sizes are chosen
 * for simplicity when working with the read and write indexes. Both can just
 * wrap around.
 *
 * Implemented are:
 * Single reader, single writer (lockless)
 * Multi reader, single writer (lockless)
 * Multi reader, multi writer (partly locked)
 */
#include "suricata-common.h"
#include "suricata.h"
#include "util-ringbuffer.h"
#include "util-atomic.h"


#define USLEEP_TIME 5

/* Multi Reader, Single Writer, 8 bits */

RingBufferMrSw8 *RingBufferMrSw8Init(void) {
    RingBufferMrSw8 *rb = SCMalloc(sizeof(RingBufferMrSw8));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrSw8));

    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);

    return rb;
}

void RingBufferMrSw8Destroy(RingBufferMrSw8 *rb) {
    if (rb != NULL) {
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

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
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
    while (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return NULL;

        usleep(USLEEP_TIME);
    }

    /* atomically update rb->read */
    readp = SC_ATOMIC_GET(rb->read) - 1;
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
        if (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write))
            goto retry;

        readp++;
        ptr = rb->array[readp];
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));

    SCLogDebug("ptr %p", ptr);
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer
 */
int RingBufferMrSw8Put(RingBufferMrSw8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
    while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(USLEEP_TIME);
    }

    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    SC_ATOMIC_ADD(rb->write, 1);
    return 0;
}


/* Multi Reader, Single Writer */

RingBufferMrSw *RingBufferMrSwInit(void) {
    RingBufferMrSw *rb = SCMalloc(sizeof(RingBufferMrSw));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrSw));

    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);

    return rb;
}

void RingBufferMrSwDestroy(RingBufferMrSw *rb) {
    if (rb != NULL) {
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

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
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
    while (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return NULL;

        usleep(USLEEP_TIME);
    }

    /* atomically update rb->read */
    readp = SC_ATOMIC_GET(rb->read) - 1;
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
        if (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write))
            goto retry;

        readp++;
        ptr = rb->array[readp];
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));

    SCLogDebug("ptr %p", ptr);
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer
 */
int RingBufferMrSwPut(RingBufferMrSw *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
    while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(USLEEP_TIME);
    }

    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    SC_ATOMIC_ADD(rb->write, 1);
    return 0;
}


/* Single Reader, Single Writer */

RingBufferSrSw *RingBufferSrSwInit(void) {
    RingBufferSrSw *rb = SCMalloc(sizeof(RingBufferSrSw));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferSrSw));

    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);

    return rb;
}

void RingBufferSrSwDestroy(RingBufferSrSw *rb) {
    if (rb != NULL) {
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

        SCFree(rb);
    }
}

void *RingBufferSrSwGet(RingBufferSrSw *rb) {
    void *ptr = NULL;

    /* buffer is empty, wait... */
    while (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return NULL;

        usleep(USLEEP_TIME);
    }

    ptr = rb->array[SC_ATOMIC_GET(rb->read)];
    SC_ATOMIC_ADD(rb->read, 1);

    return ptr;
}

int RingBufferSrSwPut(RingBufferSrSw *rb, void *ptr) {
    /* buffer is full, wait... */
    while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(USLEEP_TIME);
    }

    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    SC_ATOMIC_ADD(rb->write, 1);
    return 0;
}

/* Multi Reader, Multi Writer, 8 bits */

RingBufferMrMw8 *RingBufferMrMw8Init(void) {
    RingBufferMrMw8 *rb = SCMalloc(sizeof(RingBufferMrMw8));
    if (rb == NULL) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBufferMrMw8));

    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);

    SCSpinInit(&rb->spin, 0);
    return rb;
}

void RingBufferMrMw8Destroy(RingBufferMrMw8 *rb) {
    if (rb != NULL) {
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

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
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
    while (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return NULL;

        usleep(USLEEP_TIME);
    }

    /* atomically update rb->read */
    readp = SC_ATOMIC_GET(rb->read) - 1;
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
        if (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write))
            goto retry;

        readp++;
        ptr = rb->array[readp];
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));

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
    while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(USLEEP_TIME);
    }

    /* get our lock */
    SCSpinLock(&rb->spin);
    /* if while we got our lock the buffer changed, we need to retry */
    if ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        SCSpinUnlock(&rb->spin);
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", SC_ATOMIC_GET(rb->write), ptr);

    /* update the ring buffer */
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    SC_ATOMIC_ADD(rb->write, 1);
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

    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);

    SCSpinInit(&rb->spin, 0);
    return rb;
}

void RingBufferMrMwDestroy(RingBufferMrMw *rb) {
    if (rb != NULL) {
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

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
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
    while (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return NULL;

        usleep(USLEEP_TIME);
    }

    /* atomically update rb->read */
    readp = SC_ATOMIC_GET(rb->read) - 1;
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
        if (SC_ATOMIC_GET(rb->read) == SC_ATOMIC_GET(rb->write))
            goto retry;

        readp++;
        ptr = rb->array[readp];
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));

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
    while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        usleep(USLEEP_TIME);
    }

    /* get our lock */
    SCSpinLock(&rb->spin);
    /* if while we got our lock the buffer changed, we need to retry */
    if ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        SCSpinUnlock(&rb->spin);
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", SC_ATOMIC_GET(rb->write), ptr);

    /* update the ring buffer */
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    SC_ATOMIC_ADD(rb->write, 1);
    SCSpinUnlock(&rb->spin);
    SCLogDebug("ptr %p, done", ptr);
    return 0;
}

