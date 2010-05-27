#ifndef __UTIL_RINGBUFFER_H__

/** \brief ring buffer api
 *
 *  Ring buffer api for a single writer and a single reader. It uses a
 *  read and write pointer. Only the read ptr needs atomic updating.
 */

#define RING_BUFFER_MRSW_SIZE 65536

/** Multiple Reader, Single Writer ring buffer, fixed at
 *  65536 items so we can use unsigned shorts that just
 *  wrap around */
typedef struct RingBufferMrSw_ {
    unsigned short write;  /**< idx where we put data */
    unsigned short read;   /**< idx where we read data */
    void *array[RING_BUFFER_MRSW_SIZE];
} RingBufferMrSw;

void *RingBufferMrSwGet(RingBufferMrSw *);
int RingBufferMrSwPut(RingBufferMrSw *, void *);
RingBufferMrSw *RingBufferMrSwInit(void);
void RingBufferMrSwDestroy(RingBufferMrSw *);

#define RING_BUFFER_SRSW_SIZE 65536

/** Single Reader, Single Writer ring buffer, fixed at
 *  65536 items so we can use unsigned shorts that just
 *  wrap around */
typedef struct RingBufferSrSw_ {
    unsigned short write;  /**< idx where we put data */
    unsigned short read;   /**< idx where we read data */
    void *array[RING_BUFFER_SRSW_SIZE];
} RingBufferSrSw;

void *RingBufferSrSwGet(RingBufferSrSw *);
int RingBufferSrSwPut(RingBufferSrSw *, void *);
RingBufferSrSw *RingBufferSrSwInit(void);
void RingBufferSrSwDestroy(RingBufferSrSw *);

#endif /* __UTIL_RINGBUFFER_H__ */

