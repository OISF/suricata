/**
 * Copyright (c) 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __CUDA_PACKET_BATCHER_H__
#define __CUDA_PACKET_BATCHER_H__

#include "suricata-common.h"

/* compile in, only if we have a CUDA enabled on this machine */
#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"

/* The min no of packets that we allot the buffer for.  We will make
 * this user configurable(yaml) based on the traffic they expect.  Either ways
 * for a low/medium traffic network with occasional sgh matches, we shouldn't
 * be enabling cuda.  We will only end up screwing performance */
#define SC_CUDA_PB_MIN_NO_OF_PACKETS 4000

/* the maximum payload size we're sending to the card (defined in decode.h) */
#define SC_CUDA_PB_MAX_PAYLOAD_SIZE CUDA_MAX_PAYLOAD_SIZE

/**
 * \brief Implement the template SCDQGenericQData to transfer the cuda
 *        packet buffer from the cuda batcher thread to the dispatcher
 *        thread using the queue SCDQDataQueue.
 */
typedef struct SCCudaPBPacketsBuffer_ {
    /* these members from the template SCDQGenericQData that have to be
     * compulsarily implemented */
    struct SCDQGenericQData_ *next;
    struct SCDQGenericQData_ *prev;
    /* if we want to consider this pointer as the head of a list, this var
     * holds the no of elements in the list */
    //uint16_t len;
    /* in case this data instance is the head of a list, we can refer the
     * bottomost instance directly using this var */
    //struct SCDQGenericaQData *bot;

    /* our own members from here on*/

    /* current count of packets held in packets_buffer.  nop = no of packets */
    uint32_t nop_in_buffer;
    /* the packets buffer.  We will assign buffer for SC_CUDA_PB_MIN_NO_OF_PACKETS
     * packets.  Basically the size of this buffer would be
     * SC_CUDA_PB_MIN_NO_OF_PACKETS * sizeof(SCCudaPBPacketDataForGPU), so that
     * we can hold mininum SC_CUDA_PB_MIN_NO_OF_PACKETS */
    uint8_t *packets_buffer;
    /* length of data buffered so far in packets_buffer, which would be sent
     * to the GPU.  We will need this to copy the buffered data from the
     * packets_buffer here on the host, to the buffer on the GPU */
    uint32_t packets_buffer_len;
    /* packet offset within the packets_buffer.  Each packet would be stored in
     * packets buffer at a particular offset.  This buffer would indicate the
     * offset of a packet inside the packet buffer.  We will allot space to hold
     * offsets for SC_CUDA_PB_MIN_NO_OF_PACKETS packets
     * \todo change it to holds offsets for more than SC_CUDA_PB_MIN_NO_OF_PACKETS
     * when we use the buffer to hold packets based on the remaining size in the
     * buffer rather than on a fixed limit like SC_CUDA_PB_MIN_NO_OF_PACKETS */
    uint32_t *packets_offset_buffer;

    /* the total packet payload lengths buffered so far.  We will need this to
     * transfer the total length of the results buffer that has to be transferred
     * back from the gpu */
    uint32_t packets_total_payload_len;
    /* the payload offsets for the different payload lengths buffered in.  For
     * example if we buffer 4 packets of lengths 3, 4, 5, 6, we will store four
     * offsets in the buffer {0, 3, 7, 12, 18} */
    uint32_t *packets_payload_offset_buffer;

    /* packet addresses for all the packets buffered in the packets_buffer.  We
     * will allot space to hold packet addresses for SC_CUDA_PB_MIN_NO_OF_PACKETS.
     * We will need this, so that the cuda mpm b2g dispatcher thread can inform
     * and store the b2g cuda mpm results for the packet*/
    Packet **packets_address_buffer;
} SCCudaPBPacketsBuffer;

/**
 * \brief Structure for each packet that is being batched to the GPU.
 */
typedef struct SCCudaPBPacketDataForGPU_ {
    /* holds B2gCudaCtx->m */
    unsigned int m;
    /* holds B2gCudaCtx->cuda_B2g */
    CUdeviceptr table;
    /* holds the length of the payload */
    unsigned int payload_len;
    /* holds the payload.  While we actually store the payload in the buffer,
     * we may not end up using the entire 1480 bytes if the payload is smaller */
    uint8_t payload[SC_CUDA_PB_MAX_PAYLOAD_SIZE];
} SCCudaPBPacketDataForGPU;

/**
 * \brief Same as struct SCCudaPBPacketDataForGPU_ except for the payload part.
 *        We will need this for calculating the size of the non-payload part
 *        of the packet data to be buffered.
 */
typedef struct SCCudaPBPacketDataForGPUNonPayload_ {
    /* holds B2gCudaCtx->m */
    unsigned int m;
    /* holds B2gCudaCtx->cuda_B2g */
    CUdeviceptr table;
    /* holds the length of the payload */
    unsigned int payload_len;
} SCCudaPBPacketDataForGPUNonPayload;

/**
 * \brief The cuda packet batcher threading context.
 */
typedef struct SCCudaPBThreadCtx_ {
    /* we need the detection engine context to retrieve the sgh while we start
     * receiving and batching the packets */
    DetectEngineCtx *de_ctx;

    /* packets buffer currently in use inside the cuda batcher thread */
    SCCudaPBPacketsBuffer *curr_pb;
} SCCudaPBThreadCtx;

SCCudaPBPacketsBuffer *SCCudaPBAllocSCCudaPBPacketsBuffer(void);
void SCCudaPBDeAllocSCCudaPBPacketsBuffer(SCCudaPBPacketsBuffer *);

void SCCudaPBSetBufferPacketThreshhold(uint32_t);
void SCCudaPBCleanUpQueuesAndBuffers(void);
void SCCudaPBSetUpQueuesAndBuffers(void);
void SCCudaPBKillBatchingPackets(void);

TmEcode SCCudaPBBatchPackets(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode SCCudaPBThreadInit(ThreadVars *, void *, void **);
TmEcode SCCudaPBThreadDeInit(ThreadVars *, void *);
void SCCudaPBThreadExitStats(ThreadVars *, void *);
void SCCudaPBRegisterTests(void);

void TmModuleCudaPacketBatcherRegister(void);

void *SCCudaPBTmThreadsSlot1(void *);

void SCCudaPBRunningTests(int);
void SCCudaPBSetProfile(char *);

#endif /* __SC_CUDA_SUPPORT__ */

#endif /* __CUDA_PACKET_BATCHER_H__ */
