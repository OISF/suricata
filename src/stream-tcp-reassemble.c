/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* TODO:
 * - segment insert fasttrack: most pkts are in order
 * - OS depended handling of overlaps, retrans, etc
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "eidps.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "threads.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-pool.h"
#include "util-unittest.h"
#include "util-print.h"

#include "stream-tcp-private.h"

#include "stream.h"

void *TcpSegmentAlloc(void *payload_len) {
    TcpSegment *seg = malloc(sizeof(TcpSegment));
    if (seg == NULL)
        return NULL;

    memset(seg, 0, sizeof(TcpSegment));

    seg->pool_size = *((u_int16_t *)payload_len);
    seg->payload_len = seg->pool_size;

    seg->payload = malloc(seg->payload_len);
    if (seg->payload == NULL) {
        free(seg);
        return NULL;
    }

    return seg;
}

void TcpSegmentFree(void *ptr) {
    if (ptr == NULL)
        return;

    TcpSegment *seg = (TcpSegment *)ptr;
    free(seg->payload);
    free(seg);
    return;
}

/* We define serveral pools with prealloced segments with fixed size
 * payloads. We do this to prevent having to do an malloc call for every
 * data segment we receive, which would be a large performance penalty.
 * The cost is in memory of course. */
#define segment_pool_num 8
static u_int16_t segment_pool_pktsizes[segment_pool_num] = { 4, 16, 112, 248, 512, 768, 1448, 0xffff };
static u_int16_t segment_pool_poolsizes[segment_pool_num] = { 1024, 1024, 1024, 1024, 4096, 4096, 1024, 128 };
static Pool *segment_pool[segment_pool_num];
static pthread_mutex_t segment_pool_mutex[segment_pool_num];
/* index to the right pool for all packet sizes. */
static u_int16_t segment_pool_idx[65536]; /* O(1) lookups of the pool */

int StreamTcpReassembleInit(void) {
    StreamMsgQueuesInit();

    u_int16_t u16 = 0;
    for (u16 = 0; u16 < segment_pool_num; u16++) {
        segment_pool[u16] = PoolInit(segment_pool_poolsizes[u16], segment_pool_poolsizes[u16]/2, TcpSegmentAlloc, (void *)&segment_pool_pktsizes[u16], TcpSegmentFree);
        pthread_mutex_init(&segment_pool_mutex[u16], NULL);
    }

    u_int16_t idx = 0;
    u16 = 0;
    while (1) {
        if (idx <= segment_pool_pktsizes[u16]) {
            segment_pool_idx[idx] = u16;
            if (segment_pool_pktsizes[u16] == idx)
                u16++;
        }

        if (idx == 0xffff)
            break;

        idx++;
    }

    /*
    printf("pkt 0    : idx %u\n", segment_pool_idx[0]);
    printf("pkt 1    : idx %u\n", segment_pool_idx[1]);
    printf("pkt 1200 : idx %u\n", segment_pool_idx[1200]);
    printf("pkt 32   : idx %u\n", segment_pool_idx[32]);
    printf("pkt 1448 : idx %u\n", segment_pool_idx[1448]);
    printf("pkt 1449 : idx %u\n", segment_pool_idx[1449]);
    printf("pkt 65534: idx %u\n", segment_pool_idx[65534]);
    printf("pkt 65535: idx %u\n", segment_pool_idx[65535]);
    */

    return 0;
}

static int ReassembleInsertSegment(TcpStream *stream, TcpSegment *seg) {
    TcpSegment *list_seg = stream->seg_list, *prev_seg = NULL;
    if (list_seg == NULL) {
        printf("ReassembleInsertSegment: empty list, inserting %u, len %u\n", seg->seq, seg->payload_len);
        stream->seg_list = seg;
        return 0;
    }

    for ( ; list_seg != NULL; prev_seg = list_seg, list_seg = list_seg->next) {
            printf("ReassembleInsertSegment: seg %p, list_seg %p, list_seg->next %p\n", seg, list_seg, list_seg->next);

        /* seg is entirely before list_seg */
        if (SEQ_LT(seg->seq, list_seg->seq) &&
            SEQ_LT((seg->seq + seg->payload_len), list_seg->seq)) {

            printf("ReassembleInsertSegment: before list seg: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);
            seg->next = list_seg;
            if (prev_seg == NULL) stream->seg_list = seg;
            else prev_seg->next = seg;
            return 0;

        /* seg partly overlaps with list_seg, starts before, ends on list seq */
        } else if (SEQ_LT(seg->seq, list_seg->seq) &&
                   SEQ_EQ((seg->seq + seg->payload_len), list_seg->seq)) {

            /* XXX depends on target OS */
            printf("ReassembleInsertSegment: starts before list seg, ends on list seq: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg partly overlaps with list_seg, starts before, ends inside */
        } else if (SEQ_LT(seg->seq, list_seg->seq) &&
                   SEQ_GT((seg->seq + seg->payload_len), list_seg->seq) &&
                   SEQ_LT((seg->seq + seg->payload_len),
                          (list_seg->seq+list_seg->payload_len))) {

            /* XXX depends on target OS */
            printf("ReassembleInsertSegment: starts before list seg, ends inside list: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg fully overlaps list_seg, starts before, at end point */
        } else if (SEQ_LT(seg->seq, list_seg->seq) &&
                   SEQ_EQ((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts before list seg, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg fully overlaps list_seg, starts before, ends after list endpoint */
        } else if (SEQ_LT(seg->seq, list_seg->seq) &&
                   SEQ_GT((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts before list seg, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts at seq, but end before list_seg end. */
        } else if (SEQ_EQ(seg->seq, list_seg->seq) &&
                   SEQ_LT((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts at list seq, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts at seq, ends at seq, retransmission. */
        } else if (SEQ_EQ(seg->seq, list_seg->seq) &&
                   SEQ_EQ((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {
            /* check csum, ack, other differences? */
            printf("ReassembleInsertSegment: (retransmission) starts at list seq, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts at seq, ends beyond seq. */
        } else if (SEQ_EQ(seg->seq, list_seg->seq) &&
                   SEQ_GT((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts at list seq, ends beyond list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts after seq, before end, ends before seq. */
        } else if (SEQ_GT(seg->seq, list_seg->seq) &&
                   SEQ_LT((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts beyond list seq, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts after seq, before end, ends at seq. */
        } else if (SEQ_GT(seg->seq, list_seg->seq) &&
                   SEQ_EQ((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts beyond list seq, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts after seq, before end, ends beyond seq. */
        } else if (SEQ_GT(seg->seq, list_seg->seq) &&
                   SEQ_LT(seg->seq, list_seg->seq + list_seg->payload_len) &&
                   SEQ_GT((seg->seq + seg->payload_len),
                          (list_seg->seq + list_seg->payload_len))) {

            printf("ReassembleInsertSegment: starts beyond list seq, before list end, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);

        /* seg starts on end seq, ends beyond seq. */
        } else if (SEQ_EQ(seg->seq, (list_seg->seq + list_seg->payload_len)) &&
                   SEQ_GT((seg->seq + seg->payload_len),
                          (list_seg->seq+list_seg->payload_len))) {
            if (list_seg->next == NULL) {
                printf("ReassembleInsertSegment: (normal insert) starts at list end, ends beyond list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);
                list_seg->next = seg;
                return 0;
            } else {
                printf("ReassembleInsertSegment: (normal, inspect more of the list) starts at list seq, ends beyond list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);
            }

        /* seg starts beyond end seq, ends beyond seq. */
        } else if (SEQ_GT(seg->seq, (list_seg->seq + list_seg->payload_len)) &&
                   SEQ_GT((seg->seq + seg->payload_len),
                          (list_seg->seq+list_seg->payload_len))) {
            printf("ReassembleInsertSegment: starts beyond list end, ends after list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u (%u)\n", seg->seq, list_seg->seq, list_seg->payload_len, list_seg->seq+list_seg->payload_len);

            if (list_seg->next == NULL) {
                list_seg->next = seg;
                return 0;
            }
        }
    }
    return 0;
}

int StreamTcpReassembleHandleSegmentHandleData (TcpSession *ssn, TcpStream *stream, Packet *p) {
    u_int16_t idx = segment_pool_idx[p->payload_len];
    //printf("StreamTcpReassembleHandleSegmentHandleData: idx %u for payload_len %u\n", idx, p->payload_len);

    mutex_lock(&segment_pool_mutex[idx]);
    //printf("StreamTcpReassembleHandleSegmentHandleData: mutex locked, getting data from pool %p\n", segment_pool[idx]);
    TcpSegment *seg = (TcpSegment *)PoolGet(segment_pool[idx]);
    mutex_unlock(&segment_pool_mutex[idx]);

    if (seg == NULL) {
        return -1;
    }
    //printf("StreamTcpReassembleHandleSegmentHandleData: seg %p, seg->pool_size %u\n", seg, seg->pool_size);

    memcpy(seg->payload, p->payload, p->payload_len);
    seg->payload_len = p->payload_len;
    seg->seq = TCP_GET_SEQ(p);
    seg->next = NULL;

    ReassembleInsertSegment(stream, seg);
    return 0;
}

/* initialize the first msg */
static void StreamTcpSetupInitMsg(Packet *p, StreamMsg *smsg) {
    smsg->flags |= STREAM_START;

    if (p->flowflags & FLOW_PKT_TOSERVER) {
        COPY_ADDRESS(&p->flow->src,&smsg->data.src_ip);
        COPY_ADDRESS(&p->flow->dst,&smsg->data.dst_ip);
        COPY_PORT(p->flow->sp,smsg->data.src_port);
        COPY_PORT(p->flow->dp,smsg->data.dst_port);

        smsg->flags |= STREAM_TOSERVER;
    } else {
        COPY_ADDRESS(&p->flow->dst,&smsg->data.src_ip);
        COPY_ADDRESS(&p->flow->src,&smsg->data.dst_ip);
        COPY_PORT(p->flow->dp,smsg->data.src_port);
        COPY_PORT(p->flow->sp,smsg->data.dst_port);

        smsg->flags |= STREAM_TOCLIENT;
    }
}

int StreamTcpReassembleHandleSegmentUpdateACK (TcpSession *ssn, TcpStream *stream, Packet *p) {
    if (stream->seg_list == NULL)
        return 0;

    printf("StreamTcpReassembleHandleSegmentUpdateACK: start\n");

    StreamMsg *smsg = NULL;
    char remove = FALSE;
    u_int16_t smsg_offset = 0;
    u_int16_t payload_offset = 0;
    u_int16_t payload_len = 0;
    TcpSegment *seg = stream->seg_list;

    /* check if we have enough data to send to l7 */
    if (p->flowflags & FLOW_PKT_TOSERVER) {
        if (stream->ra_base_seq == stream->isn) {
            if (StreamMsgQueueGetMinInitChunkLen(STREAM_TOSERVER) >
                (stream->last_ack - stream->ra_base_seq))
                return 0;
        } else {
            if (StreamMsgQueueGetMinChunkLen(STREAM_TOSERVER) >
                (stream->last_ack - stream->ra_base_seq))
                return 0;
        }
    } else {
        if (stream->ra_base_seq == stream->isn) {
            if (StreamMsgQueueGetMinInitChunkLen(STREAM_TOCLIENT) >
                (stream->last_ack - stream->ra_base_seq))
                return 0;
        } else {
            if (StreamMsgQueueGetMinChunkLen(STREAM_TOCLIENT) >
                (stream->last_ack - stream->ra_base_seq))
                return 0;
        }
    }

    for ( ; seg != NULL && SEQ_LT(seg->seq,stream->last_ack); ) {
        printf("StreamTcpReassembleHandleSegmentUpdateACK: seg %p\n", seg);

        /* if the segment ends beyond ra_base_seq we need to consider it */
        if (SEQ_GEQ((seg->seq + seg->payload_len),stream->ra_base_seq)) {
            /* get a message */
            if (smsg == NULL) {
                smsg = StreamMsgGetFromPool();
                if (smsg == NULL) {
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: couldn't "
                           "get a stream msg from the pool\n");
                    return -1;
                }

                smsg_offset = 0;

                if (stream->ra_base_seq == stream->isn) {
                    StreamTcpSetupInitMsg(p, smsg);
                }
                smsg->data.data_len = 0;
                smsg->flow = p->flow;
            }

            /* handle segments partly before ra_base_seq */
            if (SEQ_GT(stream->ra_base_seq, seg->seq)) {
                payload_offset = stream->ra_base_seq - seg->seq;

                if (SEQ_LT(stream->last_ack,(seg->seq + seg->payload_len))) {
                    payload_len = ((seg->seq + seg->payload_len) - stream->last_ack) - payload_offset;
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: starts "
                            "before ra_base, ends beyond last_ack, payload_offset %u, "
                            "payload_len %u\n", payload_offset, payload_len);
                } else {
                    payload_len = seg->payload_len - payload_offset;
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: starts "
                           "before ra_base, ends normal, payload_offset %u, "
                           "payload_len %u\n", payload_offset, payload_len);
                }
            /* handle segments after ra_base_seq */
            } else {
                payload_offset = 0;

                if (SEQ_LT(stream->last_ack,(seg->seq + seg->payload_len))) {
                    payload_len = stream->last_ack - seg->seq;
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: start "
                           "fine, ends beyond last_ack, payload_offset %u, "
                           "payload_len %u\n", payload_offset, payload_len);
                } else {
                    payload_len = seg->payload_len;
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: normal "
                           "(smsg_offset %u), payload_offset %u, payload_len %u\n",
                            smsg_offset, payload_offset, payload_len);
                }
            }

            u_int16_t copy_size = sizeof(smsg->data.data) - smsg_offset;
            if (copy_size > payload_len) {
                copy_size = payload_len;
            }
            printf("StreamTcpReassembleHandleSegmentUpdateACK: normal -- "
                   "copy_size %u (payload %u)\n", copy_size, payload_len);

            memcpy(smsg->data.data + smsg_offset, seg->payload + payload_offset, copy_size);

            smsg_offset += copy_size;
            stream->ra_base_seq += copy_size;
            smsg->data.data_len += copy_size;

            if (copy_size < payload_len) {
                printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                       "copy_size %u < %u\n", copy_size, payload_len);

                StreamMsgPutInQueue(smsg);
                smsg = NULL;
                payload_offset = copy_size + payload_offset;
                printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                       "payload_offset %u\n", payload_offset);

                /* we need a while loop here as the packets theoretically can be 64k */

                while (remove == FALSE) {
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                           "new msg at offset %u, payload_len %u\n", payload_offset, payload_len);

                    /* get a new message */
                    smsg = StreamMsgGetFromPool();
                    if (smsg == NULL) {
                        printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                               "couldn't get a stream msg from the pool (while loop)\n");
                        return -1;
                    }
                    smsg_offset = 0;
                    smsg->data.data_len = 0;
                    smsg->flow = p->flow;

                    copy_size = sizeof(smsg->data.data) - smsg_offset;
                    if (copy_size > (payload_len - payload_offset)) {
                        copy_size = (payload_len - payload_offset);
                    }

                    printf("StreamTcpReassembleHandleSegmentUpdateACK: copy "
                           "payload_offset %u, smsg_offset %u, copy_size %u\n",
                           payload_offset, smsg_offset, copy_size);

                    memcpy(smsg->data.data + smsg_offset, seg->payload + payload_offset, copy_size);
                    smsg_offset += copy_size;
                    stream->ra_base_seq += copy_size;
                    smsg->data.data_len += copy_size;

                    printf("StreamTcpReassembleHandleSegmentUpdateACK: copied "
                           "payload_offset %u, smsg_offset %u, copy_size %u\n",
                            payload_offset, smsg_offset, copy_size);

                    if ((copy_size + payload_offset) < payload_len) {
                        payload_offset += copy_size;
                        printf("StreamTcpReassembleHandleSegmentUpdateACK: loop not done\n");
                    } else {
                        printf("StreamTcpReassembleHandleSegmentUpdateACK: loop done\n");
                        payload_offset = 0;
                        remove = TRUE;
                    }
                }
            } else {
                payload_offset = 0;
                remove = TRUE;
            }
        }

        TcpSegment *next_seg = seg->next;

        /* done with this segment, return it to the pool */
        if (remove == TRUE) {
            printf("StreamTcpReassembleHandleSegmentUpdateACK: removing seg %p, "
                   "seg->next %p\n", seg, seg->next);
            stream->seg_list = seg->next;

            u_int16_t idx = segment_pool_idx[seg->pool_size];
            mutex_lock(&segment_pool_mutex[idx]);
            //printf("StreamTcpReassembleHandleSegmentHandleData: mutex locked, getting data from pool %p\n", segment_pool[idx]);
            PoolReturn(segment_pool[idx], (void *)seg);
            mutex_unlock(&segment_pool_mutex[idx]);

            remove = FALSE;
        }

        seg = next_seg;
    }

    /* put the partly filled smsg in the queue to the l7 handler */
    if (smsg != NULL) {
        StreamMsgPutInQueue(smsg);
        smsg = NULL;
    }

    return 0;
}

int StreamTcpReassembleHandleSegment (TcpSession *ssn, TcpStream *stream, Packet *p) {
    /* handle ack received */
    StreamTcpReassembleHandleSegmentUpdateACK(ssn, stream, p);

    if (p->payload_len > 0) {
        StreamTcpReassembleHandleSegmentHandleData(ssn, stream, p);
    }

    return 0;
}

/* Initialize the l7data ptr in the TCP session used
 * by the L7 Modules for data storage.
 *
 * ssn = TcpSesssion
 * cnt = number of items in the array
 *
 * XXX use a pool?
 */
void StreamL7DataPtrInit(TcpSession *ssn, u_int8_t cnt) {
    if (cnt == 0)
        return;

    ssn->l7data = (void **)malloc(sizeof(void *) * cnt);
    if (ssn->l7data != NULL) {
        u_int8_t u;
        for (u = 0; u < cnt; u++) {
            ssn->l7data[u] = NULL;
        }
    }
}

