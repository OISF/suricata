/** Copyright (c) 2008 Victor Julien <victor@inliniac.net>
 *  Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Reference:
 * Judy Novak, Steve Sturges: Target-Based TCP Stream Reassembly August, 2007
 *
 * \todo segment insert fasttrack: most pkts are in order
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
#include "stream-tcp-reassemble.h"

#include "stream.h"

//#define DEBUG

/* prototypes */
static int HandleSegmentStartsBeforeListSegment(TcpStream *, TcpSegment *, TcpSegment *, TcpSegment *, u_int8_t);
static int HandleSegmentStartsAtSameListSegment(TcpStream *, TcpSegment *, TcpSegment *, TcpSegment *, u_int8_t);
static int HandleSegmentStartsAfterListSegment(TcpStream *, TcpSegment *, TcpSegment *, TcpSegment *, u_int8_t);
void StreamTcpSegmentDataReplace(TcpSegment *, TcpSegment *, u_int32_t, u_int16_t);
void StreamTcpSegmentDataCopy(TcpSegment *, TcpSegment *);
TcpSegment* StreamTcpGetSegment(u_int16_t);
void StreamTcpSegmentReturntoPool(TcpSegment *);
void StreamTcpCreateTestPacket(u_int8_t *, u_int8_t, u_int8_t);
static int StreamTcpCheckStreamContents(u_int8_t *, TcpStream *);

void *TcpSegmentAlloc(void *payload_len) {
    TcpSegment *seg = malloc(sizeof (TcpSegment));
    if (seg == NULL)
        return NULL;

    memset(seg, 0, sizeof (TcpSegment));

    seg->pool_size = *((u_int16_t *) payload_len);
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

    TcpSegment *seg = (TcpSegment *) ptr;
    free(seg->payload);
    free(seg);
    return;
}

/* We define serveral pools with prealloced segments with fixed size
 * payloads. We do this to prevent having to do an malloc call for every
 * data segment we receive, which would be a large performance penalty.
 * The cost is in memory of course. */
#define segment_pool_num 8
static u_int16_t segment_pool_pktsizes[segment_pool_num] = {4, 16, 112, 248, 512, 768, 1448, 0xffff};
static u_int16_t segment_pool_poolsizes[segment_pool_num] = {1024, 1024, 1024, 1024, 4096, 4096, 1024, 128};
static Pool *segment_pool[segment_pool_num];
static pthread_mutex_t segment_pool_mutex[segment_pool_num];
/* index to the right pool for all packet sizes. */
static u_int16_t segment_pool_idx[65536]; /* O(1) lookups of the pool */

int StreamTcpReassembleInit(void) {
    StreamMsgQueuesInit();

    u_int16_t u16 = 0;
    for (u16 = 0; u16 < segment_pool_num; u16++) {
        segment_pool[u16] = PoolInit(segment_pool_poolsizes[u16], segment_pool_poolsizes[u16] / 2, TcpSegmentAlloc, (void *) & segment_pool_pktsizes[u16], TcpSegmentFree);
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

#ifdef DEBUG
static void PrintList(TcpSegment *seg) {
    if (seg == NULL)
        return;

    u_int32_t next_seq = seg->seq;

    while (seg != NULL) {
        if (next_seq != seg->seq) {
            printf("PrintList: missing segment(s) for %u bytes of data\n", (seg->seq - next_seq));
        }

        printf("PrintList: seg %10u len %u\n", seg->seq, seg->payload_len);

        next_seq = seg->seq + seg->payload_len;
        seg = seg->next;
    }
}
#endif /* DEBUG */

/**
 *  \brief  Function to handle the insertion newly arrived segment,
 *          The packet is handled based on its target OS.
 *
 *  \param  stream  The given TCP stream to which this new segment belongs
 *  \param  seg     Newly arrived segment
 */

static int ReassembleInsertSegment(TcpStream *stream, TcpSegment *seg) {
    TcpSegment *list_seg = stream->seg_list;
    TcpSegment *prev_seg = NULL;
    u_int8_t os_policy = stream->os_policy;
    u_int8_t ret_value = 0;
    if (list_seg == NULL) {
#ifdef DEBUG
        printf("ReassembleInsertSegment: empty list, inserting seg %p seq %u, len %u\n", seg, seg->seq, seg->payload_len);
        //PrintRawDataFp(stdout, seg->payload, seg->payload_len);
#endif
        stream->seg_list = seg;
        seg->prev = NULL;
        return 0;
    }

    for (; list_seg != NULL; prev_seg = list_seg, list_seg = list_seg->next) {
#ifdef DEBUG
        printf("ReassembleInsertSegment: seg %p, list_seg %p, list_prev %p list_seg->next %p, segment length %u\n", seg, list_seg, list_seg->prev, list_seg->next, seg->payload_len);
        PrintRawDataFp(stdout, seg->payload, seg->payload_len);
        PrintRawDataFp(stdout, list_seg->payload, list_seg->payload_len);
#endif
        /* segment starts before list */
        if (SEQ_LT(seg->seq, list_seg->seq)) {
            /*seg is entirely before list_seg*/
            if (SEQ_LEQ((seg->seq + seg->payload_len), list_seg->seq)) {
#ifdef DEBUG
                printf("ReassembleInsertSegment: before list seg: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u\n", seg->seq, list_seg->seq, list_seg->payload_len);
#endif
                seg->next = list_seg;
                list_seg->prev = seg;
                if (prev_seg == NULL)
                    stream->seg_list = seg;
                else {
                    prev_seg->next = seg;
                    seg->prev = prev_seg;
                }
                /* To print the full stream upon arrival of packet with content as 0 (test pcap)
                   the variable should be DEBUG in to the final patch :) */
#ifdef DEBUG
                printf("seg is %u policy %u\n", ((u_int8_t) (seg->payload)), stream->os_policy);
                if (((u_int8_t) (seg->payload)) == 104) {
                    TcpSegment *temp;
                    for (temp = stream->seg_list; temp != NULL; temp = temp->next)
                        PrintRawDataFp(stdout, temp->payload, temp->payload_len);
                }
#endif
                return 0;
                /*seg overlap with nest seg(s)*/
            } else {
                ret_value = HandleSegmentStartsBeforeListSegment(stream, list_seg, seg, prev_seg, os_policy);
                if (ret_value == 1) {
                    ret_value = 0;
                    return 0;
                } else if (ret_value == -1) {
                    ret_value = 0;
                    return -1;
                }
            }

            /* seg starts at same sequence number as list_seg */
        } else if (SEQ_EQ(seg->seq, list_seg->seq)) {
            ret_value = HandleSegmentStartsAtSameListSegment(stream, list_seg, seg, prev_seg, os_policy);
            if (ret_value == 1) {
                ret_value = 0;
                return 0;
            } else if (ret_value == -1) {
                ret_value = 0;
                return -1;
            }

            /* seg starts at sequence number higher than list_seg */
        } else if (SEQ_GT(seg->seq, list_seg->seq)) {
            if (((SEQ_GEQ(seg->seq, (list_seg->seq + list_seg->payload_len)))) &&
                    SEQ_GT((seg->seq + seg->payload_len),
                    (list_seg->seq + list_seg->payload_len))) {
#ifdef DEBUG
                printf("ReassembleInsertSegment: starts beyond list end, ends after list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u (%u)\n", seg->seq, list_seg->seq, list_seg->payload_len, list_seg->seq + list_seg->payload_len);
#endif

                if (list_seg->next == NULL) {
                    list_seg->next = seg;
                    seg->prev = list_seg;
                    return 0;
                }
            } else {
                ret_value = HandleSegmentStartsAfterListSegment(stream, list_seg, seg, prev_seg, os_policy);
                if (ret_value == 1) {
                    ret_value = 0;
                    return 0;
                } else if (ret_value == -1) {
                    ret_value = 0;
                    return -1;
                }
            }
        }
    }
    return 0;
}

/**
 *  \brief  Function to handle the newly arrived segment, when newly arrived
 *          starts with the sequence number lower than the original segment and
 *          ends at different position relative to original segment.
 *          The packet is handled based on its target OS.
 *
 *  \param  list_seg    Original Segment in the stream
 *  \param  seg         Newly arrived segment
 *  \param  prev_seg    Previous segment in the stream segment list
 *  \param  os_policy   OS_POLICY of the given stream.
 */

static int HandleSegmentStartsBeforeListSegment(TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, TcpSegment *prev_seg, u_int8_t os_policy) {
    u_int16_t overlap = 0;
    u_int16_t packet_length;
    u_int32_t overlap_point;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;

    if (SEQ_GT((seg->seq + seg->payload_len), list_seg->seq) &&
            SEQ_LT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {

        end_before = TRUE;
        overlap = (list_seg->seq + list_seg->payload_len) - (seg->seq + seg->payload_len);
        overlap_point = list_seg->seq;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts before list seg, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
        /* seg fully overlaps list_seg, starts before, at end point */
    } else if (SEQ_EQ((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = list_seg->payload_len;
        end_same = TRUE;
        overlap_point = list_seg->seq;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts before list seg, ends at list end: list prev %p seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", list_seg->prev, seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
        /* seg fully overlaps list_seg, starts before, ends after list endpoint */
    } else if (SEQ_GT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = list_seg->payload_len;
        end_after = TRUE;
        overlap_point = list_seg->seq;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts before list seg, ends after list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
    }
    if (overlap > 0) {
        /*Handling case when the packet starts before the first packet in the list*/
        if (list_seg->prev == NULL) {
            packet_length = seg->payload_len + (list_seg->payload_len - overlap);
            //printf("entered here pkt len%u seg %u list %u\n", packet_length, seg->payload_len, list_seg->payload_len);
            TcpSegment *new_seg = StreamTcpGetSegment(packet_length);
            if (new_seg == NULL) {
                return -1;
            }
            new_seg->payload_len = packet_length;
            new_seg->seq = seg->seq;
            new_seg->next = list_seg->next;
            new_seg->prev = list_seg->prev;
            StreamTcpSegmentDataCopy(new_seg, list_seg);
            StreamTcpSegmentDataReplace(new_seg, seg, (seg->seq), (u_int16_t) (list_seg->seq - seg->seq));
            if (SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq + list_seg ->payload_len))) {
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq + list_seg->payload_len), (u_int16_t) (((seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len)) + 1));
            }
            StreamTcpSegmentReturntoPool(list_seg);
            list_seg = new_seg;
            stream->seg_list = list_seg;
        } else if (end_before == TRUE || end_same == TRUE) {
            /* Handling overlapping with more than one segment and filling gap*/
            if (SEQ_LEQ(seg->seq, (prev_seg->seq + prev_seg->payload_len))) {
                //printf("the diff is %u \n", (list_seg->seq - (prev_seg->seq + prev_seg->payload_len)));
                packet_length = list_seg->payload_len + (list_seg->seq - (prev_seg->seq + prev_seg->payload_len));
                //overlap += packet_length - list_seg->payload_len;
                TcpSegment *new_seg = StreamTcpGetSegment(packet_length);
                if (new_seg == NULL) {
                    return -1;
                }
                //printf("StreamTcpReassembleHandleSegmentHandleData: seg %p, seg->pool_size %u\n", seg, seg->pool_size);
                new_seg->payload_len = packet_length;
                if (SEQ_GT((prev_seg->seq + prev_seg->payload_len), seg->seq))
                    new_seg->seq = (prev_seg->seq + prev_seg->payload_len);
                else
                    new_seg->seq = seg->seq;
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;
                StreamTcpSegmentDataCopy(new_seg, list_seg);
                StreamTcpSegmentDataReplace(new_seg, seg, (prev_seg->seq + prev_seg->payload_len), (u_int16_t) (list_seg->seq - (prev_seg->seq + prev_seg->payload_len)));
                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                prev_seg->next = list_seg;
            }
        } else if (end_after == TRUE) {
            if (SEQ_LEQ((seg->seq + seg->payload_len), list_seg->next->seq)) {
                if (SEQ_GT(seg->seq, (prev_seg->seq + prev_seg->payload_len)))
                    packet_length = list_seg->payload_len + (list_seg->seq - seg->seq);
                else
                    packet_length = list_seg->payload_len + (list_seg->seq - (prev_seg->seq + prev_seg->payload_len));
                packet_length += (seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len);
                //printf("the diff is %u in after \n", packet_length);
                //overlap = packet_length;
                TcpSegment *new_seg = StreamTcpGetSegment(packet_length);
                if (new_seg == NULL) {
                    return -1;
                }
                new_seg->payload_len = packet_length;
                if (SEQ_GT((prev_seg->seq + prev_seg->payload_len), seg->seq))
                    new_seg->seq = (prev_seg->seq + prev_seg->payload_len);
                else
                    new_seg->seq = seg->seq;
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;
                StreamTcpSegmentDataCopy(new_seg, list_seg);
                StreamTcpSegmentDataReplace(new_seg, seg, (prev_seg->seq + prev_seg->payload_len), (u_int16_t) (list_seg->seq - (prev_seg->seq + prev_seg->payload_len)));
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq + list_seg->payload_len), (u_int16_t) ((seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len)));
                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                prev_seg->next = list_seg;
            }
        }

        switch (os_policy) {
            case OS_POLICY_BSD:
            case OS_POLICY_HPUX10:
            case OS_POLICY_IRIX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_WINDOWS2K3:
            case OS_POLICY_OLD_LINUX:
            case OS_POLICY_LINUX:
            case OS_POLICY_MACOS:
            case OS_POLICY_LAST:
#ifdef DEBUG
                printf("Replacing Old Data in starts before list seg list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                StreamTcpSegmentDataReplace(list_seg, seg, overlap_point, overlap);
                break;
            case OS_POLICY_SOLARIS:
            case OS_POLICY_HPUX11:
                if (end_after == TRUE || end_same == TRUE) {
                    StreamTcpSegmentDataReplace(list_seg, seg, overlap_point, overlap);
                    end_after = FALSE;
                } else {
#ifdef DEBUG
                    printf("Using Old Data in starts before list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                }
                break;
            case OS_POLICY_VISTA:
            case OS_POLICY_FIRST:
#ifdef DEBUG
                printf("Using Old Data in starts before list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                break;
            default:
                break;
        }
        /*To return from for loop as seg is finished with current list_seg
         no need to check further (improve performance)*/
        //PrintRawDataFp(stdout, list_seg->payload, list_seg->payload_len);
        if (end_before == TRUE || end_same == TRUE) {
            end_before = FALSE;
            end_same = FALSE;
            return 1;
        }
    }
    return 0;
}

/**
 *  \brief  Function to handle the newly arrived segment, when newly arrived
 *          starts with the same sequence number as the original segment and
 *          ends at different position relative to original segment.
 *          The packet is handled based on its target OS.
 *
 *  \param  list_seg    Original Segment in the stream
 *  \param  seg         Newly arrived segment
 *  \param  prev_seg    Previous segment in the stream segment list
 *  \param  os_policy   OS_POLICY of the given stream.
 */

static int HandleSegmentStartsAtSameListSegment(TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, TcpSegment *prev_seg, u_int8_t os_policy) {
    u_int16_t overlap = 0;
    u_int16_t packet_length;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;
    char handle_beyond = FALSE;

    if (SEQ_LT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = (list_seg->seq + list_seg->payload_len) - (seg->seq + seg->payload_len);
        end_before = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts at list seq, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is%u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif

        /* seg starts at seq, ends at seq, retransmission. */
    } else if (SEQ_EQ((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        /* check csum, ack, other differences? */
        overlap = seg->payload_len;
        end_same = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: (retransmission) starts at list seq, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is%u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
        /* seg starts at seq, ends beyond seq. */
    } else if (SEQ_GT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = list_seg->payload_len;
        end_after = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts at list seq, ends beyond list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is%u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
    }
    if (overlap > 0) {
        /*Handle the case when newly arrived segment ends after original
          segment and original segment is the last segment in the list
          or the next segment in the list starts after the end of new segment*/
        if (end_after == TRUE) {
            if (SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq + list_seg->payload_len))) {
                if (list_seg->next == NULL)
                    handle_beyond = TRUE;
                else if (SEQ_GT(list_seg->next->seq, (seg->seq + seg->payload_len)))
                    handle_beyond = TRUE;
            }
            if (handle_beyond == TRUE) {
                packet_length = seg->payload_len;
                TcpSegment *new_seg = StreamTcpGetSegment(packet_length);
                if (new_seg == NULL) {
                    return -1;
                }
                new_seg->payload_len = packet_length;
                new_seg->seq = list_seg->seq;
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;
                StreamTcpSegmentDataCopy(new_seg, list_seg);
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq + list_seg->payload_len), (u_int16_t) ((seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len)));
                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                if (prev_seg == NULL)
                    stream->seg_list = list_seg;
                else
                    prev_seg->next = list_seg;
            }
        }
        switch (os_policy) {
            case OS_POLICY_BSD:
            case OS_POLICY_HPUX10:
            case OS_POLICY_IRIX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_WINDOWS2K3:
            case OS_POLICY_VISTA:
            case OS_POLICY_MACOS:
            case OS_POLICY_FIRST:
#ifdef DEBUG
                printf("Using Old Data in starts at list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                break;
            case OS_POLICY_LINUX:
                if (end_after == TRUE) {
                    StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                } else
#ifdef DEBUG
                    printf("Using Old Data in starts at list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                break;
            case OS_POLICY_OLD_LINUX:
            case OS_POLICY_SOLARIS:
            case OS_POLICY_HPUX11:
                if (end_after == TRUE || end_same == TRUE) {
                    StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    end_after = FALSE;
                } else {
#ifdef DEBUG
                    printf("Using Old Data in starts at list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                }
                break;
            case OS_POLICY_LAST:
                StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                break;
            default:
                break;
        }
        if (end_before == TRUE || end_same == TRUE || handle_beyond == TRUE) {
            end_before = FALSE;
            end_same = FALSE;
            handle_beyond = FALSE;
            return 1;
        }
    }
    return 0;
}

/**
 *  \brief  Function to handle the newly arrived segment, when newly arrived
 *          starts with the sequence number higher than the original segment and
 *          ends at different position relative to original segment.
 *          The packet is handled based on its target OS.
 *
 *  \param  list_seg    Original Segment in the stream
 *  \param  seg         Newly arrived segment
 *  \param  prev_seg    Previous segment in the stream segment list
 *  \param  os_policy   OS_POLICY of the given stream.
 */

static int HandleSegmentStartsAfterListSegment(TcpStream *stream, TcpSegment *list_seg, TcpSegment *seg, TcpSegment *prev_seg, u_int8_t os_policy) {
    u_int16_t overlap = 0;
    u_int16_t packet_length;
    char end_before = FALSE;
    char end_after = FALSE;
    char end_same = FALSE;
    char handle_beyond = FALSE;

    if (SEQ_LT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = (list_seg->seq + list_seg->payload_len) - (seg->seq + seg->payload_len);
        end_before = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts beyond list seq, ends before list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
        /* seg starts after seq, before end, ends at seq. */
    } else if (SEQ_EQ((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = (list_seg->seq + list_seg->payload_len) - (seg->seq);
        end_same = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts beyond list seq, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
        /* seg starts after seq, before end, ends beyond seq. */
    } else if (SEQ_LT(seg->seq, list_seg->seq + list_seg->payload_len) &&
            SEQ_GT((seg->seq + seg->payload_len),
            (list_seg->seq + list_seg->payload_len))) {
        overlap = (seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len);
        end_after = TRUE;
#ifdef DEBUG
        printf("ReassembleInsertSegment: starts beyond list seq, before list end, ends at list end: seg->seq %u, list_seg->seq %u, list_seg->payload_len %u overlap is %u\n", seg->seq, list_seg->seq, list_seg->payload_len, overlap);
#endif
    }
    if (overlap > 0) {
        /*Handle the case when newly arrived segment ends after original
          segment and original segment is the last segment in the list*/
        if (end_after == TRUE) {
            if (SEQ_GT((seg->seq + seg->payload_len), (list_seg->seq + list_seg->payload_len))) {
                if (list_seg->next == NULL)
                    handle_beyond = TRUE;
                else if (SEQ_GT(list_seg->next->seq, (seg->seq + seg->payload_len)))
                    handle_beyond = TRUE;
            }
            if (handle_beyond == TRUE) {
                packet_length = (list_seg->payload_len + seg->payload_len) - overlap;
                TcpSegment *new_seg = StreamTcpGetSegment(packet_length);
                if (new_seg == NULL) {
                    return -1;
                }
                new_seg->payload_len = packet_length;
                if (SEQ_LT(list_seg->seq, seg->seq))
                    new_seg->seq = list_seg->seq;
                else
                    new_seg->seq = seg->seq;
                new_seg->next = list_seg->next;
                new_seg->prev = list_seg->prev;
                StreamTcpSegmentDataCopy(new_seg, list_seg);
                StreamTcpSegmentDataReplace(new_seg, seg, (list_seg->seq + list_seg->payload_len), (u_int16_t) ((seg->seq + seg->payload_len) - (list_seg->seq + list_seg->payload_len)));
                StreamTcpSegmentReturntoPool(list_seg);
                list_seg = new_seg;
                if (prev_seg == NULL)
                    stream->seg_list = list_seg;
                else
                    prev_seg->next = list_seg;
            }
        }
        switch (os_policy) {
            case OS_POLICY_BSD:
            case OS_POLICY_HPUX10:
            case OS_POLICY_IRIX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_WINDOWS2K3:
            case OS_POLICY_VISTA:
            case OS_POLICY_OLD_LINUX:
            case OS_POLICY_LINUX:
            case OS_POLICY_MACOS:
            case OS_POLICY_FIRST:
#ifdef DEBUG
                printf("Using Old Data in starts beyond list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                break;
            case OS_POLICY_SOLARIS:
            case OS_POLICY_HPUX11:
                if (end_after == TRUE) {
                    StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                    end_after = FALSE;
                } else {
#ifdef DEBUG
                    printf("Using Old Data in starts beyond list case, list_seg->seq %u policy %u overlap %u\n", list_seg->seq, os_policy, overlap);
#endif
                }
                break;
            case OS_POLICY_LAST:
                StreamTcpSegmentDataReplace(list_seg, seg, seg->seq, overlap);
                break;
            default:
                break;
        }
        if (end_before == TRUE || end_same == TRUE || handle_beyond == TRUE) {
            end_before = FALSE;
            end_same = FALSE;
            handle_beyond = FALSE;
            return 1;
        }
    }
    return 0;
}

int StreamTcpReassembleHandleSegmentHandleData(TcpSession *ssn, TcpStream *stream, Packet *p) {

    TcpSegment *seg = StreamTcpGetSegment(p->payload_len);
    if (seg == NULL)
        return -1;
    //printf("StreamTcpReassembleHandleSegmentHandleData: seg %p, seg->pool_size %u\n", seg, seg->pool_size);

    memcpy(seg->payload, p->payload, p->payload_len);
    seg->payload_len = p->payload_len;
    seg->seq = TCP_GET_SEQ(p);
    seg->next = NULL;

    if (ReassembleInsertSegment(stream, seg) != 0)
        return -1;
    return 0;
}

/* initialize the first msg */
static void StreamTcpSetupInitMsg(Packet *p, StreamMsg *smsg) {
    smsg->flags |= STREAM_START;

    if (p->flowflags & FLOW_PKT_TOSERVER) {
        COPY_ADDRESS(&p->flow->src, &smsg->data.src_ip);
        COPY_ADDRESS(&p->flow->dst, &smsg->data.dst_ip);
        COPY_PORT(p->flow->sp, smsg->data.src_port);
        COPY_PORT(p->flow->dp, smsg->data.dst_port);

        smsg->flags |= STREAM_TOSERVER;
    } else {
        COPY_ADDRESS(&p->flow->dst, &smsg->data.src_ip);
        COPY_ADDRESS(&p->flow->src, &smsg->data.dst_ip);
        COPY_PORT(p->flow->dp, smsg->data.src_port);
        COPY_PORT(p->flow->sp, smsg->data.dst_port);

        smsg->flags |= STREAM_TOCLIENT;
    }
}

int StreamTcpReassembleHandleSegmentUpdateACK(TcpSession *ssn, TcpStream *stream, Packet *p) {
    if (stream->seg_list == NULL)
        return 0;

#ifdef DEBUG
    printf("StreamTcpReassembleHandleSegmentUpdateACK: start\n");
#endif

    StreamMsg *smsg = NULL;
    char remove = FALSE;
    u_int16_t smsg_offset = 0;
    u_int16_t payload_offset = 0;
    u_int16_t payload_len = 0;
    TcpSegment *seg = stream->seg_list;
    u_int32_t next_seq = seg->seq;

    /* check if we have enough data to send to L7 */
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

#ifdef DEBUG
   PrintList(seg);
#endif

    /* loop through the segments and fill one or more msgs */
    for (; seg != NULL && SEQ_LT(seg->seq, stream->last_ack);) {
        printf("StreamTcpReassembleHandleSegmentUpdateACK: seg %p\n", seg);

        if (next_seq != seg->seq) {
            printf("StreamTcpReassembleHandleSegmentUpdateACK: expected next_seq %u, got %u. Seq gap?\n", next_seq, seg->seq);
            if (smsg != NULL)
                StreamMsgPutInQueue(smsg);
            return -1;
        }

        /* if the segment ends beyond ra_base_seq we need to consider it */
        if (SEQ_GT((seg->seq + seg->payload_len), stream->ra_base_seq)) {
            printf("StreamTcpReassembleHandleSegmentUpdateACK: seg->seq %u, seg->payload_len %u, stream->ra_base_seq %u\n",
                    seg->seq, seg->payload_len, stream->ra_base_seq);

            /* get a message
               XXX we need a setup function */
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
                if (smsg->flow)
                    smsg->flow->use_cnt++;
            }

            /* handle segments partly before ra_base_seq */
            if (SEQ_GT(stream->ra_base_seq, seg->seq)) {
                payload_offset = stream->ra_base_seq - seg->seq;

                if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {
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


                if (payload_offset > seg->payload_len) {
                    printf("BUG(%u): payload_offset %u > seg->payload_len %u. seg->seq %u, stream->ra_base_seq %u\n",
                            __LINE__, payload_offset, seg->payload_len, seg->seq, stream->ra_base_seq);
                    abort();
                }
                /* handle segments after ra_base_seq */
            } else {
                payload_offset = 0;

                if (SEQ_LT(stream->last_ack, (seg->seq + seg->payload_len))) {
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

            u_int16_t copy_size = sizeof (smsg->data.data) - smsg_offset;
            if (copy_size > payload_len) {
                copy_size = payload_len;
            }
            if (copy_size > sizeof (smsg->data.data)) {
                printf("BUG(%u): copy_size %u > sizeof(smsg->data.data) %u\n", __LINE__, copy_size, sizeof (smsg->data.data));
                abort();
            }
            printf("StreamTcpReassembleHandleSegmentUpdateACK: copy_size %u "
                    "(payload_len %u, payload_offset %u)\n", copy_size, payload_len, payload_offset);

            memcpy(smsg->data.data + smsg_offset, seg->payload + payload_offset, copy_size);

            smsg_offset += copy_size;
            stream->ra_base_seq += copy_size;
            smsg->data.data_len += copy_size;

            if (smsg->data.data_len == sizeof (smsg->data.data)) {
                StreamMsgPutInQueue(smsg);
                smsg = NULL;
            }

            if (copy_size < payload_len) {
                printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                        "copy_size %u < %u\n", copy_size, payload_len);

                payload_offset += copy_size;
                payload_len -= copy_size;
                if (payload_offset > seg->payload_len) {
                    printf("BUG(%u): payload_offset %u > seg->payload_len %u\n", __LINE__, payload_offset, seg->payload_len);
                    abort();
                }
                printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                        "payload_offset %u\n", payload_offset);

                /* we need a while loop here as the packets theoretically can be 64k */

                while (remove == FALSE) {
                    printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                            "new msg at offset %u, payload_len %u\n", payload_offset, payload_len);

                    /* get a new message
                       XXX we need a setup function */
                    smsg = StreamMsgGetFromPool();
                    if (smsg == NULL) {
                        printf("StreamTcpReassembleHandleSegmentUpdateACK: "
                                "couldn't get a stream msg from the pool (while loop)\n");
                        return -1;
                    }
                    smsg_offset = 0;
                    smsg->data.data_len = 0;
                    smsg->flow = p->flow;
                    if (smsg->flow)
                        smsg->flow->use_cnt++;

                    copy_size = sizeof (smsg->data.data) - smsg_offset;
                    if (copy_size > (seg->payload_len - payload_offset)) {
                        copy_size = (seg->payload_len - payload_offset);
                    }
                    if (copy_size > sizeof (smsg->data.data)) {
                        printf("BUG(%u): copy_size %u > sizeof(smsg->data.data) %u\n", __LINE__, copy_size, sizeof (smsg->data.data));
                        abort();
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

                    if (smsg->data.data_len == sizeof (smsg->data.data)) {
                        StreamMsgPutInQueue(smsg);
                        smsg = NULL;
                    }

                    if ((copy_size + payload_offset) < seg->payload_len) {
                        payload_offset += copy_size;
                        payload_len -= copy_size;

                        if (payload_offset > seg->payload_len) {
                            printf("BUG(%u): payload_offset %u > seg->payload_len %u\n", __LINE__, payload_offset, seg->payload_len);
                            abort();
                        }
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
            next_seq = seg->seq + seg->payload_len;

            printf("StreamTcpReassembleHandleSegmentUpdateACK: removing seg %p, "
                    "seg->next %p\n", seg, seg->next);
            stream->seg_list = seg->next;

            StreamTcpSegmentReturntoPool(seg);

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

int StreamTcpReassembleHandleSegment(TcpSession *ssn, TcpStream *stream, Packet *p) {
    /* handle ack received */
    if (StreamTcpReassembleHandleSegmentUpdateACK(ssn, stream, p) != 0)
        return -1;

    if (p->payload_len > 0) {
        if (StreamTcpReassembleHandleSegmentHandleData(ssn, stream, p) != 0)
            return -1;
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

    ssn->l7data = (void **) malloc(sizeof (void *) * cnt);
    if (ssn->l7data != NULL) {
        u_int8_t u;
        for (u = 0; u < cnt; u++) {
            ssn->l7data[u] = NULL;
        }
    }
}

/**
 *  \brief  Function to replace the data from a specific point up to
 *          given length.
 *
 *  \param  list_seg    Destination segment to replace the data
 *  \param  seg         Source segment of which data is to be written to destination
 *  \param  start_point Starting point to replace the data onwards
 *  \param  len         Length up to which data is need to be replaced
 */

void StreamTcpSegmentDataReplace(TcpSegment *list_seg, TcpSegment *seg, u_int32_t start_point, u_int16_t len) {
    u_int32_t i;
    u_int16_t cnt = 0;
    u_int16_t s_cnt = 0;
    for (i = list_seg->seq; i < (start_point + len) && s_cnt < seg->payload_len && cnt < list_seg->payload_len; i++) {
        if (i >= start_point) {
            //printf("i: %u start point: %u len %u \n", i, start_point, len);
            list_seg->payload[cnt] = seg->payload[s_cnt];
            s_cnt++;
        }
        cnt++;
    }
    //printf("print in data replace\n");
    //PrintRawDataFp(stdout, list_seg->payload, list_seg->payload_len);
}

/**
 *  \brief  Function to copy the data from list_seg to newly created new_seg.
 *
 *  \param  new_seg     Destination segment for copying the contents
 *  \param  list_seg    Source segment to copy its contents
 */

void StreamTcpSegmentDataCopy(TcpSegment *new_seg, TcpSegment *list_seg) {
    u_int32_t i;
    u_int16_t cnt = 0;
    u_int16_t s_cnt = 0;
    for (i = new_seg->seq; i <= (list_seg->seq + list_seg->payload_len) - 1; i++) {
        if (i >= list_seg->seq) {
            new_seg->payload[cnt] = list_seg->payload[s_cnt++];
            //printf("value is %X and list%X scnt%d new seq%u list seq %u i is %u pay lengt %u\n", new_seg->payload[cnt], list_seg->payload[s_cnt], s_cnt, new_seg->seq, list_seg->seq, i, list_seg->payload_len);
        }
        cnt++;
    }
    //PrintRawDataFp(stdout, new_seg->payload, new_seg->payload_len);
    //PrintRawDataFp(stdout,list_seg->payload,list_seg->payload_len);
}

/**
 *  \brief   Function to get the segment of required length from the pool.
 *
 *  \param   len    Length which tells the required size of needed segment.
 */

TcpSegment* StreamTcpGetSegment(u_int16_t len) {
    u_int16_t idx = segment_pool_idx[len];
    //printf("StreamTcpReassembleHandleSegmentHandleData: idx %u for payload_len %u\n", idx, p->payload_len);

    mutex_lock(&segment_pool_mutex[idx]);
    //printf("StreamTcpReassembleHandleSegmentHandleData: mutex locked, getting data from pool %p\n", segment_pool[idx]);
    TcpSegment *seg = (TcpSegment *) PoolGet(segment_pool[idx]);
    mutex_unlock(&segment_pool_mutex[idx]);

    return seg;
}

/**
 *  \brief   Function to return the segment back to the pool.
 *
 *  \param   seg    Segment which will be returned back to the pool.
 */

void StreamTcpSegmentReturntoPool(TcpSegment *seg) {

    u_int16_t idx = segment_pool_idx[seg->pool_size];
    mutex_lock(&segment_pool_mutex[idx]);
    //printf("StreamTcpReassembleHandleSegmentHandleData: mutex locked, getting data from pool %p\n", segment_pool[idx]);
    PoolReturn(segment_pool[idx], (void *) seg);
    mutex_unlock(&segment_pool_mutex[idx]);
}

#ifdef UNITTESTS
/** unit tests and it's support functions below */

/** \brief  The Function tests the reassembly engine working for different
 *          OSes supported. It includes all the OS cases and send
 *          crafted packets to test the reassembly.
 *
 *  \param  stream  The stream which will contain the reassembled segments
 */

static int StreamTcpReassembleStreamTest(TcpStream *stream) {

    TcpSession ssn;
    Packet p;
    ThreadVars tv;
    Flow f;
    u_int8_t payload[4];
    TCPHdr tcph;

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.isn = 10;
    ssn.server.isn = 30;
    f.stream = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    StreamTcpCreateTestPacket(payload, 0x41, 3); /*AAA*/
    p.tcph->th_seq = htonl(12);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x42, 2); /*BB*/
    p.tcph->th_seq = htonl(16);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x43, 3); /*CCC*/
    p.tcph->th_seq = htonl(18);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x44, 1); /*D*/
    p.tcph->th_seq = htonl(22);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x45, 2); /*EE*/
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x46, 3); /*FFF*/
    p.tcph->th_seq = htonl(27);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x47, 2); /*GG*/
    p.tcph->th_seq = htonl(30);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x48, 2); /*HH*/
    p.tcph->th_seq = htonl(32);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x49, 1); /*I*/
    p.tcph->th_seq = htonl(34);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4a, 4); /*JJJJ*/
    p.tcph->th_seq = htonl(13);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4b, 3); /*KKK*/
    p.tcph->th_seq = htonl(18);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4c, 3); /*LLL*/
    p.tcph->th_seq = htonl(21);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4d, 3); /*MMM*/
    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4e, 1); /*N*/
    p.tcph->th_seq = htonl(28);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4f, 1); /*O*/
    p.tcph->th_seq = htonl(31);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x50, 1); /*P*/
    p.tcph->th_seq = htonl(32);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x51, 2); /*QQ*/
    p.tcph->th_seq = htonl(34);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x30, 1); /*0*/
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;

    return 1;
}

/** \brief  The Function to create the packet with given payload, which is used
 *          to test the reassembly of the engine.
 *
 *  \param  payload     The variable used to store the payload contents of the
 *                      current packet.
 *  \param  value       The value which current payload will have for this packet
 *  \param  payload_len The length of the payload for current packet.
 */

void StreamTcpCreateTestPacket(u_int8_t *payload, u_int8_t value, u_int8_t payload_len) {
    u_int8_t i;
    for (i = 0; i < payload_len; i++)
        payload[i] = value;
    for (; i < 4; i++)
        payload = NULL;
}

/** \brief  The Function Checks the reassembled stream contents against predefined
 *          stream contents according to OS policy used.
 *
 *  \param  stream_policy   Predefined value of stream for different OS policies
 *  \param  stream          Reassembled stream returned from the reassembly functions
 */

static int StreamTcpCheckStreamContents(u_int8_t *stream_policy, TcpStream *stream) {
    TcpSegment *temp;
    u_int16_t i = 0;
    u_int8_t j;
    /*TcpSegment *temp1;
    printf("check stream !!\n");
    for (temp1 = stream->seg_list; temp1 != NULL; temp1 = temp1->next)
        PrintRawDataFp(stdout, temp1->payload, temp1->payload_len);*/

    for (temp = stream->seg_list; temp != NULL; temp = temp->next) {
        j = 0;
        for (; j < temp->payload_len; j++) {
            //printf("i is %u and len is %u stream %x and temp is %x\n", i, temp->payload_len, stream_policy[i], temp->payload[j]);
            if (stream_policy[i] == temp->payload[j]) {
                i++;
                continue;
            } else
                return 0;
        }
    }
    return 1;
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats before the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */

static int StreamTcpTestStartsBeforeListSegment(TcpStream *stream) {
    TcpSession ssn;
    Packet p;
    ThreadVars tv;
    Flow f;
    u_int8_t payload[4];
    TCPHdr tcph;

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.isn = 10;
    ssn.server.isn = 30;
    f.stream = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 1); /*B*/
    p.tcph->th_seq = htonl(16);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x44, 1); /*D*/
    p.tcph->th_seq = htonl(22);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x45, 2); /*EE*/
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x41, 2); /*AA*/
    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4a, 4); /*JJJJ*/
    p.tcph->th_seq = htonl(14);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4c, 3); /*LLL*/
    p.tcph->th_seq = htonl(21);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4d, 3); /*MMM*/
    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;

    return 1;
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats at the same seq no. as the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */

static int StreamTcpTestStartsAtSameListSegment(TcpStream *stream) {
    TcpSession ssn;
    Packet p;
    ThreadVars tv;
    Flow f;
    u_int8_t payload[4];
    TCPHdr tcph;

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.isn = 10;
    ssn.server.isn = 30;
    f.stream = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3); /*CCC*/
    p.tcph->th_seq = htonl(18);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x48, 2); /*HH*/
    p.tcph->th_seq = htonl(32);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x49, 1); /*I*/
    p.tcph->th_seq = htonl(34);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4b, 3); /*KKK*/
    p.tcph->th_seq = htonl(18);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4c, 4); /*LLLL*/
    p.tcph->th_seq = htonl(18);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 4;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x50, 1); /*P*/
    p.tcph->th_seq = htonl(32);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x51, 2); /*QQ*/
    p.tcph->th_seq = htonl(34);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;

    return 1;
}

/* \brief           The function craft packets to test the overlapping, where
 *                  new segment stats after the list segment.
 *
 *  \param  stream  The stream which will contain the reassembled segments and
 *                  also tells the OS policy used for reassembling the segments.
 */


static int StreamTcpTestStartsAfterListSegment(TcpStream *stream) {
    TcpSession ssn;
    Packet p;
    ThreadVars tv;
    Flow f;
    u_int8_t payload[4];
    TCPHdr tcph;

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.isn = 10;
    ssn.server.isn = 30;
    f.stream = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 2); /*AA*/
    p.tcph->th_seq = htonl(12);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x46, 3); /*FFF*/
    p.tcph->th_seq = htonl(27);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 3;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x47, 2); /*GG*/
    p.tcph->th_seq = htonl(30);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4a, 2); /*JJ*/
    p.tcph->th_seq = htonl(13);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 2;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4f, 1); /*O*/
    p.tcph->th_seq = htonl(31);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;
    StreamTcpCreateTestPacket(payload, 0x4e, 1); /*N*/
    p.tcph->th_seq = htonl(28);
    p.tcph->th_ack = htonl(31);
    p.payload = payload;
    p.payload_len = 1;
    if (StreamTcpReassembleHandleSegment(&ssn, stream, &p) == -1)
        return 0;

    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest01(void) {
    TcpStream stream;
    u_int8_t stream_before_bsd[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                      0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_bsd, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and BSD policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest02(void) {
    TcpStream stream;
    u_int8_t stream_same_bsd[8] = {0x43, 0x43, 0x43, 0x4c, 0x48, 0x48,
                                    0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_bsd, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest03(void) {
    TcpStream stream;
    u_int8_t stream_after_bsd[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                     0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_bsd, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and BSD policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest04(void) {
    TcpStream stream;
    u_int8_t stream_bsd[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x43,
                               0x43, 0x43, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                               0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_BSD;
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_bsd, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and VISTA policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest05(void) {
    TcpStream stream;
    u_int8_t stream_before_vista[10] = {0x4a, 0x41, 0x42, 0x4a, 0x4c, 0x44,
                                        0x4c, 0x4d, 0x45, 0x45};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_vista, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and VISTA policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest06(void) {
    TcpStream stream;
    u_int8_t stream_same_vista[8] = {0x43, 0x43, 0x43, 0x4c, 0x48, 0x48,
                                     0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_vista, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and BSD policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest07(void) {
    TcpStream stream;
    u_int8_t stream_after_vista[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                      0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_vista, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and VISTA policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest08(void) {
    TcpStream stream;
    u_int8_t stream_vista[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x42, 0x42, 0x43,
                                 0x43, 0x43, 0x4c, 0x44, 0x4c, 0x4d, 0x45, 0x45,
                                 0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x49, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_VISTA;
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_vista, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest09(void) {
    TcpStream stream;
    u_int8_t stream_before_linux[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                        0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and LINUX policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest10(void) {
    TcpStream stream;
    u_int8_t stream_same_linux[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                     0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest11(void) {
    TcpStream stream;
    u_int8_t stream_after_linux[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                      0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and LINUX policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest12(void) {
    TcpStream stream;
    u_int8_t stream_linux[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x43,
                                 0x43, 0x43, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                 0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LINUX;
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and OLD_LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest13(void) {
    TcpStream stream;
    u_int8_t stream_before_old_linux[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                            0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_old_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and OLD_LINUX policy is
 *              used to reassemble segments.
 */

static int StreamTcpReassembleTest14(void) {
    TcpStream stream;
    u_int8_t stream_same_old_linux[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                         0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_old_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and OLD_LINUX policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest15(void) {
    TcpStream stream;
    u_int8_t stream_after_old_linux[8] = {0x41, 0x41, 0x4a, 0x46, 0x46, 0x46,
                                          0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_old_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and OLD_LINUX policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest16(void) {
    TcpStream stream;
    u_int8_t stream_old_linux[25] = {0x30, 0x41, 0x41, 0x41, 0x4a, 0x4a, 0x42, 0x4b,
                                     0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                     0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_OLD_LINUX;
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_old_linux, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and SOLARIS policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest17(void) {
    TcpStream stream;
    u_int8_t stream_before_solaris[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                          0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_solaris, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and SOLARIS policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest18(void) {
    TcpStream stream;
    u_int8_t stream_same_solaris[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x48, 0x48,
                                       0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_solaris, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and SOLARIS policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest19(void) {
    TcpStream stream;
    u_int8_t stream_after_solaris[8] = {0x41, 0x4a, 0x4a, 0x46, 0x46, 0x46,
                                        0x47, 0x47};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_solaris, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and SOLARIS policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest20(void) {
    TcpStream stream;
    u_int8_t stream_solaris[25] = {0x30, 0x41, 0x4a, 0x4a, 0x4a, 0x42, 0x42, 0x4b,
                                   0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                   0x46, 0x46, 0x46, 0x47, 0x47, 0x48, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_SOLARIS;
    if (StreamTcpReassembleStreamTest(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_solaris, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              before the list segment and LAST policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest21(void) {
    TcpStream stream;
    u_int8_t stream_before_last[10] = {0x4a, 0x4a, 0x4a, 0x4a, 0x4c, 0x4c,
                                       0x4c, 0x4d, 0x4d, 0x4d};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    if (StreamTcpTestStartsBeforeListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_before_last, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              at the same seq no. as the list segment and LAST policy is used
 *              to reassemble segments.
 */

static int StreamTcpReassembleTest22(void) {
    TcpStream stream;
    u_int8_t stream_same_last[8] = {0x4c, 0x4c, 0x4c, 0x4c, 0x50, 0x48,
                                    0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    if (StreamTcpTestStartsAtSameListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_same_last, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly when new segment starts
 *              after the list segment and LAST policy is used to reassemble
 *              segments.
 */

static int StreamTcpReassembleTest23(void) {
    TcpStream stream;
    u_int8_t stream_after_last[8] = {0x41, 0x4a, 0x4a, 0x46, 0x4e, 0x46,
                                     0x47, 0x4f};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    if (StreamTcpTestStartsAfterListSegment(&stream) == 0) {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_after_last, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief      The Function to test the reassembly engine for all the case
 *              before, same and after overlapping and LAST policy is used to
 *              reassemble segments.
 */

static int StreamTcpReassembleTest24(void) {
    TcpStream stream;
    u_int8_t stream_last[25] = {0x30, 0x41, 0x4a, 0x4a, 0x4a, 0x4a, 0x42, 0x4b,
                                0x4b, 0x4b, 0x4c, 0x4c, 0x4c, 0x4d, 0x4d, 0x4d,
                                0x46, 0x4e, 0x46, 0x47, 0x4f, 0x50, 0x48, 0x51, 0x51};
    memset(&stream, 0, sizeof (TcpStream));
    stream.os_policy = OS_POLICY_LAST;
    if (StreamTcpReassembleStreamTest(&stream) == 0)  {
        printf("failed in segments reassembly!!\n");
        return 0;
    }
    if (StreamTcpCheckStreamContents(stream_last, &stream) == 0) {
        printf("failed in stream mathcing!!\n");
        return 0;
    }
    return 1;
}

/** \brief  The Function Register the Unit tests to test the reassembly engine
 *          for various OS policies.
 */

void StreamTcpReassembleRegisterTests(void) {
    UtRegisterTest("StreamTcpReassembleTest01 -- BSD OS Before Reassembly Test", StreamTcpReassembleTest01, 1);
    UtRegisterTest("StreamTcpReassembleTest02 -- BSD OS At Same Reassembly Test", StreamTcpReassembleTest02, 1);
    UtRegisterTest("StreamTcpReassembleTest03 -- BSD OS After Reassembly Test", StreamTcpReassembleTest03, 1);
    UtRegisterTest("StreamTcpReassembleTest04 -- BSD OS Complete Reassembly Test", StreamTcpReassembleTest04, 1);
    UtRegisterTest("StreamTcpReassembleTest05 -- VISTA OS Before Reassembly Test", StreamTcpReassembleTest05, 1);
    UtRegisterTest("StreamTcpReassembleTest06 -- VISTA OS At Same Reassembly Test", StreamTcpReassembleTest06, 1);
    UtRegisterTest("StreamTcpReassembleTest07 -- VISTA OS After Reassembly Test", StreamTcpReassembleTest07, 1);
    UtRegisterTest("StreamTcpReassembleTest08 -- VISTA OS Complete Reassembly Test", StreamTcpReassembleTest08, 1);
    UtRegisterTest("StreamTcpReassembleTest09 -- LINUX OS Before Reassembly Test", StreamTcpReassembleTest09, 1);
    UtRegisterTest("StreamTcpReassembleTest10 -- LINUX OS At Same Reassembly Test", StreamTcpReassembleTest10, 1);
    UtRegisterTest("StreamTcpReassembleTest11 -- LINUX OS After Reassembly Test", StreamTcpReassembleTest11, 1);
    UtRegisterTest("StreamTcpReassembleTest12 -- LINUX OS Complete Reassembly Test", StreamTcpReassembleTest12, 1);
    UtRegisterTest("StreamTcpReassembleTest13 -- LINUX_OLD OS Before Reassembly Test", StreamTcpReassembleTest13, 1);
    UtRegisterTest("StreamTcpReassembleTest14 -- LINUX_OLD At Same Reassembly Test", StreamTcpReassembleTest14, 1);
    UtRegisterTest("StreamTcpReassembleTest15 -- LINUX_OLD OS After Reassembly Test", StreamTcpReassembleTest15, 1);
    UtRegisterTest("StreamTcpReassembleTest16 -- LINUX_OLD OS Complete Reassembly Test", StreamTcpReassembleTest16, 1);
    UtRegisterTest("StreamTcpReassembleTest17 -- SOLARIS OS Before Reassembly Test", StreamTcpReassembleTest17, 1);
    UtRegisterTest("StreamTcpReassembleTest18 -- SOLARIS At Same Reassembly Test", StreamTcpReassembleTest18, 1);
    UtRegisterTest("StreamTcpReassembleTest19 -- SOLARIS OS After Reassembly Test", StreamTcpReassembleTest19, 1);
    UtRegisterTest("StreamTcpReassembleTest20 -- SOLARIS OS Complete Reassembly Test", StreamTcpReassembleTest20, 1);
    UtRegisterTest("StreamTcpReassembleTest21 -- LAST OS Before Reassembly Test", StreamTcpReassembleTest21, 1);
    UtRegisterTest("StreamTcpReassembleTest22 -- LAST OS At Same Reassembly Test", StreamTcpReassembleTest22, 1);
    UtRegisterTest("StreamTcpReassembleTest23 -- LAST OS After Reassembly Test", StreamTcpReassembleTest23, 1);
    UtRegisterTest("StreamTcpReassembleTest24 -- LAST OS Complete Reassembly Test", StreamTcpReassembleTest24, 1);
}

#endif /* UNITTESTS */

