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
 */

#ifndef __STREAM_H__
#define __STREAM_H__

#include "flow.h"

#define STREAM_START            0x01
#define STREAM_EOF              0x02
#define STREAM_TOSERVER         0x04
#define STREAM_TOCLIENT         0x08
#define STREAM_GAP              0x10    /* data gap encountered */
#define STREAM_DEPTH            0x20    /* depth reached */

/** size of the data chunks sent to the app layer parser. */
#define MSG_DATA_SIZE       4072    /* 4096 - 24 (size of rest of the struct) */

typedef struct StreamMsg_ {
    struct StreamMsg_ *next;
    struct StreamMsg_ *prev;

    uint32_t seq;                   /**< sequence number */
    uint32_t data_len;              /**< length of the data */
    uint8_t data[MSG_DATA_SIZE];    /**< reassembled data */
} StreamMsg;

typedef struct StreamMsgQueue_ {
    StreamMsg *top;
    StreamMsg *bot;
    uint16_t len;
    //uint8_t flags;
#ifdef DBG_PERF
    uint16_t dbg_maxlen;
#endif /* DBG_PERF */
} StreamMsgQueue;

/* prototypes */
void StreamMsgQueuesInit(uint32_t prealloc);
void StreamMsgQueuesDeinit(char);

StreamMsg *StreamMsgGetFromPool(void);
void StreamMsgReturnToPool(StreamMsg *);
StreamMsg *StreamMsgGetFromQueue(StreamMsgQueue *);
void StreamMsgPutInQueue(StreamMsgQueue *, StreamMsg *);

StreamMsgQueue *StreamMsgQueueGetNew(void);
void StreamMsgQueueFree(StreamMsgQueue *);
StreamMsgQueue *StreamMsgQueueGetByPort(uint16_t);

void StreamMsgQueueSetMinChunkLen(uint8_t dir, uint16_t len);
uint16_t StreamMsgQueueGetMinChunkLen(uint8_t);

void StreamMsgReturnListToPool(void *);

typedef int (*StreamSegmentCallback)(const Packet *, void *, uint8_t *, uint32_t);
int StreamSegmentForEach(const Packet *p, uint8_t flag,
                      StreamSegmentCallback CallbackFunc,
                      void *data);

#endif /* __STREAM_H__ */

