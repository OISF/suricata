/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * Stream engine TCP SACK handling.
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-sack.h"
#include "util-unittest.h"

#ifdef DEBUG
static void StreamTcpSackPrintList(TcpStream *stream)
{
    StreamTcpSackRecord *rec = stream->sack_head;
    for (; rec != NULL; rec = rec->next) {
        SCLogDebug("record %8u - %8u", rec->le, rec->re);
    }
}
#endif /* DEBUG */

static StreamTcpSackRecord *StreamTcpSackRecordAlloc(void)
{
    if (StreamTcpCheckMemcap((uint32_t)sizeof(StreamTcpSackRecord)) == 0)
        return NULL;

    StreamTcpSackRecord *rec = SCMalloc(sizeof(*rec));
    if (unlikely(rec == NULL))
        return NULL;

    StreamTcpIncrMemuse((uint64_t)sizeof(*rec));
    return rec;
}

static void StreamTcpSackRecordFree(StreamTcpSackRecord *rec)
{
    SCFree(rec);
    StreamTcpDecrMemuse((uint64_t)sizeof(*rec));
}

/**
 *  \brief insert a SACK range
 *
 *  \param le left edge in host order
 *  \param re right edge in host order
 *
 *  \retval 0 all is good
 *  \retval -1 error
 */
static int StreamTcpSackInsertRange(TcpStream *stream, uint32_t le, uint32_t re)
{
    SCLogDebug("le %u, re %u", le, re);
#ifdef DEBUG
    StreamTcpSackPrintList(stream);
#endif

    /* if to the left of last_ack then ignore */
    if (SEQ_LT(re, stream->last_ack)) {
        SCLogDebug("too far left. discarding");
        goto end;
    }
    /* if to the right of the tcp window then ignore */
    if (SEQ_GT(le, (stream->last_ack + stream->window))) {
        SCLogDebug("too far right. discarding");
        goto end;
    }
    if (stream->sack_head != NULL) {
        StreamTcpSackRecord *rec;

        for (rec = stream->sack_head; rec != NULL; rec = rec->next) {
            SCLogDebug("rec %p, le %u, re %u", rec, rec->le, rec->re);

            if (SEQ_LT(le, rec->le)) {
                SCLogDebug("SEQ_LT(le, rec->le)");
                if (SEQ_LT(re, rec->le)) {
                    SCLogDebug("SEQ_LT(re, rec->le)");
                    // entirely before, prepend
                    StreamTcpSackRecord *stsr = StreamTcpSackRecordAlloc();
                    if (unlikely(stsr == NULL)) {
                        SCReturnInt(-1);
                    }
                    stsr->le = le;
                    stsr->re = re;

                    stsr->next = stream->sack_head;
                    stream->sack_head = stsr;
                    goto end;
                } else if (SEQ_EQ(re, rec->le)) {
                    SCLogDebug("SEQ_EQ(re, rec->le)");
                    // starts before, ends on rec->le, expand
                    rec->le = le;
                } else if (SEQ_GT(re, rec->le)) {
                    SCLogDebug("SEQ_GT(re, rec->le)");
                    // starts before, ends beyond rec->le
                    if (SEQ_LEQ(re, rec->re)) {
                        SCLogDebug("SEQ_LEQ(re, rec->re)");
                        // ends before rec->re, expand
                        rec->le = le;
                    } else { // implied if (re > rec->re)
                        SCLogDebug("implied if (re > rec->re), le set to %u", rec->re);
                        le = rec->re;
                        continue;
                    }
                }
            } else if (SEQ_EQ(le, rec->le)) {
                SCLogDebug("SEQ_EQ(le, rec->le)");
                if (SEQ_LEQ(re, rec->re)) {
                    SCLogDebug("SEQ_LEQ(re, rec->re)");
                    // new record fully overlapped
                    SCReturnInt(0);
                } else { // implied re > rec->re
                    SCLogDebug("implied re > rec->re");
                    if (rec->next != NULL) {
                        if (SEQ_LEQ(re, rec->next->le)) {
                            rec->re = re;
                            goto end;
                        } else {
                            rec->re = rec->next->le;
                            le = rec->next->le;
                            SCLogDebug("le is now %u", le);
                            continue;
                        }
                    } else {
                        rec->re = re;
                        goto end;
                    }
                }
            } else { // implied (le > rec->le)
                SCLogDebug("implied (le > rec->le)");
                if (SEQ_LT(le, rec->re)) {
                    SCLogDebug("SEQ_LT(le, rec->re))");
                    // new record fully overlapped
                    if (SEQ_GT(re, rec->re)) {
                        SCLogDebug("SEQ_GT(re, rec->re)");

                        if (rec->next != NULL) {
                            if (SEQ_LEQ(re, rec->next->le)) {
                                rec->re = re;
                                goto end;
                            } else {
                                rec->re = rec->next->le;
                                le = rec->next->le;
                                continue;
                            }
                        } else {
                            rec->re = re;
                            goto end;
                        }
                    }

                    SCLogDebug("new range fully overlapped");
                    SCReturnInt(0);
                } else if (SEQ_EQ(le, rec->re)) {
                    SCLogDebug("here");
                    // new record fully overlapped
                    //int r = StreamTcpSackInsertRange(stream, rec->re+1, re);
                    //SCReturnInt(r);
                    le = rec->re;
                    continue;
                } else { /* implied le > rec->re */
                    SCLogDebug("implied le > rec->re");
                    if (rec->next == NULL) {
                        SCLogDebug("rec->next == NULL");
                        StreamTcpSackRecord *stsr = StreamTcpSackRecordAlloc();
                        if (unlikely(stsr == NULL)) {
                            SCReturnInt(-1);
                        }
                        stsr->le = le;
                        stsr->re = re;
                        stsr->next = NULL;

                        stream->sack_tail->next = stsr;
                        stream->sack_tail = stsr;
                        goto end;
                    } else {
                        SCLogDebug("implied rec->next != NULL");
                        if (SEQ_LT(le, rec->next->le) && SEQ_LT(re, rec->next->le)) {
                            SCLogDebug("SEQ_LT(le, rec->next->le) && SEQ_LT(re, rec->next->le)");
                            StreamTcpSackRecord *stsr = StreamTcpSackRecordAlloc();
                            if (unlikely(stsr == NULL)) {
                                SCReturnInt(-1);
                            }
                            stsr->le = le;
                            stsr->re = re;
                            stsr->next = rec->next;
                            rec->next = stsr;

                        } else if (SEQ_LT(le, rec->next->le) && SEQ_GEQ(re, rec->next->le)) {
                            SCLogDebug("SEQ_LT(le, rec->next->le) && SEQ_GEQ(re, rec->next->le)");
                            StreamTcpSackRecord *stsr = StreamTcpSackRecordAlloc();
                            if (unlikely(stsr == NULL)) {
                                SCReturnInt(-1);
                            }
                            stsr->le = le;
                            stsr->re = rec->next->le;
                            stsr->next = rec->next;
                            rec->next = stsr;

                            le = rec->next->le;
                        }
                    }
                }
            }
        }
    } else {
        SCLogDebug("implied empty list");
        StreamTcpSackRecord *stsr = StreamTcpSackRecordAlloc();
        if (unlikely(stsr == NULL)) {
            SCReturnInt(-1);
        }
        stsr->le = le;
        stsr->re = re;
        stsr->next = NULL;

        stream->sack_head = stsr;
        stream->sack_tail = stsr;
    }

    StreamTcpSackPruneList(stream);
end:
    SCReturnInt(0);
}

/**
 *  \brief Update stream with SACK records from a TCP packet.
 *
 *  \param stream The stream to update.
 *  \param p packet to get the SACK records from
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int StreamTcpSackUpdatePacket(TcpStream *stream, Packet *p)
{
    int records = TCP_GET_SACK_CNT(p);
    int record = 0;
    const uint8_t *data = TCP_GET_SACK_PTR(p);

    if (records == 0 || data == NULL)
        return 0;

    TCPOptSackRecord rec[records], *sack_rec = rec;
    memcpy(&rec, data, sizeof(TCPOptSackRecord) * records);

    for (record = 0; record < records; record++) {
        SCLogDebug("%p last_ack %u, left edge %u, right edge %u", sack_rec,
            stream->last_ack, ntohl(sack_rec->le), ntohl(sack_rec->re));

        if (SEQ_LEQ(ntohl(sack_rec->re), stream->last_ack)) {
            SCLogDebug("record before last_ack");
            goto next;
        }

        if (SEQ_GT(ntohl(sack_rec->re), stream->next_win)) {
            SCLogDebug("record %u:%u beyond next_win %u",
                    ntohl(sack_rec->le), ntohl(sack_rec->re), stream->next_win);
            goto next;
        }

        if (SEQ_GEQ(ntohl(sack_rec->le), ntohl(sack_rec->re))) {
            SCLogDebug("invalid record: le >= re");
            goto next;
        }

        if (StreamTcpSackInsertRange(stream, ntohl(sack_rec->le),
                    ntohl(sack_rec->re)) == -1)
        {
            SCReturnInt(-1);
        }

    next:
        sack_rec++;
    }
#ifdef DEBUG
    StreamTcpSackPrintList(stream);
#endif
    SCReturnInt(0);
}

void StreamTcpSackPruneList(TcpStream *stream)
{
    SCEnter();

    StreamTcpSackRecord *rec = stream->sack_head;

    while (rec != NULL) {
        if (SEQ_LT(rec->re, stream->last_ack)) {
            SCLogDebug("removing le %u re %u", rec->le, rec->re);

            if (rec->next != NULL) {
                stream->sack_head = rec->next;
                StreamTcpSackRecordFree(rec);
                rec = stream->sack_head;
                continue;
            } else {
                stream->sack_head = NULL;
                stream->sack_tail = NULL;
                StreamTcpSackRecordFree(rec);
                break;
            }
        } else if (SEQ_LT(rec->le, stream->last_ack)) {
            SCLogDebug("adjusting record to le %u re %u", rec->le, rec->re);
            /* last ack inside this record, update */
            rec->le = stream->last_ack;
            break;
        } else {
            SCLogDebug("record beyond last_ack, nothing to do. Bailing out.");
            break;
        }
    }
#ifdef DEBUG
    StreamTcpSackPrintList(stream);
#endif
    SCReturn;
}

/**
 *  \brief Free SACK list from a stream
 *
 *  \param stream Stream to cleanup
 */
void StreamTcpSackFreeList(TcpStream *stream)
{
    SCEnter();

    StreamTcpSackRecord *rec = stream->sack_head;
    StreamTcpSackRecord *next = NULL;

    while (rec != NULL) {
        next = rec->next;
        StreamTcpSackRecordFree(rec);
        rec = next;
    }

    stream->sack_head = NULL;
    stream->sack_tail = NULL;
    SCReturn;
}


#ifdef UNITTESTS

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest01 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 1, 10);
    StreamTcpSackInsertRange(&stream, 10, 20);
    StreamTcpSackInsertRange(&stream, 10, 20);
    StreamTcpSackInsertRange(&stream, 1, 20);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 1 || stream.sack_head->re != 20) {
        printf("list in weird state, head le %u, re %u: ",
                stream.sack_head->le, stream.sack_head->re);
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 19) {
        printf("size should be 19, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest02 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 10, 20);
    StreamTcpSackInsertRange(&stream, 1, 20);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 1 || stream.sack_head->re != 20) {
        printf("list in weird state, head le %u, re %u: ",
                stream.sack_head->le, stream.sack_head->re);
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 19) {
        printf("size should be 19, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest03 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 10, 20);
    StreamTcpSackInsertRange(&stream,  5, 15);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */
    StreamTcpSackInsertRange(&stream, 15, 25);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 5) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 20) {
        printf("size should be 20, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest04 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  20);
    StreamTcpSackInsertRange(&stream, 30, 50);
    StreamTcpSackInsertRange(&stream, 10, 25);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 45) {
        printf("size should be 45, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest05 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  20);
    StreamTcpSackInsertRange(&stream, 30, 50);
    StreamTcpSackInsertRange(&stream, 10, 35);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 50) {
        printf("size should be 50, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest06 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  9);
    StreamTcpSackInsertRange(&stream, 11, 19);
    StreamTcpSackInsertRange(&stream, 21, 29);
    StreamTcpSackInsertRange(&stream, 31, 39);
    StreamTcpSackInsertRange(&stream, 0, 40);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest07 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  9);
    StreamTcpSackInsertRange(&stream, 11, 19);
    StreamTcpSackInsertRange(&stream, 21, 29);
    StreamTcpSackInsertRange(&stream, 31, 39);
    StreamTcpSackInsertRange(&stream, 0, 40);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 10;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 30) {
        printf("size should be 30, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest08 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  9);
    StreamTcpSackInsertRange(&stream, 11, 19);
    StreamTcpSackInsertRange(&stream, 21, 29);
    StreamTcpSackInsertRange(&stream, 31, 39);
    StreamTcpSackInsertRange(&stream, 0, 40);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 41;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 0) {
        printf("size should be 0, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest09 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  9);
    StreamTcpSackInsertRange(&stream, 11, 19);
    StreamTcpSackInsertRange(&stream, 21, 29);
    StreamTcpSackInsertRange(&stream, 31, 39);
    StreamTcpSackInsertRange(&stream, 0, 40);

#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 0) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 39;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 1) {
        printf("size should be 1, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest10 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 1000;

    StreamTcpSackInsertRange(&stream, 100, 119);
    StreamTcpSackInsertRange(&stream, 111, 119);
    StreamTcpSackInsertRange(&stream, 121, 129);
    StreamTcpSackInsertRange(&stream, 131, 139);
    StreamTcpSackInsertRange(&stream, 100, 140);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 100) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 99;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest11 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 1000;

    StreamTcpSackInsertRange(&stream, 100, 119);
    StreamTcpSackInsertRange(&stream, 111, 119);
    StreamTcpSackInsertRange(&stream, 121, 129);
    StreamTcpSackInsertRange(&stream, 131, 139);
    StreamTcpSackInsertRange(&stream, 101, 140);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 100) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 99;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 40) {
        printf("size should be 40, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest12 (void)
{
    TcpStream stream;
    int retval = 0;

    memset(&stream, 0, sizeof(stream));
    stream.window = 2000;

    StreamTcpSackInsertRange(&stream, 800, 1000);
    StreamTcpSackInsertRange(&stream, 700, 900);
    StreamTcpSackInsertRange(&stream, 600, 800);
    StreamTcpSackInsertRange(&stream, 500, 700);
    StreamTcpSackInsertRange(&stream, 100, 600);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (stream.sack_head->le != 100) {
        goto end;
    }

    if (StreamTcpSackedSize(&stream) != 900) {
        printf("size should be 900, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    StreamTcpSackInsertRange(&stream, 0, 1000);

    if (StreamTcpSackedSize(&stream) != 1000) {
        printf("size should be 1000, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    stream.last_ack = 500;

    StreamTcpSackPruneList(&stream);

    if (StreamTcpSackedSize(&stream) != 500) {
        printf("size should be 500, is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion on out of window condition.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest13 (void) {
    TcpStream stream;
    int retval = 0;
    int i;

    memset(&stream, 0, sizeof(stream));
    stream.last_ack = 10000;
    stream.window = 2000;

    for (i = 0; i < 10; i++) {
        StreamTcpSackInsertRange(&stream, 100+(20*i), 110+(20*i));
    }
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (StreamTcpSackedSize(&stream) != 0) {
        printf("Sacked size is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

/**
 *  \test   Test the insertion of out of window condition.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest14 (void) {
    TcpStream stream;
    int retval = 0;
    int i;

    memset(&stream, 0, sizeof(stream));
    stream.last_ack = 1000;
    stream.window = 2000;

    for (i = 0; i < 10; i++) {
        StreamTcpSackInsertRange(&stream, 4000+(20*i), 4010+(20*i));
    }
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    if (StreamTcpSackedSize(&stream) != 0) {
        printf("Sacked size is %u: ", StreamTcpSackedSize(&stream));
        goto end;
    }

    retval = 1;
end:
    StreamTcpSackFreeList(&stream);
    SCReturnInt(retval);
}

#endif /* UNITTESTS */

void StreamTcpSackRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpSackTest01 -- Insertion", StreamTcpSackTest01);
    UtRegisterTest("StreamTcpSackTest02 -- Insertion", StreamTcpSackTest02);
    UtRegisterTest("StreamTcpSackTest03 -- Insertion", StreamTcpSackTest03);
    UtRegisterTest("StreamTcpSackTest04 -- Insertion", StreamTcpSackTest04);
    UtRegisterTest("StreamTcpSackTest05 -- Insertion", StreamTcpSackTest05);
    UtRegisterTest("StreamTcpSackTest06 -- Insertion", StreamTcpSackTest06);
    UtRegisterTest("StreamTcpSackTest07 -- Pruning", StreamTcpSackTest07);
    UtRegisterTest("StreamTcpSackTest08 -- Pruning", StreamTcpSackTest08);
    UtRegisterTest("StreamTcpSackTest09 -- Pruning", StreamTcpSackTest09);
    UtRegisterTest("StreamTcpSackTest10 -- Pruning", StreamTcpSackTest10);
    UtRegisterTest("StreamTcpSackTest11 -- Insertion && Pruning",
                   StreamTcpSackTest11);
    UtRegisterTest("StreamTcpSackTest12 -- Insertion && Pruning",
                   StreamTcpSackTest12);
    UtRegisterTest("StreamTcpSackTest13 -- Insertion out of window",
                   StreamTcpSackTest13);
    UtRegisterTest("StreamTcpSackTest14 -- Insertion out of window",
                   StreamTcpSackTest14);
#endif
}
