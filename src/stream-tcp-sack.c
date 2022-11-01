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
#include "stream-tcp-sack.h"

RB_GENERATE(TCPSACK, StreamTcpSackRecord, rb, TcpSackCompare);

int TcpSackCompare(struct StreamTcpSackRecord *a, struct StreamTcpSackRecord *b)
{
    if (SEQ_GT(a->le, b->le))
        return 1;
    else if (SEQ_LT(a->le, b->le))
        return -1;
    else {
        if (SEQ_EQ(a->re, b->re))
            return 0;
        else if (SEQ_GT(a->re, b->re))
            return 1;
        else
            return -1;
    }
}
#ifdef DEBUG
static void StreamTcpSackPrintList(TcpStream *stream)
{
    SCLogDebug("size %u", stream->sack_size);
    StreamTcpSackRecord *rec = NULL;
    RB_FOREACH(rec, TCPSACK, &stream->sack_tree) {
        SCLogDebug("- record %8u - %8u", rec->le, rec->re);
    }
}
#endif /* DEBUG */

static inline StreamTcpSackRecord *StreamTcpSackRecordAlloc(void)
{
    if (StreamTcpCheckMemcap((uint32_t)sizeof(StreamTcpSackRecord)) == 0)
        return NULL;

    StreamTcpSackRecord *rec = SCMalloc(sizeof(*rec));
    if (unlikely(rec == NULL))
        return NULL;

    StreamTcpIncrMemuse((uint64_t)sizeof(*rec));
    return rec;
}

static inline void StreamTcpSackRecordFree(StreamTcpSackRecord *rec)
{
    SCFree(rec);
    StreamTcpDecrMemuse((uint64_t)sizeof(*rec));
}

static inline void ConsolidateFwd(TcpStream *stream, struct TCPSACK *tree, struct StreamTcpSackRecord *sa)
{
    struct StreamTcpSackRecord *tr, *s = sa;
    RB_FOREACH_FROM(tr, TCPSACK, s) {
        if (sa == tr)
            continue;
        SCLogDebug("-> (fwd) tr %p %u/%u", tr, tr->le, tr->re);

        if (SEQ_LT(sa->re, tr->le))
            break; // entirely before

        if (SEQ_GEQ(sa->le, tr->le) && SEQ_LEQ(sa->re, tr->re)) {
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED ECLIPSED2", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        /*
            sa: [         ]
            tr: [         ]
            sa: [         ]
            tr:    [      ]
            sa: [         ]
            tr:    [   ]
        */
        } else if (SEQ_LEQ(sa->le, tr->le) && SEQ_GEQ(sa->re, tr->re)) {
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED ECLIPSED", tr, tr->le, tr->re);
            stream->sack_size -= (tr->re - tr->le);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        /*
            sa: [         ]
            tr:      [         ]
            sa: [       ]
            tr:         [       ]
        */
        } else if (SEQ_LT(sa->le, tr->le) && // starts before
                   SEQ_GEQ(sa->re, tr->le) && SEQ_LT(sa->re, tr->re) // ends inside
            ) {
            // merge
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED MERGED", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        }
    }
}

static inline void ConsolidateBackward(TcpStream *stream,
        struct TCPSACK *tree, struct StreamTcpSackRecord *sa)
{
    struct StreamTcpSackRecord *tr, *s = sa;
    RB_FOREACH_REVERSE_FROM(tr, TCPSACK, s) {
        if (sa == tr)
            continue;
        SCLogDebug("-> (bwd) tr %p %u/%u", tr, tr->le, tr->re);

        if (SEQ_GT(sa->le, tr->re))
            break; // entirely after
        if (SEQ_GEQ(sa->le, tr->le) && SEQ_LEQ(sa->re, tr->re)) {
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED ECLIPSED2", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        /*
            sa: [         ]
            tr: [         ]
            sa:    [      ]
            tr: [         ]
            sa:    [   ]
            tr: [         ]
        */
        } else if (SEQ_LEQ(sa->le, tr->le) && SEQ_GEQ(sa->re, tr->re)) {
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED ECLIPSED", tr, tr->le, tr->re);
            stream->sack_size -= (tr->re - tr->le);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        /*
            sa:     [   ]
            tr: [   ]
            sa:    [    ]
            tr: [   ]
        */
        } else if (SEQ_GT(sa->le, tr->le) && SEQ_GT(sa->re, tr->re) && SEQ_LEQ(sa->le,tr->re)) {
            // merge
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED MERGED", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        }
    }
}

static int Insert(TcpStream *stream, struct TCPSACK *tree, uint32_t le, uint32_t re)
{
    SCLogDebug("inserting: %u-%u", le, re);

    struct StreamTcpSackRecord *sa = StreamTcpSackRecordAlloc();
    if (unlikely(sa == NULL))
        return -1;
    sa->le = le;
    sa->re = re;
    struct StreamTcpSackRecord *res = TCPSACK_RB_INSERT(tree, sa);
    if (res) {
        // exact overlap
        SCLogDebug("* insert failed: exact match in tree with %p %u/%u", res, res->le, res->re);
        StreamTcpSackRecordFree(sa);
        return 0;
    }
    stream->sack_size += (re - le);
    ConsolidateBackward(stream, tree, sa);
    ConsolidateFwd(stream, tree, sa);
    return 0;
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
        SCReturnInt(0);
    }
    /* if to the right of the tcp window then ignore */
    if (SEQ_GT(le, (stream->last_ack + stream->window))) {
        SCLogDebug("too far right. discarding");
        SCReturnInt(0);
    }

    if (Insert(stream, &stream->sack_tree, le, re) < 0)
        SCReturnInt(-1);

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
    SCEnter();

    const int records = TCP_GET_SACK_CNT(p);
    const uint8_t *data = TCP_GET_SACK_PTR(p);

    if (records == 0 || data == NULL)
        SCReturnInt(0);

    TCPOptSackRecord rec[records], *sack_rec = rec;
    memcpy(&rec, data, sizeof(TCPOptSackRecord) * records);

    for (int record = 0; record < records; record++) {
        const uint32_t le = SCNtohl(sack_rec->le);
        const uint32_t re = SCNtohl(sack_rec->re);

        SCLogDebug("%p last_ack %u, left edge %u, right edge %u", sack_rec,
            stream->last_ack, le, re);

        if (SEQ_LEQ(re, stream->last_ack)) {
            SCLogDebug("record before last_ack");
            goto next;
        }

        if (SEQ_GT(re, stream->next_win)) {
            SCLogDebug("record %u:%u beyond next_win %u",
                    le, re, stream->next_win);
            goto next;
        }

        if (SEQ_GEQ(le, re)) {
            SCLogDebug("invalid record: le >= re");
            goto next;
        }

        if (StreamTcpSackInsertRange(stream, le, re) == -1) {
            SCReturnInt(-1);
        }

    next:
        sack_rec++;
    }
    StreamTcpSackPruneList(stream);
#ifdef DEBUG
    StreamTcpSackPrintList(stream);
#endif
    SCReturnInt(0);
}

static inline int CompareOverlap(
        struct StreamTcpSackRecord *lookup, struct StreamTcpSackRecord *intree)
{
    if (lookup->re <= intree->le) // entirely before
        return -1;
    else if (lookup->re >= intree->le && lookup->le < intree->re) // (some) overlap
        return 0;
    else
        return 1; // entirely after
}

static struct StreamTcpSackRecord *FindOverlap(
        struct TCPSACK *head, struct StreamTcpSackRecord *elm)
{
    SCLogDebug("looking up le:%u re:%u", elm->le, elm->re);

    struct StreamTcpSackRecord *tmp = RB_ROOT(head);
    struct StreamTcpSackRecord *res = NULL;
    while (tmp) {
        SCLogDebug("compare with le:%u re:%u", tmp->le, tmp->re);
        const int comp = CompareOverlap(elm, tmp);
        SCLogDebug("compare result: %d", comp);
        if (comp < 0) {
            res = tmp;
            tmp = RB_LEFT(tmp, rb);
        } else if (comp > 0) {
            tmp = RB_RIGHT(tmp, rb);
        } else {
            return tmp;
        }
    }
    return res;
}

bool StreamTcpSackPacketIsOutdated(TcpStream *stream, Packet *p)
{
    const int records = TCP_GET_SACK_CNT(p);
    const uint8_t *data = TCP_GET_SACK_PTR(p);
    if (records > 0 && data != NULL) {
        int sack_outdated = 0;
        TCPOptSackRecord rec[records], *sack_rec = rec;
        memcpy(&rec, data, sizeof(TCPOptSackRecord) * records);
        for (int record = 0; record < records; record++) {
            const uint32_t le = SCNtohl(sack_rec->le);
            const uint32_t re = SCNtohl(sack_rec->re);
            SCLogDebug("%p last_ack %u, left edge %u, right edge %u", sack_rec, stream->last_ack,
                    le, re);

            struct StreamTcpSackRecord lookup = { .le = le, .re = re };
            struct StreamTcpSackRecord *res = FindOverlap(&stream->sack_tree, &lookup);
            SCLogDebug("res %p", res);
            if (res) {
                if (le >= res->le && re <= res->re) {
                    SCLogDebug("SACK rec le:%u re:%u eclipsed by in tree le:%u re:%u", le, re,
                            res->le, res->re);
                    sack_outdated++;
                } else {
                    SCLogDebug("SACK rec le:%u re:%u SACKs new DATA vs in tree le:%u re:%u", le, re,
                            res->le, res->re);
                }
            } else {
                SCLogDebug("SACK rec le:%u re:%u SACKs new DATA. No match in tree", le, re);
            }
            sack_rec++;
        }
#ifdef DEBUG
        StreamTcpSackPrintList(stream);
#endif
        if (records != sack_outdated) {
            // SACK tree needs updating
            return false;
        } else {
            // SACK list is packet is completely outdated
            return true;
        }
    }
    return false;
}

void StreamTcpSackPruneList(TcpStream *stream)
{
    SCEnter();

    StreamTcpSackRecord *rec = NULL, *safe = NULL;
    RB_FOREACH_SAFE(rec, TCPSACK, &stream->sack_tree, safe) {
        if (SEQ_LT(rec->re, stream->last_ack)) {
            SCLogDebug("removing le %u re %u", rec->le, rec->re);
            stream->sack_size -= (rec->re - rec->le);
            TCPSACK_RB_REMOVE(&stream->sack_tree, rec);
            StreamTcpSackRecordFree(rec);

        } else if (SEQ_LT(rec->le, stream->last_ack)) {
            SCLogDebug("adjusting record to le %u re %u", rec->le, rec->re);
            /* last ack inside this record, update */
            stream->sack_size -= (rec->re - rec->le);
            rec->le = stream->last_ack;
            stream->sack_size += (rec->re - rec->le);
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
 *  \brief Free SACK tree from a stream
 *
 *  \param stream Stream to cleanup
 */
void StreamTcpSackFreeList(TcpStream *stream)
{
    SCEnter();

    StreamTcpSackRecord *rec = NULL, *safe = NULL;
    RB_FOREACH_SAFE(rec, TCPSACK, &stream->sack_tree, safe) {
        stream->sack_size -= (rec->re - rec->le);
        TCPSACK_RB_REMOVE(&stream->sack_tree, rec);
        StreamTcpSackRecordFree(rec);
    }

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
    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 1, 10);
    FAIL_IF_NOT(stream.sack_size == 9);
    StreamTcpSackInsertRange(&stream, 10, 20);
    FAIL_IF_NOT(stream.sack_size == 19);
    StreamTcpSackInsertRange(&stream, 10, 20);
    FAIL_IF_NOT(stream.sack_size == 19);
    StreamTcpSackInsertRange(&stream, 1, 20);
    FAIL_IF_NOT(stream.sack_size == 19);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 1);
    FAIL_IF(rec->re != 20);

    FAIL_IF(StreamTcpSackedSize(&stream) != 19);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest02 (void)
{
    TcpStream stream;
    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 10, 20);
    StreamTcpSackInsertRange(&stream, 1, 20);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 1);
    FAIL_IF(rec->re != 20);

    FAIL_IF(StreamTcpSackedSize(&stream) != 19);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest03 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 5);
    FAIL_IF(rec->re != 25);

    FAIL_IF(StreamTcpSackedSize(&stream) != 20);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest04 (void)
{
    TcpStream stream;
    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  20);
    StreamTcpSackInsertRange(&stream, 30, 50);
    StreamTcpSackInsertRange(&stream, 10, 25);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 25);

    FAIL_IF(StreamTcpSackedSize(&stream) != 45);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest05 (void)
{
    TcpStream stream;
    memset(&stream, 0, sizeof(stream));
    stream.window = 100;

    StreamTcpSackInsertRange(&stream, 0,  20);
    StreamTcpSackInsertRange(&stream, 30, 50);
    StreamTcpSackInsertRange(&stream, 10, 35);
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 50);

    FAIL_IF(StreamTcpSackedSize(&stream) != 50);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest06 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);

    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 40);

    FAIL_IF(StreamTcpSackedSize(&stream) != 40);
    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest07 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 40);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    stream.last_ack = 10;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 30);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest08 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 40);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    stream.last_ack = 41;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 0);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest09 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 0);
    FAIL_IF(rec->re != 40);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    stream.last_ack = 39;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 1);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest10 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 100);
    FAIL_IF(rec->re != 140);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    stream.last_ack = 99;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest11 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 100);
    FAIL_IF(rec->re != 140);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    stream.last_ack = 99;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 40);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the pruning of SACK ranges.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest12 (void)
{
    TcpStream stream;
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

    StreamTcpSackRecord *rec = RB_MIN(TCPSACK, &stream.sack_tree);
    FAIL_IF_NULL(rec);
    FAIL_IF(rec->le != 100);
    FAIL_IF(rec->re != 1000);
    FAIL_IF(StreamTcpSackedSize(&stream) != 900);

    StreamTcpSackInsertRange(&stream, 0, 1000);
    FAIL_IF(StreamTcpSackedSize(&stream) != 1000);

    stream.last_ack = 500;
    StreamTcpSackPruneList(&stream);
    FAIL_IF(StreamTcpSackedSize(&stream) != 500);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion on out of window condition.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest13 (void) {
    TcpStream stream;
    memset(&stream, 0, sizeof(stream));
    stream.last_ack = 10000;
    stream.window = 2000;

    for (int i = 0; i < 10; i++) {
        StreamTcpSackInsertRange(&stream, 100+(20*i), 110+(20*i));
    }
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    FAIL_IF(StreamTcpSackedSize(&stream) != 0);

    StreamTcpSackFreeList(&stream);
    PASS;
}

/**
 *  \test   Test the insertion of out of window condition.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpSackTest14 (void) {
    TcpStream stream;
    memset(&stream, 0, sizeof(stream));
    stream.last_ack = 1000;
    stream.window = 2000;

    for (int i = 0; i < 10; i++) {
        StreamTcpSackInsertRange(&stream, 4000+(20*i), 4010+(20*i));
    }
#ifdef DEBUG
    StreamTcpSackPrintList(&stream);
#endif /* DEBUG */

    FAIL_IF(StreamTcpSackedSize(&stream) != 0);

    StreamTcpSackFreeList(&stream);
    PASS;
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
