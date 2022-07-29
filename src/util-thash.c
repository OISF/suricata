/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 */

#include "suricata-common.h"

#include "util-thash.h"

#include "util-random.h"
#include "util-misc.h"
#include "util-byte.h"

#include "util-validate.h"

static THashData *THashGetUsed(THashTableContext *ctx);
static void THashDataEnqueue (THashDataQueue *q, THashData *h);

void THashDataMoveToSpare(THashTableContext *ctx, THashData *h)
{
    THashDataEnqueue(&ctx->spare_q, h);
    (void) SC_ATOMIC_SUB(ctx->counter, 1);
}

static THashDataQueue *THashDataQueueInit (THashDataQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(THashDataQueue));
        HQLOCK_INIT(q);
    }
    return q;
}

THashDataQueue *THashDataQueueNew(void)
{
    THashDataQueue *q = (THashDataQueue *)SCMalloc(sizeof(THashDataQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in THashDataQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = THashDataQueueInit(q);
    return q;
}

/**
 *  \brief Destroy a queue
 *
 *  \param q the queue to destroy
 */
static void THashDataQueueDestroy (THashDataQueue *q)
{
    HQLOCK_DESTROY(q);
}

/**
 *  \brief add to queue
 *
 *  \param q queue
 *  \param h data
 */
static void THashDataEnqueue (THashDataQueue *q, THashData *h)
{
#ifdef DEBUG
    BUG_ON(q == NULL || h == NULL);
#endif

    HQLOCK_LOCK(q);

    /* more data in queue */
    if (q->top != NULL) {
        h->next = q->top;
        q->top->prev = h;
        q->top = h;
    /* only data */
    } else {
        q->top = h;
        q->bot = h;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    HQLOCK_UNLOCK(q);
}

/**
 *  \brief remove data from the queue
 *
 *  \param q queue
 *
 *  \retval h data or NULL if empty list.
 */
static THashData *THashDataDequeue (THashDataQueue *q)
{
    HQLOCK_LOCK(q);

    THashData *h = q->bot;
    if (h == NULL) {
        HQLOCK_UNLOCK(q);
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;

    h->next = NULL;
    h->prev = NULL;

    HQLOCK_UNLOCK(q);
    return h;
}

#if 0
static uint32_t THashDataQueueLen(THashDataQueue *q)
{
    uint32_t len;
    HQLOCK_LOCK(q);
    len = q->len;
    HQLOCK_UNLOCK(q);
    return len;
}
#endif

static THashData *THashDataAlloc(THashTableContext *ctx)
{
    const size_t data_size = THASH_DATA_SIZE(ctx);

    if (!(THASH_CHECK_MEMCAP(ctx, data_size))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(ctx->memuse, data_size);

    THashData *h = SCCalloc(1, data_size);
    if (unlikely(h == NULL))
        goto error;

    /* points to data right after THashData block */
    h->data = (uint8_t *)h + sizeof(THashData);

//    memset(h, 0x00, data_size);

    SCMutexInit(&h->m, NULL);
    SC_ATOMIC_INIT(h->use_cnt);
    return h;

error:
    return NULL;
}

static void THashDataFree(THashTableContext *ctx, THashData *h)
{
    if (h != NULL) {
        DEBUG_VALIDATE_BUG_ON(SC_ATOMIC_GET(h->use_cnt) != 0);

        if (h->data != NULL) {
            ctx->config.DataFree(h->data);
        }
        SCMutexDestroy(&h->m);
        SCFree(h);
        (void) SC_ATOMIC_SUB(ctx->memuse, THASH_DATA_SIZE(ctx));
    }
}

#define THASH_DEFAULT_HASHSIZE 4096
#define THASH_DEFAULT_MEMCAP 16777216
#define THASH_DEFAULT_PREALLOC 1000

#define GET_VAR(prefix,name) \
    snprintf(varname, sizeof(varname), "%s.%s", (prefix), (name))

/** \brief initialize the configuration
 *  \warning Not thread safe */
static int THashInitConfig(THashTableContext *ctx, const char *cnf_prefix)
{
    char varname[256];

    SCLogDebug("initializing thash engine...");

    /* Check if we have memcap and hash_size defined at config */
    const char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    GET_VAR(cnf_prefix, "memcap");
    if ((ConfGet(varname, &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &ctx->config.memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing %s "
                       "from conf file - %s.  Killing engine",
                       varname, conf_val);
            return -1;
        }
    }
    GET_VAR(cnf_prefix, "hash-size");
    if ((ConfGet(varname, &conf_val)) == 1)
    {
        if (StringParseUint32(&configval, 10, (uint16_t)strlen(conf_val), conf_val) > 0) {
            ctx->config.hash_size = configval;
        }
    }

    GET_VAR(cnf_prefix, "prealloc");
    if ((ConfGet(varname, &conf_val)) == 1)
    {
        if (StringParseUint32(&configval, 10, (uint16_t)strlen(conf_val), conf_val) > 0) {
            ctx->config.prealloc = configval;
        } else {
            WarnInvalidConfEntry(varname, "%"PRIu32, ctx->config.prealloc);
        }
    }

    /* alloc hash memory */
    uint64_t hash_size = ctx->config.hash_size * sizeof(THashHashRow);
    if (!(THASH_CHECK_MEMCAP(ctx, hash_size))) {
        SCLogError(SC_ERR_THASH_INIT, "allocating hash failed: "
                "max hash memcap is smaller than projected hash size. "
                "Memcap: %"PRIu64", Hash table size %"PRIu64". Calculate "
                "total hash size by multiplying \"hash-size\" with %"PRIuMAX", "
                "which is the hash bucket size.", ctx->config.memcap, hash_size,
                (uintmax_t)sizeof(THashHashRow));
        return -1;
    }
    ctx->array = SCMallocAligned(ctx->config.hash_size * sizeof(THashHashRow), CLS);
    if (unlikely(ctx->array == NULL)) {
        SCLogError(SC_ERR_THASH_INIT, "Fatal error encountered in THashInitConfig. Exiting...");
        return -1;
    }
    memset(ctx->array, 0, ctx->config.hash_size * sizeof(THashHashRow));

    uint32_t i = 0;
    for (i = 0; i < ctx->config.hash_size; i++) {
        HRLOCK_INIT(&ctx->array[i]);
    }
    (void) SC_ATOMIC_ADD(ctx->memuse, (ctx->config.hash_size * sizeof(THashHashRow)));

    /* pre allocate prealloc */
    for (i = 0; i < ctx->config.prealloc; i++) {
        if (!(THASH_CHECK_MEMCAP(ctx, THASH_DATA_SIZE(ctx)))) {
            SCLogError(SC_ERR_THASH_INIT, "preallocating data failed: "
                    "max thash memcap reached. Memcap %"PRIu64", "
                    "Memuse %"PRIu64".", ctx->config.memcap,
                    ((uint64_t)SC_ATOMIC_GET(ctx->memuse) + THASH_DATA_SIZE(ctx)));
            return -1;
        }

        THashData *h = THashDataAlloc(ctx);
        if (h == NULL) {
            SCLogError(SC_ERR_THASH_INIT, "preallocating data failed: %s", strerror(errno));
            return -1;
        }
        THashDataEnqueue(&ctx->spare_q,h);
    }

    return 0;
}

THashTableContext *THashInit(const char *cnf_prefix, size_t data_size,
        int (*DataSet)(void *, void *), void (*DataFree)(void *), uint32_t (*DataHash)(void *),
        bool (*DataCompare)(void *, void *), bool reset_memcap, uint64_t memcap, uint32_t hashsize)
{
    THashTableContext *ctx = SCCalloc(1, sizeof(*ctx));
    BUG_ON(!ctx);

    ctx->config.data_size = data_size;
    ctx->config.DataSet = DataSet;
    ctx->config.DataFree = DataFree;
    ctx->config.DataHash = DataHash;
    ctx->config.DataCompare = DataCompare;

    /* set defaults */
    ctx->config.hash_rand = (uint32_t)RandomGet();
    ctx->config.hash_size = hashsize > 0 ? hashsize : THASH_DEFAULT_HASHSIZE;
    /* Reset memcap in case of loading from file to the highest possible value
     unless defined by the rule keyword */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // limit memcap size to default when fuzzing
    ctx->config.memcap = THASH_DEFAULT_MEMCAP;
#else
    if (memcap > 0) {
        ctx->config.memcap = memcap;
    } else {
        ctx->config.memcap = reset_memcap ? UINT64_MAX : THASH_DEFAULT_MEMCAP;
    }
#endif
    ctx->config.prealloc = THASH_DEFAULT_PREALLOC;

    SC_ATOMIC_INIT(ctx->counter);
    SC_ATOMIC_INIT(ctx->memuse);
    SC_ATOMIC_INIT(ctx->prune_idx);
    THashDataQueueInit(&ctx->spare_q);

    if (THashInitConfig(ctx, cnf_prefix) < 0) {
        THashShutdown(ctx);
        ctx = NULL;
    }
    return ctx;
}

/* \brief Set memcap to current memuse
 * */
void THashConsolidateMemcap(THashTableContext *ctx)
{
    ctx->config.memcap = MAX(SC_ATOMIC_GET(ctx->memuse), ctx->config.memcap);
    SCLogDebug("memcap after load set to: %" PRIu64, ctx->config.memcap);
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void THashShutdown(THashTableContext *ctx)
{
    THashData *h;

    /* free spare queue */
    while ((h = THashDataDequeue(&ctx->spare_q))) {
        BUG_ON(SC_ATOMIC_GET(h->use_cnt) > 0);
        THashDataFree(ctx, h);
    }

    /* clear and free the hash */
    if (ctx->array != NULL) {
        for (uint32_t u = 0; u < ctx->config.hash_size; u++) {
            h = ctx->array[u].head;
            while (h) {
                THashData *n = h->next;
                THashDataFree(ctx, h);
                h = n;
            }

            HRLOCK_DESTROY(&ctx->array[u]);
        }
        SCFreeAligned(ctx->array);
        ctx->array = NULL;
    }
    (void) SC_ATOMIC_SUB(ctx->memuse, ctx->config.hash_size * sizeof(THashHashRow));
    THashDataQueueDestroy(&ctx->spare_q);
    SCFree(ctx);
    return;
}

/** \brief Walk the hash
 *
 */
int THashWalk(THashTableContext *ctx, THashFormatFunc FormatterFunc, THashOutputFunc OutputterFunc, void *output_ctx)
{
    uint32_t u;

    if (ctx->array == NULL)
        return -1;

    bool err = false;
    for (u = 0; u < ctx->config.hash_size; u++) {
        THashHashRow *hb = &ctx->array[u];
        HRLOCK_LOCK(hb);
        THashData *h = hb->head;
        while (h) {
            char output_string[1024] = "";
            int size = FormatterFunc(h->data, output_string, sizeof(output_string));
            if (size > 0) {
                if (OutputterFunc(output_ctx, (const uint8_t *)output_string, size) < 0) {
                    err = true;
                    break;
                }
            }
            h = h->next;
        }
        HRLOCK_UNLOCK(hb);
        if (err == true)
            return -1;
    }
    return 0;
}

/** \brief Cleanup the thash engine
 *
 * Cleanup the thash engine from tag and threshold.
 *
 */
void THashCleanup(THashTableContext *ctx)
{
    uint32_t u;

    if (ctx->array == NULL)
        return;

    for (u = 0; u < ctx->config.hash_size; u++) {
        THashHashRow *hb = &ctx->array[u];
        HRLOCK_LOCK(hb);
        THashData *h = hb->head;
        while (h) {
            if ((SC_ATOMIC_GET(h->use_cnt) > 0)) {
                h = h->next;
            } else {
                THashData *n = h->next;
                /* remove from the hash */
                if (h->prev != NULL)
                    h->prev->next = h->next;
                if (h->next != NULL)
                    h->next->prev = h->prev;
                if (hb->head == h)
                    hb->head = h->next;
                if (hb->tail == h)
                    hb->tail = h->prev;
                h->next = NULL;
                h->prev = NULL;
                THashDataMoveToSpare(ctx, h);
                h = n;
            }
        }
        HRLOCK_UNLOCK(hb);
    }
    return;
}

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source address
 */
static uint32_t THashGetKey(const THashConfig *cnf, void *data)
{
    uint32_t key;

    key = cnf->DataHash(data);
    key %= cnf->hash_size;

    return key;
}

static inline int THashCompare(const THashConfig *cnf, void *a, void *b)
{
    if (cnf->DataCompare(a, b))
        return 1;
    return 0;
}

/**
 *  \brief Get new data
 *
 *  Get new data. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \retval h *LOCKED* data on succes, NULL on error.
 */
static THashData *THashDataGetNew(THashTableContext *ctx, void *data)
{
    THashData *h = NULL;

    /* get data from the spare queue */
    h = THashDataDequeue(&ctx->spare_q);
    if (h == NULL) {
        /* If we reached the max memcap, we get used data */
        if (!(THASH_CHECK_MEMCAP(ctx, THASH_DATA_SIZE(ctx)))) {
            h = THashGetUsed(ctx);
            if (h == NULL) {
                return NULL;
            }

            if (!SC_ATOMIC_GET(ctx->memcap_reached)) {
                SC_ATOMIC_SET(ctx->memcap_reached, true);
            }

            /* freed data, but it's unlocked */
        } else {
            /* now see if we can alloc a new data */
            h = THashDataAlloc(ctx);
            if (h == NULL) {
                return NULL;
            }

            /* data is initialized but *unlocked* */
        }
    } else {
        /* data has been recycled before it went into the spare queue */

        /* data is initialized (recylced) but *unlocked* */
    }

    // setup the data
    BUG_ON(ctx->config.DataSet(h->data, data) != 0);

    (void) SC_ATOMIC_ADD(ctx->counter, 1);
    SCMutexLock(&h->m);
    return h;
}

/*
 * returns a *LOCKED* data or NULL
 */

struct THashDataGetResult
THashGetFromHash (THashTableContext *ctx, void *data)
{
    struct THashDataGetResult res = { .data = NULL, .is_new = false, };
    THashData *h = NULL;

    /* get the key to our bucket */
    uint32_t key = THashGetKey(&ctx->config, data);
    /* get our hash bucket and lock it */
    THashHashRow *hb = &ctx->array[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has data */
    if (hb->head == NULL) {
        h = THashDataGetNew(ctx, data);
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            return res;
        }

        /* data is locked */
        hb->head = h;
        hb->tail = h;

        /* initialize and return */
        (void) THashIncrUsecnt(h);

        HRLOCK_UNLOCK(hb);
        res.data = h;
        res.is_new = true;
        return res;
    }

    /* ok, we have data in the bucket. Let's find out if it is our data */
    h = hb->head;

    /* see if this is the data we are looking for */
    if (THashCompare(&ctx->config, h->data, data) == 0) {
        THashData *ph = NULL; /* previous data */

        while (h) {
            ph = h;
            h = h->next;

            if (h == NULL) {
                h = ph->next = THashDataGetNew(ctx, data);
                if (h == NULL) {
                    HRLOCK_UNLOCK(hb);
                    return res;
                }
                hb->tail = h;

                /* data is locked */

                h->prev = ph;

                /* initialize and return */
                (void) THashIncrUsecnt(h);

                HRLOCK_UNLOCK(hb);
                res.data = h;
                res.is_new = true;
                return res;
            }

            if (THashCompare(&ctx->config, h->data, data) != 0) {
                /* we found our data, lets put it on top of the
                 * hash list -- this rewards active data */
                if (h->next) {
                    h->next->prev = h->prev;
                }
                if (h->prev) {
                    h->prev->next = h->next;
                }
                if (h == hb->tail) {
                    hb->tail = h->prev;
                }

                h->next = hb->head;
                h->prev = NULL;
                hb->head->prev = h;
                hb->head = h;

                /* found our data, lock & return */
                SCMutexLock(&h->m);
                (void) THashIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                res.data = h;
                res.is_new = false;
                /* coverity[missing_unlock : FALSE] */
                return res;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) THashIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    res.data = h;
    res.is_new = false;
    /* coverity[missing_unlock : FALSE] */
    return res;
}

/** \brief look up data in the hash
 *
 *  \param data data to look up
 *
 *  \retval h *LOCKED* data or NULL
 */
THashData *THashLookupFromHash (THashTableContext *ctx, void *data)
{
    THashData *h = NULL;

    /* get the key to our bucket */
    uint32_t key = THashGetKey(&ctx->config, data);
    /* get our hash bucket and lock it */
    THashHashRow *hb = &ctx->array[key];
    HRLOCK_LOCK(hb);

    if (hb->head == NULL) {
        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have data in the bucket. Let's find out if it is our data */
    h = hb->head;

    /* see if this is the data we are looking for */
    if (THashCompare(&ctx->config, h->data, data) == 0) {
        while (h) {
            h = h->next;
            if (h == NULL) {
                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (THashCompare(&ctx->config, h->data, data) != 0) {
                /* we found our data, lets put it on top of the
                 * hash list -- this rewards active data */
                if (h->next) {
                    h->next->prev = h->prev;
                }
                if (h->prev) {
                    h->prev->next = h->next;
                }
                if (h == hb->tail) {
                    hb->tail = h->prev;
                }

                h->next = hb->head;
                h->prev = NULL;
                hb->head->prev = h;
                hb->head = h;

                /* found our data, lock & return */
                SCMutexLock(&h->m);
                (void) THashIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) THashIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \internal
 *  \brief Get data from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is
 *  reached.
 *
 *  Walks the hash until data can be freed. "prune_idx" atomic int makes
 *  sure we don't start at the top each time since that would clear the top
 *  of the hash leading to longer and longer search times under high
 *  pressure (observed).
 *
 *  \retval h data or NULL
 */
static THashData *THashGetUsed(THashTableContext *ctx)
{
    uint32_t idx = SC_ATOMIC_GET(ctx->prune_idx) % ctx->config.hash_size;
    uint32_t cnt = ctx->config.hash_size;

    while (cnt--) {
        if (++idx >= ctx->config.hash_size)
            idx = 0;

        THashHashRow *hb = &ctx->array[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        THashData *h = hb->tail;
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        if (SCMutexTrylock(&h->m) != 0) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        if (SC_ATOMIC_GET(h->use_cnt) > 0) {
            HRLOCK_UNLOCK(hb);
            SCMutexUnlock(&h->m);
            continue;
        }

        /* remove from the hash */
        if (h->prev != NULL)
            h->prev->next = h->next;
        if (h->next != NULL)
            h->next->prev = h->prev;
        if (hb->head == h)
            hb->head = h->next;
        if (hb->tail == h)
            hb->tail = h->prev;

        h->next = NULL;
        h->prev = NULL;
        HRLOCK_UNLOCK(hb);

        if (h->data != NULL) {
            ctx->config.DataFree(h->data);
        }
        SCMutexUnlock(&h->m);

        (void) SC_ATOMIC_ADD(ctx->prune_idx, (ctx->config.hash_size - cnt));
        return h;
    }

    return NULL;
}

/**
 * \retval int -1 not found
 * \retval int 0 found, but it was busy (ref cnt)
 * \retval int 1 found and removed */
int THashRemoveFromHash (THashTableContext *ctx, void *data)
{
    /* get the key to our bucket */
    uint32_t key = THashGetKey(&ctx->config, data);
    /* get our hash bucket and lock it */
    THashHashRow *hb = &ctx->array[key];

    HRLOCK_LOCK(hb);
    THashData *h = hb->head;
    while (h != NULL) {
        /* see if this is the data we are looking for */
        if (THashCompare(&ctx->config, h->data, data) == 0) {
            h = h->next;
            continue;
        }

        SCMutexLock(&h->m);
        if (SC_ATOMIC_GET(h->use_cnt) > 0) {
            SCMutexUnlock(&h->m);
            HRLOCK_UNLOCK(hb);
            return 0;
        }

        /* remove from the hash */
        if (h->prev != NULL)
            h->prev->next = h->next;
        if (h->next != NULL)
            h->next->prev = h->prev;
        if (hb->head == h)
            hb->head = h->next;
        if (hb->tail == h)
            hb->tail = h->prev;

        h->next = NULL;
        h->prev = NULL;
        SCMutexUnlock(&h->m);
        HRLOCK_UNLOCK(hb);
        THashDataFree(ctx, h);
        SCLogDebug("found and removed");
        return 1;
    }

    HRLOCK_UNLOCK(hb);
    SCLogDebug("data not found");
    return -1;
}
