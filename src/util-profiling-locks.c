/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * An API for profiling locks.
 *
 */

#include "suricata-common.h"
#include "util-profiling-locks.h"
#include "util-hashlist.h"

#ifdef PROFILING
#ifdef PROFILE_LOCKING

__thread ProfilingLock locks[PROFILING_MAX_LOCKS];
__thread int locks_idx = 0;
__thread int record_locks = 0;

int profiling_locks_enabled = 0;
int profiling_locks_output_to_file = 0;
char *profiling_locks_file_name = NULL;
const char *profiling_locks_file_mode = "a";

typedef struct LockRecord_ {
    char *file; // hash

    char *func; // info
    int type;   // info

    int line;   // hash

    uint32_t cont;
    uint32_t ticks_cnt;
    uint64_t ticks_total;
    uint64_t ticks_max;
} LockRecord;

HashListTable *lock_records;
pthread_mutex_t lock_records_mutex;

static uint32_t LockRecordHash(HashListTable *ht, void *buf, uint16_t buflen)
{
     LockRecord *fn = (LockRecord *)buf;
     uint32_t hash = strlen(fn->file) + fn->line;
     uint16_t u;

     for (u = 0; u < strlen(fn->file); u++) {
         hash += fn->file[u];
     }

     return hash % ht->array_size;
}

static char LockRecordCompare(void *buf1, uint16_t len1, void *buf2, uint16_t len2)
{
    LockRecord *fn1 = (LockRecord *)buf1;
    LockRecord *fn2 = (LockRecord *)buf2;

    if (fn1->line != fn2->line)
        return 0;

    if (fn1->file == fn2->file)
        return 1;

    return 0;
}

static void LockRecordFree(void *data)
{
    LockRecord *fn = (LockRecord *)data;

    if (fn == NULL)
        return;
    SCFree(fn);
}

int LockRecordInitHash()
{
    pthread_mutex_init(&lock_records_mutex, NULL);
    pthread_mutex_lock(&lock_records_mutex);

    lock_records = HashListTableInit(512, LockRecordHash, LockRecordCompare, LockRecordFree);
    BUG_ON(lock_records == NULL);

    pthread_mutex_unlock(&lock_records_mutex);

    return 0;
}

static void LockRecordAdd(ProfilingLock *l)
{
    LockRecord fn = { NULL, NULL, 0,0,0,0,0,0}, *ptr = &fn;
    fn.file = l->file;
    fn.line = l->line;

    LockRecord *lookup_fn = (LockRecord *)HashListTableLookup(lock_records, (void *)ptr, 0);
    if (lookup_fn == NULL) {
        LockRecord *new = SCMalloc(sizeof(LockRecord));
        BUG_ON(new == NULL);

        new->file = l->file;
        new->line = l->line;
        new->type = l->type;
        new->cont = l->cont;
        new->func = l->func;
        new->ticks_max = l->ticks;
        new->ticks_total = l->ticks;
        new->ticks_cnt = 1;

        HashListTableAdd(lock_records, (void *)new, 0);
    } else {
        lookup_fn->ticks_total += l->ticks;
        if (l->ticks > lookup_fn->ticks_max)
            lookup_fn->ticks_max = l->ticks;
        lookup_fn->ticks_cnt++;
        lookup_fn->cont += l->cont;
    }

    return;
}

/** \param p void ptr to Packet struct */
void SCProfilingAddPacketLocks(void *p)
{
    int i;

    if (profiling_locks_enabled == 0)
        return;

    for (i = 0; i < locks_idx; i++) {
        pthread_mutex_lock(&lock_records_mutex);
        LockRecordAdd(&locks[i]);
        pthread_mutex_unlock(&lock_records_mutex);
    }
}

static void SCProfilingListLocks(void)
{
    FILE *fp = NULL;

    if (profiling_locks_output_to_file == 1) {
        fp = fopen(profiling_locks_file_name, profiling_locks_file_mode);

        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s",
                    profiling_locks_file_name, strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    fprintf(fp, "\n\nLock                                               Cnt        Avg ticks Max ticks    Total ticks  Cont    Func\n");
    fprintf(fp,     "------------------                                 ---------- --------- ------------ ------------ ------- ---------\n");

    uint64_t total = 0;
    uint32_t cont = 0;
    uint64_t cnt = 0;

    HashListTableBucket *b = HashListTableGetListHead(lock_records);
    while (b) {
        LockRecord *r = HashListTableGetListData(b);

        const char *lock;
        switch (r->type) {
            case LOCK_MUTEX:
                lock = "mtx";
                break;
            case LOCK_SPIN:
                lock = "spn";
                break;
            case LOCK_RWW:
                lock = "rww";
                break;
            case LOCK_RWR:
                lock = "rwr";
                break;
            default:
                lock = "bug";
                break;
        }

        char str[128] = "";
        snprintf(str, sizeof(str), "(%s) %s:%d", lock,r->file, r->line);

        fprintf(fp, "%-50s %-10u %-9"PRIu64" %-12"PRIu64" %-12"PRIu64" %-7u %-s\n",
            str, r->ticks_cnt, (uint64_t)((uint64_t)r->ticks_total/(uint64_t)r->ticks_cnt), r->ticks_max, r->ticks_total, r->cont, r->func);

        total += r->ticks_total;
        cnt += r->ticks_cnt;
        cont += r->cont;

        b = HashListTableGetListNext(b);
    }

    fprintf(fp, "\nOverall: locks %"PRIu64", average cost %"PRIu64", contentions %"PRIu32", total ticks %"PRIu64"\n",
        cnt, (uint64_t)((uint64_t)total/(uint64_t)cnt), cont, total);

    fclose(fp);
}

void LockRecordFreeHash()
{
    if (profiling_locks_enabled == 0)
        return;

    pthread_mutex_lock(&lock_records_mutex);

    SCProfilingListLocks();

    if (lock_records != NULL) {
        HashListTableFree(lock_records);
        lock_records = NULL;
    }
    pthread_mutex_unlock(&lock_records_mutex);

    pthread_mutex_destroy(&lock_records_mutex);
}

#endif
#endif

