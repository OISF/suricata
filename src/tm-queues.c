#include "eidps.h"
#include "threads.h"

#include "tm-queues.h"

#define TMQ_MAX_QUEUES 256

static uint16_t tmq_id = 0;
static Tmq tmqs[TMQ_MAX_QUEUES];

Tmq* TmqAlloc(void) {
    Tmq *q = malloc(sizeof(Tmq));
    if (q == NULL)
        goto error;

    memset(q, 0, sizeof(Tmq));
    return q;

error:
    return NULL;
}

Tmq* TmqCreateQueue(char *name) {
    if (tmq_id >= TMQ_MAX_QUEUES)
        goto error;

    Tmq *q = &tmqs[tmq_id];
    q->name = name;
    q->id = tmq_id++;
    return q;

error:
    return NULL;
}

Tmq* TmqGetQueueByName(char *name) {
    uint16_t i;

    for (i = 0; i < tmq_id; i++) {
        if (strcmp(tmqs[i].name, name) == 0)
            return &tmqs[i];
    }

    return NULL;
}

void TmqDebugList(void) {
    uint16_t i = 0;
    for (i = 0; i < tmq_id; i++) {
        /* get a lock accessing the len */
        mutex_lock(&trans_q[tmqs[i].id].mutex_q);
        printf("TmqDebugList: id %" PRIu32 ", name \'%s\', len %" PRIu32 "\n", tmqs[i].id, tmqs[i].name, trans_q[tmqs[i].id].len);
        mutex_unlock(&trans_q[tmqs[i].id].mutex_q);
    }
}

