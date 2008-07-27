#include "vips.h"
#include "tm-queues.h"

#define TMQ_MAX_QUEUES 256

static u_int16_t tmq_id = 0;
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
    u_int16_t i;

    for (i = 0; i < tmq_id; i++) {
        if (strcmp(tmqs[i].name, name) == 0)
            return &tmqs[i];
    }

    return NULL;
}

