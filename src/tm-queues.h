#ifndef __TM_QUEUES_H__
#define __TM_QUEUES_H__

typedef struct Tmq_ {
    char *name;
    uint16_t id;
    uint16_t usecnt;
} Tmq;

Tmq* TmqCreateQueue(char *name);
Tmq* TmqGetQueueByName(char *name);

void TmqDebugList(void);

#endif /* __TM_QUEUES_H__ */

