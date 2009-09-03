#ifndef __TM_QUEUES_H__
#define __TM_QUEUES_H__

typedef struct Tmq_ {
    char *name;
    uint16_t id;
    uint16_t reader_cnt;
    uint16_t writer_cnt;
} Tmq;

Tmq* TmqCreateQueue(char *name);
Tmq* TmqGetQueueByName(char *name);

void TmqDebugList(void);
void TmqResetQueues(void);
void TmValidateQueueState(void);

#endif /* __TM_QUEUES_H__ */

