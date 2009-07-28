#ifndef __TM_QUEUES_H__
#define __TM_QUEUES_H__

typedef struct Tmq_ {
    char *name;
    u_int16_t id;
    u_int16_t usecnt;
} Tmq;

Tmq* TmqCreateQueue(char *name);
Tmq* TmqGetQueueByName(char *name);


#endif /* __TM_QUEUES_H__ */

