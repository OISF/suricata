/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __ACTION_GLOBALS_H__
#define __ACTION_GLOBALS_H__

typedef enum {
    ACTION_ALERT,
    ACTION_DROP,
    ACTION_REJECT,
    ACTION_REJECT_DST,
    ACTION_REJECT_BOTH,
    ACTION_PASS
} ActionType;

#endif /* __ACTION_GLOBALS_H__ */
