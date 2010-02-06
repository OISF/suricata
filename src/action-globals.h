/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __ACTION_GLOBALS_H__
#define __ACTION_GLOBALS_H__
/* Changing them as flags, so later we can have alerts
 * and drop simultaneously */
#define ACTION_ALERT        0x01
#define ACTION_DROP         0x02
#define ACTION_REJECT       0x04
#define ACTION_REJECT_DST   0x08
#define ACTION_REJECT_BOTH  0x10
#define ACTION_PASS         0x20
#endif /* __ACTION_GLOBALS_H__ */
