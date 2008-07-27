/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_UNITTEST_H__
#define __UTIL_UNITTEST_H__

typedef struct _UtTest {

    char *name;
    int(*testfn)(void);
    int evalue;

    struct _UtTest *next;

} UtTest;


void UtRegisterTest(char *name, int(*testfn)(void), int evalue);
int UtRunTests(void);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (void);

#endif /* __UTIL_UNITTEST_H__ */

