/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_UNITTEST_H__
#define __UTIL_UNITTEST_H__

typedef struct UtTest_ {

    char *name;
    int(*TestFn)(void);
    int evalue;

    struct UtTest_ *next;

} UtTest;


void UtRegisterTest(char *name, int(*TestFn)(void), int evalue);
uint32_t UtRunTests(void);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (void);

#endif /* __UTIL_UNITTEST_H__ */

