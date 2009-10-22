/** Copyright (c) 2009 Open Information Security Foundation
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __UTIL_UNITTEST_H__
#define __UTIL_UNITTEST_H__

typedef struct UtTest_ {

    char *name;
    int(*TestFn)(void);
    int evalue;

    struct UtTest_ *next;

} UtTest;


void UtRegisterTest(char *name, int(*TestFn)(void), int evalue);
uint32_t UtRunTests(char *regex_arg);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (char *regex_arg);
void UtListTests(char *regex_arg);

#endif /* __UTIL_UNITTEST_H__ */

