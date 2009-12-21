/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __DEBUG_FILTERS_H__
#define __DEBUG_FILTERS_H__

#include <pthread.h>
#include "threads.h"

/**
 * \brief extra defines needed for FreeBSD
 */
#ifdef OS_FREEBSD
#ifndef SYS_gettid
#if __i386__
#define SYS_gettid 224
#elif __amd64__
#define SYS_gettid 186
#endif /* cpu arch */
#endif /* SYS_gettid */
#endif /* OS_FREEBSD */

/**
 * \brief Enum that holds the different kinds of filters available
 */
enum {
    SC_LOG_FILTER_BL = 0,
    SC_LOG_FILTER_WL = 1,
    SC_LOG_FILTER_MAX = 2,
};

/**
 * \brief Structure used to hold the line_no details of a FG filter
 */
typedef struct SCLogFGFilterLine_ {
    int line;

    struct SCLogFGFilterLine_ *next;
} SCLogFGFilterLine;

/**
 * \brief structure used to hold the function details of a FG filter
 */
typedef struct SCLogFGFilterFunc_ {
    char *func;
    SCLogFGFilterLine *line;

    struct SCLogFGFilterFunc_ *next;
} SCLogFGFilterFunc;

/**
 * \brief Structure used to hold FG filters.  Encapsulates filename details,
 *        func details, which inturn encapsulates the line_no details
 */
typedef struct SCLogFGFilterFile_ {
    char *file;
    SCLogFGFilterFunc *func;

    struct SCLogFGFilterFile_ *next;
} SCLogFGFilterFile;

/**
 * \brief Structure used to hold the thread_list used by FD filters
 */
typedef struct SCLogFDFilterThreadList_ {
    int entered;
    pthread_t t;

    struct SCLogFDFilterThreadList_ *next;
} SCLogFDFilterThreadList;

/**
 * \brief Structure that holds the FD filters
 */
typedef struct SCLogFDFilter_ {
    char *func;

    struct SCLogFDFilter_ *next;
} SCLogFDFilter;


extern int sc_log_fg_filters_present;

extern int sc_log_fd_filters_present;


int SCLogAddFGFilterWL(const char *, const char *, int);

int SCLogAddFGFilterBL(const char *, const char *, int);

int SCLogMatchFGFilterBL(const char *, const char *, int);

int SCLogMatchFGFilterWL(const char *, const char *, int);

void SCLogReleaseFGFilters(void);

int SCLogAddFDFilter(const char *);

int SCLogPrintFDFilters(void);

void SCLogReleaseFDFilters(void);

int SCLogRemoveFDFilter(const char *);

int SCLogCheckFDFilterEntry(const char *);

void SCLogCheckFDFilterExit(const char *);

int SCLogMatchFDFilter(const char *);

int SCLogPrintFGFilters(void);

#endif /* __DEBUG_H__ */
