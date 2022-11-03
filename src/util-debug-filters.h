/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DEBUG_FILTERS_H__
#define __DEBUG_FILTERS_H__

// pthread_t
#include "threads.h"

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
//    pid_t t;

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

void SCLogAddToFGFFileList(SCLogFGFilterFile *,
                                         const char *,
                                         const char *, int,
                                         int);

void SCLogAddToFGFFuncList(SCLogFGFilterFile *,
                                         SCLogFGFilterFunc *,
                                         const char *, int);

void SCLogAddToFGFLineList(SCLogFGFilterFunc *,
                                         SCLogFGFilterLine *,
                                         int);

void SCLogReleaseFDFilter(SCLogFDFilter *);
#endif /* __DEBUG_H__ */
