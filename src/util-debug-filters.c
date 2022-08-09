/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 *
 * Debug filter utility functions
 */

#include "suricata-common.h"
#include "util-debug-filters.h"

/* both of these are defined in util-debug.c */
extern int sc_log_module_initialized;
extern int sc_log_module_cleaned;

/* used to indicate if any FG filters are registered */
int sc_log_fg_filters_present = 0;

/* used to indicate if any FD filters are registered */
int sc_log_fd_filters_present = 0;

/**
 * \brief Holds the fine-grained filters
 */
SCLogFGFilterFile *sc_log_fg_filters[SC_LOG_FILTER_MAX] = { NULL, NULL };

/**
 * \brief Mutex for accessing the fine-grained filters sc_log_fg_filters
 */
static SCMutex sc_log_fg_filters_m[SC_LOG_FILTER_MAX] = { SCMUTEX_INITIALIZER,
                                                          SCMUTEX_INITIALIZER };

/**
 * \brief Holds the function-dependent filters
 */
static SCLogFDFilter *sc_log_fd_filters = NULL;

/**
 * \brief Mutex for accessing the function-dependent filters sc_log_fd_filters
 */
static SCMutex sc_log_fd_filters_m = SCMUTEX_INITIALIZER;

/**
 * \brief Holds the thread_list required by function-dependent filters
 */
static SCLogFDFilterThreadList *sc_log_fd_filters_tl = NULL;

/**
 * \brief Mutex for accessing the FD thread_list sc_log_fd_filters_tl
 */
static SCMutex sc_log_fd_filters_tl_m = SCMUTEX_INITIALIZER;

/**
 * \brief Helper function used internally to add a FG filter
 *
 * \param file     File_name of the filter
 * \param function Function_name of the filter
 * \param line     Line number of the filter
 * \param listtype The filter listtype.  Can be either a blacklist or whitelist
 *                 filter listtype(SC_LOG_FILTER_BL or SC_LOG_FILTER_WL)
 *
 * \retval  0 on successfully adding the filter;
 * \retval -1 on failure
 */
static int SCLogAddFGFilter(const char *file, const char *function,
                                   int line, int listtype)
{
    SCLogFGFilterFile *fgf_file = NULL;
    SCLogFGFilterFile *prev_fgf_file = NULL;

    SCLogFGFilterFunc *fgf_func = NULL;
    SCLogFGFilterFunc *prev_fgf_func = NULL;

    SCLogFGFilterLine *fgf_line = NULL;
    SCLogFGFilterLine *prev_fgf_line = NULL;

    int found = 0;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return -1 ;
    }

    if (file == NULL && function == NULL && line < 0) {
        printf("Error: Invalid arguments supplied to SCLogAddFGFilter\n");
        return -1;
    }

    SCMutex *m = &sc_log_fg_filters_m[listtype];

    SCMutexLock(m);

    fgf_file = sc_log_fg_filters[listtype];

    prev_fgf_file = fgf_file;
    while (fgf_file != NULL) {
        prev_fgf_file = fgf_file;
        if (file == NULL && fgf_file->file == NULL)
            found = 1;
        else if (file != NULL && fgf_file->file != NULL)
            found = (strcmp(file, fgf_file->file) == 0);
        else
            found = 0;

        if (found == 1)
            break;

        fgf_file = fgf_file->next;
    }

    if (found == 0) {
        SCLogAddToFGFFileList(prev_fgf_file, file, function, line, listtype);
        goto done;
    }

    found = 0;
    fgf_func = fgf_file->func;
    prev_fgf_func = fgf_func;
    while (fgf_func != NULL) {
        prev_fgf_func = fgf_func;
        if (function == NULL && fgf_func->func == NULL)
            found = 1;
        else if (function != NULL && fgf_func->func != NULL)
            found = (strcmp(function, fgf_func->func) == 0);
        else
            found = 0;

        if (found == 1)
            break;

        fgf_func = fgf_func->next;
    }

    if (found == 0) {
        SCLogAddToFGFFuncList(fgf_file, prev_fgf_func, function, line);
        goto done;
    }

    found = 0;
    fgf_line = fgf_func->line;
    prev_fgf_line = fgf_line;
    while(fgf_line != NULL) {
        prev_fgf_line = fgf_line;
        if (line == fgf_line->line) {
            found = 1;
            break;
        }

        fgf_line = fgf_line->next;
    }

    if (found == 0) {
        SCLogAddToFGFLineList(fgf_func, prev_fgf_line, line);
        goto done;
    }

 done:
    SCMutexUnlock(&sc_log_fg_filters_m[listtype]);
    sc_log_fg_filters_present = 1;

    return 0;
}

/**
 * \brief Internal function used to check for matches against registered FG
 *        filters.  Checks if there is a match for the incoming log_message with
 *        any of the FG filters.  Based on whether the filter type is whitelist
 *        or blacklist, the function allows the message to be logged or not.
 *
 * \param file     File_name from where the log_message originated
 * \param function Function_name from where the log_message originated
 * \param line     Line number from where the log_message originated
 * \param listtype The filter listtype.  Can be either a blacklist or whitelist
 *                 filter listtype(SC_LOG_FILTER_BL or SC_LOG_FILTER_WL)
 *
 * \retval  1 if there is a match
 * \retval  0 on no match
 * \retval -1 on failure
 */
static int SCLogMatchFGFilter(const char *file, const char *function, int line,
                              int listtype)
{
    SCLogFGFilterFile *fgf_file = NULL;
    SCLogFGFilterFunc *fgf_func = NULL;
    SCLogFGFilterLine *fgf_line = NULL;
    int match = 1;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return -1;
    }

    SCMutexLock(&sc_log_fg_filters_m[listtype]);

    fgf_file = sc_log_fg_filters[listtype];

    if (fgf_file == NULL) {
        SCMutexUnlock(&sc_log_fg_filters_m[listtype]);
        return 1;
    }

    while(fgf_file != NULL) {
        match = 1;

        match &= (fgf_file->file != NULL)? !strcmp(file, fgf_file->file): 1;

        if (match == 0) {
            fgf_file = fgf_file->next;
            continue;
        }

        fgf_func = fgf_file->func;
        while (fgf_func != NULL) {
            match = 1;

            match &= (fgf_func->func != NULL)? !strcmp(function, fgf_func->func): 1;

            if (match == 0) {
                fgf_func = fgf_func->next;
                continue;
            }

            fgf_line = fgf_func->line;
            while (fgf_line != NULL) {
                match = 1;

                match &= (fgf_line->line != -1)? (line == fgf_line->line): 1;

                if (match == 1)
                    break;

                fgf_line = fgf_line->next;
            }

            if (match == 1)
                break;

            fgf_func = fgf_func->next;
        }

        if (match == 1) {
            SCMutexUnlock(&sc_log_fg_filters_m[listtype]);
            if (listtype == SC_LOG_FILTER_WL)
                return 1;
            else
                return 0;
        }

        fgf_file = fgf_file->next;
    }

    SCMutexUnlock(&sc_log_fg_filters_m[listtype]);

    if (listtype == SC_LOG_FILTER_WL)
        return 0;
    else
        return 1;
}

/**
 * \brief Checks if there is a match for the incoming log_message with any
 *        of the FG filters.  If there is a match, it allows the message
 *        to be logged, else it rejects that message.
 *
 * \param file     File_name from where the log_message originated
 * \param function Function_name from where the log_message originated
 * \param line     Line number from where the log_message originated
 *
 * \retval  1 if there is a match
 * \retval  0 on no match
 * \retval -1 on failure
 */
int SCLogMatchFGFilterWL(const char *file, const char *function, int line)
{
    return SCLogMatchFGFilter(file, function, line, SC_LOG_FILTER_WL);
}

/**
 * \brief Checks if there is a match for the incoming log_message with any
 *        of the FG filters.  If there is a match it rejects the logging
 *        for that messages, else it allows that message to be logged
 *
 * \param file    File_name from where the log_message originated
 * \param function Function_name from where the log_message originated
 * \param line     Line number from where the log_message originated
 *
 * \retval  1 if there is a match
 * \retval  0 on no match
 * \retval -1 on failure
 */
int SCLogMatchFGFilterBL(const char *file, const char *function, int line)
{
    return SCLogMatchFGFilter(file, function, line, SC_LOG_FILTER_BL);
}

/**
 * \brief Adds a Whitelist(WL) fine-grained(FG) filter.  A FG filter WL filter
 *        allows messages that match this filter, to be logged, while the filter
 *        is defined using a file_name, function_name and line_number.
 *
 *        If a particular parameter in the fg-filter(file, function and line),
 *        shouldn't be considered while logging the message, one can supply
 *        NULL for the file_name or function_name and a negative line_no.
 *
 * \param file     File_name of the filter
 * \param function Function_name of the filter
 * \param line     Line number of the filter
 *
 * \retval  0 on successfully adding the filter;
 * \retval -1 on failure
 */
int SCLogAddFGFilterWL(const char *file, const char *function, int line)
{
    return SCLogAddFGFilter(file, function, line, SC_LOG_FILTER_WL);
}

/**
 * \brief Adds a Blacklist(BL) fine-grained(FG) filter.  A FG filter BL filter
 *        allows messages that don't match this filter, to be logged, while the
 *        filter is defined using a file_name, function_name and line_number
 *
 *        If a particular parameter in the fg-filter(file, function and line),
 *        shouldn't be considered while logging the message, one can supply
 *        NULL for the file_name or function_name and a negative line_no.
 *
 * \param file     File_name of the filter
 * \param function Function_name of the filter
 * \param line     Line number of the filter
 *
 * \retval  0 on successfully adding the filter
 * \retval -1 on failure
 */
int SCLogAddFGFilterBL(const char *file, const char *function, int line)
{
    return SCLogAddFGFilter(file, function, line, SC_LOG_FILTER_BL);
}

void SCLogReleaseFGFilters(void)
{
    SCLogFGFilterFile *fgf_file = NULL;
    SCLogFGFilterFunc *fgf_func = NULL;
    SCLogFGFilterLine *fgf_line = NULL;

    void *temp = NULL;

    int i = 0;

    for (i = 0; i < SC_LOG_FILTER_MAX; i++) {
        SCMutexLock(&sc_log_fg_filters_m[i]);

        fgf_file = sc_log_fg_filters[i];
        while (fgf_file != NULL) {

            fgf_func = fgf_file->func;
            while (fgf_func != NULL) {

                fgf_line = fgf_func->line;
                while(fgf_line != NULL) {
                    temp = fgf_line;
                    fgf_line = fgf_line->next;
                    SCFree(temp);
                }

                if (fgf_func->func != NULL)
                    SCFree(fgf_func->func);
                temp = fgf_func;
                fgf_func = fgf_func->next;
                SCFree(temp);
            }

            if (fgf_file->file != NULL)
                SCFree(fgf_file->file);
            temp = fgf_file;
            fgf_file = fgf_file->next;
            SCFree(temp);
        }

        SCMutexUnlock(&sc_log_fg_filters_m[i]);
        sc_log_fg_filters[i] = NULL;
    }

    return;
}

/**
 * \brief Prints the FG filters(both WL and BL).  Used for debugging purposes.
 *
 * \retval count The no of FG filters
 */
int SCLogPrintFGFilters()
{
    SCLogFGFilterFile *fgf_file = NULL;
    SCLogFGFilterFunc *fgf_func = NULL;
    SCLogFGFilterLine *fgf_line = NULL;

    int count = 0;
    int i = 0;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return 0;
    }

#ifdef DEBUG
    printf("Fine grained filters:\n");
#endif

    for (i = 0; i < SC_LOG_FILTER_MAX; i++) {
        SCMutexLock(&sc_log_fg_filters_m[i]);

        fgf_file = sc_log_fg_filters[i];
        while (fgf_file != NULL) {

            fgf_func = fgf_file->func;
            while (fgf_func != NULL) {

                fgf_line = fgf_func->line;
                while(fgf_line != NULL) {
#ifdef DEBUG
                    printf("%s - ", fgf_file->file);
                    printf("%s - ", fgf_func->func);
                    printf("%d\n", fgf_line->line);
#endif

                    count++;

                    fgf_line = fgf_line->next;
                }

                fgf_func = fgf_func->next;
            }

            fgf_file = fgf_file->next;
        }
        SCMutexUnlock(&sc_log_fg_filters_m[i]);
    }

    return count;
}



/* --------------------------------------------------|--------------------------
 * -------------------------- Code for the FD Filter |--------------------------
 * --------------------------------------------------V--------------------------
 */

/**
 * \brief Checks if there is a match for the incoming log_message with any
 *        of the FD filters
 *
 * \param function Function_name from where the log_message originated
 *
 * \retval 1 if there is a match
 * \retval 0 on no match;
 */
int SCLogMatchFDFilter(const char *function)
{
#ifndef DEBUG
    return 1;
#else
    SCLogFDFilterThreadList *thread_list = NULL;

    pthread_t self = pthread_self();

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return 0;
    }

    SCMutexLock(&sc_log_fd_filters_tl_m);

    if (sc_log_fd_filters_tl == NULL) {
        SCMutexUnlock(&sc_log_fd_filters_tl_m);
        if (sc_log_fd_filters != NULL)
            return 0;
        return 1;
    }

    thread_list = sc_log_fd_filters_tl;
    while (thread_list != NULL) {
        if (pthread_equal(self, thread_list->t)) {
            if (thread_list->entered > 0) {
                SCMutexUnlock(&sc_log_fd_filters_tl_m);
                return 1;
            }
            SCMutexUnlock(&sc_log_fd_filters_tl_m);
            return 0;
        }

        thread_list = thread_list->next;
    }

    SCMutexUnlock(&sc_log_fd_filters_tl_m);

    return 0;
#endif
}

/**
 * \brief Updates a FD filter, based on whether the function that calls this
 *        function, is registered as a FD filter or not.  This is called by
 *        a function only on its entry
 *
 * \param function Function_name from where the log_message originated
 *
 * \retval 1 Since it is a hack to get things working inside the macros
 */
int SCLogCheckFDFilterEntry(const char *function)
{
    SCLogFDFilter *curr = NULL;

    SCLogFDFilterThreadList *thread_list = NULL;
    SCLogFDFilterThreadList *thread_list_temp = NULL;

    //pid_t self = syscall(SYS_gettid);
    pthread_t self = pthread_self();

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return 0;
    }

    SCMutexLock(&sc_log_fd_filters_m);

    curr = sc_log_fd_filters;

    while (curr != NULL) {
        if (strcmp(function, curr->func) == 0)
            break;

        curr = curr->next;
    }

    if (curr == NULL) {
        SCMutexUnlock(&sc_log_fd_filters_m);
        return 1;
    }

    SCMutexUnlock(&sc_log_fd_filters_m);

    SCMutexLock(&sc_log_fd_filters_tl_m);

    thread_list = sc_log_fd_filters_tl;
    while (thread_list != NULL) {
        if (pthread_equal(self, thread_list->t))
            break;

        thread_list = thread_list->next;
    }

    if (thread_list != NULL) {
        thread_list->entered++;
        SCMutexUnlock(&sc_log_fd_filters_tl_m);
        return 1;
    }

    if ( (thread_list_temp = SCMalloc(sizeof(SCLogFDFilterThreadList))) == NULL) {
        SCMutexUnlock(&sc_log_fd_filters_tl_m);
        return 0;
    }
    memset(thread_list_temp, 0, sizeof(SCLogFDFilterThreadList));

    thread_list_temp->t = self;
    thread_list_temp->entered++;

    sc_log_fd_filters_tl = thread_list_temp;

    SCMutexUnlock(&sc_log_fd_filters_tl_m);

    return 1;
}

/**
 * \brief Updates a FD filter, based on whether the function that calls this
 *        function, is registered as a FD filter or not.  This is called by
 *        a function only before its exit.
 *
 * \param function Function_name from where the log_message originated
 *
 */
void SCLogCheckFDFilterExit(const char *function)
{
    SCLogFDFilter *curr = NULL;

    SCLogFDFilterThreadList *thread_list = NULL;

    //pid_t self = syscall(SYS_gettid);
    pthread_t self = pthread_self();

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return;
    }

    SCMutexLock(&sc_log_fd_filters_m);

    curr = sc_log_fd_filters;

    while (curr != NULL) {
        if (strcmp(function, curr->func) == 0)
            break;

        curr = curr->next;
    }

    if (curr == NULL) {
        SCMutexUnlock(&sc_log_fd_filters_m);
        return;
    }

    SCMutexUnlock(&sc_log_fd_filters_m);

    SCMutexLock(&sc_log_fd_filters_tl_m);

    thread_list = sc_log_fd_filters_tl;
    while (thread_list != NULL) {
        if (pthread_equal(self, thread_list->t))
            break;

        thread_list = thread_list->next;
    }

    SCMutexUnlock(&sc_log_fd_filters_tl_m);

    if (thread_list != NULL)
        thread_list->entered--;

    return;
}

/**
 * \brief Adds a Function-Dependent(FD) filter
 *
 * \param Name of the function for which a FD filter has to be registered
 *
 * \retval  0 on success
 * \retval -1 on failure
 */
int SCLogAddFDFilter(const char *function)
{
    SCLogFDFilter *curr = NULL;
    SCLogFDFilter *prev = NULL;
    SCLogFDFilter *temp = NULL;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return -1;
    }

    if (function == NULL) {
        printf("Invalid argument supplied to SCLogAddFDFilter\n");
        return -1;
    }

    SCMutexLock(&sc_log_fd_filters_m);

    curr = sc_log_fd_filters;
    while (curr != NULL) {
        prev = curr;

        if (strcmp(function, curr->func) == 0) {

            SCMutexUnlock(&sc_log_fd_filters_m);
            return 0;
        }

        curr = curr->next;
    }

    if ( (temp = SCMalloc(sizeof(SCLogFDFilter))) == NULL) {
        printf("Error Allocating memory (SCMalloc)\n");
        exit(EXIT_FAILURE);
    }
    memset(temp, 0, sizeof(SCLogFDFilter));

    if ( (temp->func = SCStrdup(function)) == NULL) {
        printf("Error Allocating memory (SCStrdup)\n");
        exit(EXIT_FAILURE);
    }

    if (sc_log_fd_filters == NULL)
        sc_log_fd_filters = temp;
    /* clang thinks prev can be NULL, but it can't be unless
     * sc_log_fd_filters is also NULL which is handled here.
     * Doing this "fix" to shut clang up. */
    else if (prev != NULL)
        prev->next = temp;

    SCMutexUnlock(&sc_log_fd_filters_m);
    sc_log_fd_filters_present = 1;

    return 0;
}

/**
 * \brief Releases all the FD filters added to the logging module
 */
void SCLogReleaseFDFilters(void)
{
    SCLogFDFilter *fdf = NULL;
    SCLogFDFilter *temp = NULL;

    SCMutexLock(&sc_log_fd_filters_m);

    fdf = sc_log_fd_filters;
    while (fdf != NULL) {
        temp = fdf;
        fdf = fdf->next;
        SCLogReleaseFDFilter(temp);
    }

    sc_log_fd_filters = NULL;

    SCMutexUnlock( &sc_log_fd_filters_m );

    return;
}

/**
 * \brief Removes a Function-Dependent(FD) filter
 *
 * \param Name of the function for which a FD filter has to be unregistered
 *
 * \retval  0 on success(the filter was removed or the filter was not present)
 * \retval -1 on failure/error
 */
int SCLogRemoveFDFilter(const char *function)
{
    SCLogFDFilter *curr = NULL;
    SCLogFDFilter *prev = NULL;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return -1 ;
    }

    if (function == NULL) {
        printf("Invalid argument(s) supplied to SCLogRemoveFDFilter\n");
        return -1;
    }

    SCMutexLock(&sc_log_fd_filters_m);

    if (sc_log_fd_filters == NULL) {
        SCMutexUnlock(&sc_log_fd_filters_m);
        return 0;
    }

    curr = sc_log_fd_filters;
    prev = curr;
    while (curr != NULL) {
        if (strcmp(function, curr->func) == 0)
            break;

        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) {

        SCMutexUnlock(&sc_log_fd_filters_m);

        return 0;
    }

    if (sc_log_fd_filters == curr)
        sc_log_fd_filters = curr->next;
    else
        prev->next = curr->next;

    SCLogReleaseFDFilter(curr);

    SCMutexUnlock(&sc_log_fd_filters_m);

    if (sc_log_fd_filters == NULL)
        sc_log_fd_filters_present = 0;

    return 0;
}

/**
 * \brief Prints the FG filters(both WL and BL).  Used for debugging purposes.
 *
 * \retval count The no of FG filters
 */
int SCLogPrintFDFilters(void)
{
    SCLogFDFilter *fdf = NULL;
    int count = 0;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return 0;
    }

#ifdef DEBUG
    printf("FD filters:\n");
#endif

    SCMutexLock(&sc_log_fd_filters_m);

    fdf = sc_log_fd_filters;
    while (fdf != NULL) {
#ifdef DEBUG
        printf("%s \n", fdf->func);
#endif
        fdf = fdf->next;
        count++;
    }

    SCMutexUnlock(&sc_log_fd_filters_m);

    return count;
}

/**
 * \brief Helper function used internally to add a FG filter.  This function is
 *        called when the file component of the incoming filter has no entry
 *        in the filter list.
 *
 * \param fgf_file The file component(basically the position in the list) from
 *                 the filter list, after which the new filter has to be added
 * \param file     File_name of the filter
 * \param function Function_name of the filter
 * \param line     Line number of the filter
 * \param listtype The filter listtype.  Can be either a blacklist or whitelist
 *                 filter listtype(SC_LOG_FILTER_BL or SC_LOG_FILTER_WL)
 */
void SCLogAddToFGFFileList(SCLogFGFilterFile *fgf_file,
                                         const char *file,
                                         const char *function, int line,
                                         int listtype)
{
    SCLogFGFilterFile *fgf_file_temp = NULL;
    SCLogFGFilterFunc *fgf_func_temp = NULL;
    SCLogFGFilterLine *fgf_line_temp = NULL;

    if ( (fgf_file_temp = SCMalloc(sizeof(SCLogFGFilterFile))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFFileList. Exiting...");
    }
    memset(fgf_file_temp, 0, sizeof(SCLogFGFilterFile));

    if ( file != NULL && (fgf_file_temp->file = SCStrdup(file)) == NULL) {
        printf("Error Allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if ( (fgf_func_temp = SCMalloc(sizeof(SCLogFGFilterFunc))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFFileList. Exiting...");
    }
    memset(fgf_func_temp, 0, sizeof(SCLogFGFilterFunc));

    if ( function != NULL && (fgf_func_temp->func = SCStrdup(function)) == NULL) {
        printf("Error Allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if ( (fgf_line_temp = SCMalloc(sizeof(SCLogFGFilterLine))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFFileList. Exiting...");
    }
    memset(fgf_line_temp, 0, sizeof(SCLogFGFilterLine));

    fgf_line_temp->line = line;

    /* add to the lists */
    fgf_func_temp->line = fgf_line_temp;

    fgf_file_temp->func = fgf_func_temp;

    if (fgf_file == NULL)
        sc_log_fg_filters[listtype] = fgf_file_temp;
    else
        fgf_file->next = fgf_file_temp;

    return;
}

/**
 * \brief Helper function used internally to add a FG filter.  This function is
 *        called when the file component of the incoming filter has an entry
 *        in the filter list, but the function component doesn't have an entry
 *        for the corresponding file component
 *
 * \param fgf_file The file component from the filter list to which the new
 *                 filter has to be added
 * \param fgf_func The function component(basically the position in the list),
 *                 from the filter list, after which the new filter has to be
 *                 added
 * \param function Function_name of the filter
 * \param line     Line number of the filter
 */
void SCLogAddToFGFFuncList(SCLogFGFilterFile *fgf_file,
                                         SCLogFGFilterFunc *fgf_func,
                                         const char *function, int line)
{
    SCLogFGFilterFunc *fgf_func_temp = NULL;
    SCLogFGFilterLine *fgf_line_temp = NULL;

    if ( (fgf_func_temp = SCMalloc(sizeof(SCLogFGFilterFunc))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFFuncList. Exiting...");
    }
    memset(fgf_func_temp, 0, sizeof(SCLogFGFilterFunc));

    if ( function != NULL && (fgf_func_temp->func = SCStrdup(function)) == NULL) {
        printf("Error Allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if ( (fgf_line_temp = SCMalloc(sizeof(SCLogFGFilterLine))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFFuncList. Exiting...");
    }
    memset(fgf_line_temp, 0, sizeof(SCLogFGFilterLine));

    fgf_line_temp->line = line;

    /* add to the lists */
    fgf_func_temp->line = fgf_line_temp;

    if (fgf_func == NULL)
        fgf_file->func = fgf_func_temp;
    else
        fgf_func->next = fgf_func_temp;

    return;
}

/**
 * \brief Helper function used internally to add a FG filter.  This function is
 *        called when the file and function components of the incoming filter
 *        have an entry in the filter list, but the line component doesn't have
 *        an entry for the corresponding function component
 *
 * \param fgf_func The function component from the filter list to which the new
 *                 filter has to be added
 * \param fgf_line The function component(basically the position in the list),
 *                 from the filter list, after which the new filter has to be
 *                 added
 * \param line     Line number of the filter
 */
void SCLogAddToFGFLineList(SCLogFGFilterFunc *fgf_func,
                                         SCLogFGFilterLine *fgf_line,
                                         int line)
{
    SCLogFGFilterLine *fgf_line_temp = NULL;

    if ( (fgf_line_temp = SCMalloc(sizeof(SCLogFGFilterLine))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAddToFGFLineList. Exiting...");
    }
    memset(fgf_line_temp, 0, sizeof(SCLogFGFilterLine));

    fgf_line_temp->line = line;

    /* add to the lists */
    if (fgf_line == NULL)
        fgf_func->line = fgf_line_temp;
    else
        fgf_line->next = fgf_line_temp;

    return;
}

/**
 * \brief Releases the memory alloted to a FD filter
 *
 * \param Pointer to the FD filter that has to be freed
 */
void SCLogReleaseFDFilter(SCLogFDFilter *fdf)
{
    if (fdf != NULL) {
        if (fdf->func != NULL)
            SCFree(fdf->func);
        SCFree(fdf);
    }

    return;
}

