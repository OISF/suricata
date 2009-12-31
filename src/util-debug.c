/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <syslog.h>

#include "util-debug.h"
#include "util-error.h"
#include "util-enum.h"
#include "util-debug-filters.h"

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "util-unittest.h"

#include "conf.h"

/* holds the string-enum mapping for the enums held in the table SCLogLevel */
SCEnumCharMap sc_log_level_map[ ] = {
    { "None",           SC_LOG_NONE },
    { "Emergency",      SC_LOG_EMERGENCY },
    { "Alert",          SC_LOG_ALERT },
    { "Critical",       SC_LOG_CRITICAL },
    { "Error",          SC_LOG_ERROR },
    { "Warning",        SC_LOG_WARNING },
    { "Notice",         SC_LOG_NOTICE },
    { "Info",           SC_LOG_INFO },
    { "Debug",          SC_LOG_DEBUG },
    { NULL,             -1 }
};

/* holds the string-enum mapping for the enums held in the table SCLogOPIface */
SCEnumCharMap sc_log_op_iface_map[ ] = {
    { "Console",        SC_LOG_OP_IFACE_CONSOLE },
    { "File",           SC_LOG_OP_IFACE_FILE },
    { "Syslog",         SC_LOG_OP_IFACE_SYSLOG },
    { NULL,             -1 }
};

/* holds the string-enum mapping for the syslog facility in SCLogOPIfaceCtx */
SCEnumCharMap sc_syslog_facility_map[] = {
    { "auth",           LOG_AUTH },
    { "authpriv",       LOG_AUTHPRIV },
    { "cron",           LOG_CRON },
    { "daemon",         LOG_DAEMON },
    { "ftp",            LOG_FTP },
    { "kern",           LOG_KERN },
    { "lpr",            LOG_LPR },
    { "mail",           LOG_MAIL },
    { "news",           LOG_NEWS },
    { "security",       LOG_AUTH },
    { "syslog",         LOG_SYSLOG },
    { "user",           LOG_USER },
    { "uucp",           LOG_UUCP },
    { "local0",         LOG_LOCAL0 },
    { "local1",         LOG_LOCAL1 },
    { "local2",         LOG_LOCAL2 },
    { "local3",         LOG_LOCAL3 },
    { "local4",         LOG_LOCAL4 },
    { "local5",         LOG_LOCAL5 },
    { "local6",         LOG_LOCAL6 },
    { "local7",         LOG_LOCAL7 },
    { NULL,             -1         }
};

/**
 * \brief Holds the config state for the logging module
 */
static SCLogConfig *sc_log_config = NULL;

/**
 * \brief Returns the full path given a file and configured log dir
 */
static char *SCLogGetLogFilename(char *);

/**
 * \brief Holds the global log level.  Is the same as sc_log_config->log_level
 */
SCLogLevel sc_log_global_log_level;

/**
 * \brief Used to indicate whether the logging module has been init or not
 */
int sc_log_module_initialized = 0;

/**
 * \brief Used to indicate whether the logging module has been cleaned or not
 */
int sc_log_module_cleaned = 0;

/**
 * \brief Maps the SC logging level to the syslog logging level
 *
 * \param The SC logging level that has to be mapped to the syslog_log_level
 *
 * \retval syslog_log_level The mapped syslog_api_log_level, for the logging
 *                          module api's internal log_level
 */
static inline int SCLogMapLogLevelToSyslogLevel(int log_level)
{
    int syslog_log_level = 0;

    switch (log_level) {
        case SC_LOG_EMERGENCY:
            syslog_log_level = LOG_EMERG;
        case SC_LOG_ALERT:
            syslog_log_level = LOG_ALERT;
        case SC_LOG_CRITICAL:
            syslog_log_level = LOG_CRIT;
        case SC_LOG_ERROR:
            syslog_log_level = LOG_ERR;
        case SC_LOG_WARNING:
            syslog_log_level = LOG_WARNING;
        case SC_LOG_NOTICE:
            syslog_log_level = LOG_NOTICE;
        case SC_LOG_INFO:
            syslog_log_level = LOG_INFO;
        case SC_LOG_DEBUG:
            syslog_log_level = LOG_DEBUG;
        default:
            syslog_log_level = LOG_EMERG;
    }

    return syslog_log_level;
}

/**
 * \brief Output function that logs a character string out to a file descriptor
 *
 * \param fd  Pointer to the file descriptor
 * \param msg Pointer to the character string that should be logged
 */
static inline void SCLogPrintToStream(FILE *fd, char *msg)
{
    if (fprintf(fd, "%s", msg) < 0)
        printf("Error writing to stream using fprintf\n");

    fflush(fd);
    return;
}

/**
 * \brief Output function that logs a character string throught the syslog iface
 *
 * \param syslog_log_level Holds the syslog_log_level that the message should be
 *                         logged as
 * \param msg              Pointer to the char string, that should be logged
 *
 * \todo syslog is thread-safe according to POSIX manual and glibc code, but we
 *       we will have to look into non POSIX compliant boxes like freeBSD
 */
static inline void SCLogPrintToSyslog(int syslog_log_level, const char *msg)
{
    //static struct syslog_data data = SYSLOG_DATA_INIT;
    //syslog_r(syslog_log_level, NULL, "%s", msg);

    syslog(syslog_log_level, "%s", msg);

    return;
}

/**
 * \brief Outputs the message sent as the argument
 *
 * \param msg       Pointer to the message that has to be logged
 * \param log_level The log_level of the message that has to be logged
 */
void SCLogOutputBuffer(SCLogLevel log_level, char *msg)
{
    char *temp = msg;
    int len = strlen(msg);
    SCLogOPIfaceCtx *op_iface_ctx = NULL;

#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return;
    }

    /* We need to add a \n for our messages, before logging them.  If the
     * messages have hit the 1023 length limit, strip the message to
     * accomodate the \n */
    if (len == SC_LOG_MAX_LOG_MSG_LEN - 1)
        len = SC_LOG_MAX_LOG_MSG_LEN - 2;

    temp[len] = '\n';
    temp[len + 1] = '\0';

    if (sc_log_config->op_filter_regex != NULL) {
        if (pcre_exec(sc_log_config->op_filter_regex,
                      sc_log_config->op_filter_regex_study,
                      msg, strlen(msg), 0, 0, ov, MAX_SUBSTRINGS) < 0)
            return;
    }

    op_iface_ctx = sc_log_config->op_ifaces;
    while (op_iface_ctx != NULL) {
        if (log_level != -1 && log_level > op_iface_ctx->log_level) {
            op_iface_ctx = op_iface_ctx->next;
            continue;
        }

        switch (op_iface_ctx->iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                SCLogPrintToStream((log_level == SC_LOG_ERROR)? stderr: stdout,
                                   msg);
                break;
            case SC_LOG_OP_IFACE_FILE:
                SCLogPrintToStream(op_iface_ctx->file_d, msg);
                break;
            case SC_LOG_OP_IFACE_SYSLOG:
                SCLogPrintToSyslog(SCLogMapLogLevelToSyslogLevel(log_level),
                                   msg);
                break;
            default:
                break;
        }
        op_iface_ctx = op_iface_ctx->next;
    }

    return;
}

/**
 * \brief Adds the global log_format to the outgoing buffer
 *
 * \param log_level log_level of the message that has to be logged
 * \param msg       Buffer containing the outgoing message
 * \param file      File_name from where the message originated
 * \param function  Function_name from where the message originated
 * \param line      Line_no from where the messaged originated
 *
 * \retval SC_OK on success; else an error code
 */
SCError SCLogMessage(SCLogLevel log_level, char **msg, const char *file,
                     unsigned line, const char *function)
{
	char *temp_fmt = strdup(sc_log_config->log_format);
    char *temp_fmt_h = temp_fmt;
	char *substr = temp_fmt;
    char *temp = *msg;
    const char *s = NULL;

    struct timeval tval;
    struct tm *tms = NULL;

    /* no of characters_written(cw) by sprintf */
    int cw = 0;

    if (temp_fmt == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if (sc_log_module_initialized != 1) {
#ifdef DEBUG
        printf("Logging module not initialized.  Call SCLogInitLogModule(), "
               "before using the logging API\n");
#endif
        return SC_LOG_MODULE_NOT_INIT;
    }

    if (sc_log_fg_filters_present == 1) {
        if (SCLogMatchFGFilterWL(file, function, line) != 1)
            return SC_LOG_FG_FILTER_MATCH_FAILED;

        if (SCLogMatchFGFilterBL(file, function, line) != 1)
            return SC_LOG_FG_FILTER_MATCH_FAILED;
    }

    if (sc_log_fd_filters_present == 1 && SCLogMatchFDFilter(function) != 1)
        return SC_LOG_FG_FILTER_MATCH_FAILED;

	while ( (temp_fmt = index(temp_fmt, SC_LOG_FMT_PREFIX)) ) {
        switch(temp_fmt[1]) {
            case SC_LOG_FMT_TIME:
                temp_fmt[0] = '\0';

                gettimeofday(&tval, NULL);
                tms = localtime(&tval.tv_sec);

                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN,
                              "%s%d/%d/%04d -- %02d:%02d:%02d",
                              substr, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec);
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_PID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%u", substr,
                              getpid());
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%lu", substr,
                              syscall(SYS_gettid));
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TM:
                temp_fmt[0] = '\0';
                ThreadVars *tv = TmThreadsGetCallingThread();
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%s", substr,
                              ((tv != NULL)? tv->name: "UNKNOWN TM"));
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LOG_LEVEL:
                temp_fmt[0] = '\0';
                s = SCMapEnumValueToName(log_level, sc_log_level_map);
                if (s != NULL)
                    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%s", substr,
                                  s);
                else
                    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%s", substr,
                                  "INVALID");
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FILE_NAME:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%s", substr,
                              file);
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LINE:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%d", substr,
                              line);
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FUNCTION:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s%s", substr,
                              function);
                if (cw < 0)
                    goto error;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

        }
        temp_fmt++;
	}
    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN, "%s", substr);
    if (cw < 0)
        goto error;

    *msg = temp + cw;

    free(temp_fmt_h);

    return SC_OK;

 error:
    return SC_SPRINTF_ERROR;
}

/**
 * \brief Returns whether debug messages are enabled to be logged or not
 *
 * \retval 1 if debug messages are enabled to be logged
 * \retval 0 if debug messages are not enabled to be logged
 */
int SCLogDebugEnabled()
{
#ifndef DEBUG
    return 0;
#endif

    if (sc_log_global_log_level == SC_LOG_DEBUG)
        return 1;
    else
        return 0;
}

/**
 * \brief Allocates an output buffer for an output interface.  Used when we
 *        want the op_interface log_format to override the global_log_format.
 *        Currently not used.
 *
 * \retval buffer Pointer to the newly created output_buffer
 */
SCLogOPBuffer *SCLogAllocLogOPBuffer(void)
{
    SCLogOPBuffer *buffer = NULL;
    SCLogOPIfaceCtx *op_iface_ctx = NULL;
    int i = 0;

    if ( (buffer = malloc(sc_log_config->op_ifaces_cnt *
                          sizeof(SCLogOPBuffer))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    op_iface_ctx = sc_log_config->op_ifaces;
    for (i = 0;
         i < sc_log_config->op_ifaces_cnt;
         i++, op_iface_ctx = op_iface_ctx->next) {
        buffer[i].log_format = op_iface_ctx->log_format;
        buffer[i].temp = buffer[i].msg;
    }

    return buffer;
}

/*----------------------The logging module initialization code--------------- */

/**
 * \brief Returns a new output_interface_context
 *
 * \retval iface_ctx Pointer to a newly allocated output_interface_context
 */
static inline SCLogOPIfaceCtx *SCLogAllocLogOPIfaceCtx()
{
    SCLogOPIfaceCtx *iface_ctx = NULL;

    if ( (iface_ctx = malloc(sizeof(SCLogOPIfaceCtx))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(iface_ctx, 0, sizeof(SCLogOPIfaceCtx));

    return iface_ctx;
}

/**
 * \brief Initializes the file output interface
 *
 * \param file       Path to the file used for logging purposes
 * \param log_format Pointer to the log_format for this op interface, that
 *                   overrides the global_log_format
 * \param log_level  Override of the global_log_level by this interface
 *
 * \retval iface_ctx Pointer to the file output interface context created
 */
static inline SCLogOPIfaceCtx *SCLogInitFileOPIface(const char *file,
                                                    const char *log_format,
                                                    int log_level)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    iface_ctx->iface = SC_LOG_OP_IFACE_FILE;

    if (file != NULL &&
        (iface_ctx->file = strdup(file)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if ( (iface_ctx->file_d = fopen(file, "w+")) == NULL) {
        printf("Error opening file %s\n", file);
        return NULL;
    }

    if (log_format != NULL &&
        (iface_ctx->log_format = strdup(log_format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    iface_ctx->log_level = log_level;

    return iface_ctx;
}

/**
 * \brief Initializes the console output interface
 *
 * \param log_format Pointer to the log_format for this op interface, that
 *                   overrides the global_log_format
 * \param log_level  Override of the global_log_level by this interface
 *
 * \retval iface_ctx Pointer to the console output interface context created
 */
static inline SCLogOPIfaceCtx *SCLogInitConsoleOPIface(const char *log_format,
                                                       int log_level)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if ( (iface_ctx = malloc(sizeof(SCLogOPIfaceCtx))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(iface_ctx, 0, sizeof(SCLogOPIfaceCtx));

    iface_ctx->iface = SC_LOG_OP_IFACE_CONSOLE;

    if (log_format != NULL &&
        (iface_ctx->log_format = strdup(log_format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    iface_ctx->log_level = log_level;

    return iface_ctx;
}

/**
 * \brief Initializes the syslog output interface
 *
 * \param facility   The facility code for syslog
 * \param log_format Pointer to the log_format for this op interface, that
 *                   overrides the global_log_format
 * \param log_level  Override of the global_log_level by this interface
 *
 * \retval iface_ctx Pointer to the syslog output interface context created
 */
static inline SCLogOPIfaceCtx *SCLogInitSyslogOPIface(int facility,
                                                      const char *log_format,
                                                      int log_level)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if ( (iface_ctx = malloc(sizeof(SCLogOPIfaceCtx))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(iface_ctx, 0, sizeof(SCLogOPIfaceCtx));

    iface_ctx->iface = SC_LOG_OP_IFACE_SYSLOG;

    if (facility == -1)
        facility = SC_LOG_DEF_SYSLOG_FACILITY;
    iface_ctx->facility = facility;

    if (log_format != NULL &&
        (iface_ctx->log_format = strdup(log_format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    iface_ctx->log_level = log_level;

    openlog(NULL, LOG_NDELAY, iface_ctx->facility);

    return iface_ctx;
}

/**
 * \brief Frees the output_interface context supplied as an argument
 *
 * \param iface_ctx Pointer to the op_interface_context to be freed
 */
static inline void SCLogFreeLogOPIfaceCtx(SCLogOPIfaceCtx *iface_ctx)
{
    SCLogOPIfaceCtx *temp = NULL;

    while (iface_ctx != NULL) {
        temp = iface_ctx;

        if (iface_ctx->file_d != NULL)
            fclose(iface_ctx->file_d);

        if (iface_ctx->file != NULL)
            free((void *)iface_ctx->file);

        if (iface_ctx->log_format != NULL)
            free((void *)iface_ctx->log_format);

        if (iface_ctx->iface == SC_LOG_OP_IFACE_SYSLOG)
            closelog();

        iface_ctx = iface_ctx->next;

        free(temp);
    }

    return;
}

/**
 * \brief Internal function used to set the logging module global_log_level
 *        during the initialization phase
 *
 * \param sc_lid The initialization data supplied.
 * \param sc_lc  The logging module context which has to be updated.
 */
static inline void SCLogSetLogLevel(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    SCLogLevel log_level = -1;
    const char *s = NULL;

    if (sc_lid != NULL)
        log_level = sc_lid->global_log_level;
    else {
        s = getenv(SC_LOG_ENV_LOG_LEVEL);
        if (s != NULL)
            log_level = SCMapEnumNameToValue(s, sc_log_level_map);
    }

    /* deal with the global_log_level to be used */
    if (log_level >= 0 && log_level < SC_LOG_LEVEL_MAX)
        sc_lc->log_level = log_level;
    else {
        sc_lc->log_level = SC_LOG_DEF_LOG_LEVEL;
#ifndef UNITTESTS
        printf("Warning: Invalid global_log_level assigned by user.  Falling "
               "back on the default_log_level \"%s\"\n",
               SCMapEnumValueToName(sc_lc->log_level, sc_log_level_map));
#endif
    }

    /* we also set it to a global var, as it is easier to access it */
    sc_log_global_log_level = sc_lc->log_level;

#ifdef DEBUG
    printf("sc_log_global_log_level: %d\n", sc_log_global_log_level);
#endif

    return;
}

/**
 * \brief Internal function used to set the logging module global_log_format
 *        during the initialization phase
 *
 * \param sc_lid The initialization data supplied.
 * \param sc_lc  The logging module context which has to be updated.
 */
static inline void SCLogSetLogFormat(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    char *format = NULL;

    if (sc_lid != NULL)
        format = sc_lid->global_log_format;
    else
        format = getenv(SC_LOG_ENV_LOG_FORMAT);

    /* deal with the global log format to be used */
    if (format == NULL || strlen(format) > SC_LOG_MAX_LOG_FORMAT_LEN) {
        format = SC_LOG_DEF_LOG_FORMAT;
#ifndef UNITTESTS
        printf("Warning: Invalid global_log_format supplied by user or format "
               "length exceeded limit of \"%d\" characters.  Falling back on "
               "default log_format \"%s\"\n", SC_LOG_MAX_LOG_FORMAT_LEN,
               format);
#endif
    }

    if (format != NULL &&
        (sc_lc->log_format = strdup(format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    printf("sc_lc->log_format: %s\n", sc_lc->log_format);
#endif

    return;
}

/**
 * \brief Internal function used to set the logging module global_op_ifaces
 *        during the initialization phase
 *
 * \param sc_lid The initialization data supplied.
 * \param sc_lc  The logging module context which has to be updated.
 */
static inline void SCLogSetOPIface(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    SCLogOPIfaceCtx *op_ifaces_ctx = NULL;
    int op_iface = 0;
    const char *s = NULL;

    if (sc_lid != NULL && sc_lid->op_ifaces != NULL) {
        sc_lc->op_ifaces = sc_lid->op_ifaces;
        sc_lid->op_ifaces = NULL;
        sc_lc->op_ifaces_cnt = sc_lid->op_ifaces_cnt;
    }
    else {
        s = getenv(SC_LOG_ENV_LOG_OP_IFACE);
        if (s != NULL) {
            op_iface = SCMapEnumNameToValue(s, sc_log_op_iface_map);

            if(op_iface < 0 || op_iface >= SC_LOG_OP_IFACE_MAX) {
                op_iface = SC_LOG_DEF_LOG_OP_IFACE;
#ifndef UNITTESTS
                printf("Warning: Invalid output interface supplied by user.  "
                       "Falling back on default_output_interface \"%s\"\n",
                       SCMapEnumValueToName(op_iface, sc_log_op_iface_map));
#endif
            }
        }
        else {
            op_iface = SC_LOG_DEF_LOG_OP_IFACE;
#ifndef UNITTESTS
            printf("Warning: Output_interface not supplied by user.  Falling "
                   "back on default_output_interface \"%s\"\n",
                   SCMapEnumValueToName(op_iface, sc_log_op_iface_map));
#endif
        }

        switch (op_iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                op_ifaces_ctx = SCLogInitConsoleOPIface(NULL, -1);
                break;
            case SC_LOG_OP_IFACE_FILE:
                s = getenv(SC_LOG_ENV_LOG_FILE);
                if (s == NULL)
                    s = SCLogGetLogFilename(SC_LOG_DEF_LOG_FILE);

                op_ifaces_ctx = SCLogInitFileOPIface(s, NULL, -1);
                break;
            case SC_LOG_OP_IFACE_SYSLOG:
                s = getenv(SC_LOG_ENV_LOG_FACILITY);
                if (s == NULL)
                    s = SC_LOG_DEF_SYSLOG_FACILITY_STR;

                op_ifaces_ctx = SCLogInitSyslogOPIface(SCMapEnumNameToValue(s, sc_syslog_facility_map), NULL, -1);
                break;
            default:
                break;
        }
        sc_lc->op_ifaces = op_ifaces_ctx;
        sc_lc->op_ifaces_cnt++;
    }

    return;
}

/**
 * \brief Internal function used to set the logging module op_filter
 *        during the initialization phase
 *
 * \param sc_lid The initialization data supplied.
 * \param sc_lc  The logging module context which has to be updated.
 */
static inline void SCLogSetOPFilter(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    const char *filter = NULL;

    int opts = 0;
    const char *ep;
    int eo = 0;

    if (sc_lid != NULL)
        filter = sc_lid->op_filter;
    else
        filter = getenv(SC_LOG_ENV_LOG_OP_FILTER);

    if (filter != NULL && strcmp(filter, "") != 0) {
        sc_lc->op_filter_regex = pcre_compile(filter, opts, &ep, &eo, NULL);
        if (sc_lc->op_filter_regex == NULL) {
            printf("pcre compile of \"%s\" failed at offset %d : %s\n", filter,
                   eo, ep);
            return;
        }

        sc_lc->op_filter_regex_study = pcre_study(sc_lc->op_filter_regex, 0,
                                                  &ep);
        if (ep != NULL) {
            printf("pcre study failed: %s\n", ep);
            return;
        }
    }

#ifdef DEBUG
    printf("SCLogSetOPFilter: filter: %s\n", filter ? filter : "<no filter>");
#endif

    return;
}

/**
 * \brief Returns a pointer to a new SCLogInitData.  This is a public interface
 *        intended to be used after the logging paramters are read from the
 *        conf file
 *
 * \retval sc_lid Pointer to the newly created SCLogInitData
 */
SCLogInitData *SCLogAllocLogInitData(void)
{
    SCLogInitData *sc_lid = NULL;

    if ( (sc_lid = malloc(sizeof(SCLogInitData))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(sc_lid, 0, sizeof(SCLogInitData));

    return sc_lid;
}

/**
 * \brief Frees a SCLogInitData
 *
 * \param sc_lid Pointer to the SCLogInitData to be freed
 */
void SCLogFreeLogInitData(SCLogInitData *sc_lid)
{
    if (sc_lid != NULL) {
        if (sc_lid->startup_message != NULL)
            free(sc_lid->startup_message);
        if (sc_lid->global_log_format != NULL)
            free(sc_lid->global_log_format);
        if (sc_lid->op_filter != NULL)
            free(sc_lid->op_filter);

        SCLogFreeLogOPIfaceCtx(sc_lid->op_ifaces);
    }

    return;
}

/**
 * \brief Frees the logging module context
 */
static inline void SCLogFreeLogConfig(SCLogConfig *sc_lc)
{
    if (sc_lc != NULL) {
        if (sc_lc->startup_message != NULL)
            free(sc_lc->startup_message);
        if (sc_lc->log_format != NULL)
            free(sc_lc->log_format);

        SCLogFreeLogOPIfaceCtx(sc_lc->op_ifaces);
        free(sc_lc);
    }

    return;
}

/**
 * \brief Appends an output_interface to the output_interface list sent in head
 *
 * \param iface_ctx Pointer to the output_interface that has to be added to head
 * \param head      Pointer to the output_interface list
 */
void SCLogAppendOPIfaceCtx(SCLogOPIfaceCtx *iface_ctx, SCLogInitData *sc_lid)
{
    SCLogOPIfaceCtx *temp = NULL, *prev = NULL;
    SCLogOPIfaceCtx **head = &sc_lid->op_ifaces;

    if (iface_ctx == NULL) {
#ifdef DEBUG
        printf("Argument(s) to SCLogAppendOPIfaceCtx() NULL\n");
#endif
        return;
    }

    temp = *head;
    while (temp != NULL) {
        prev = temp;
        temp = temp->next;
    }

    if (prev == NULL)
        *head = iface_ctx;
    else
        prev->next = iface_ctx;

    sc_lid->op_ifaces_cnt++;

    return;
}


/**
 * \brief Creates a new output interface based on the arguments sent.  The kind
 *        of output interface to be created is decided by the iface_name arg.
 *        If iface_name is "file", the arg argument will hold the filename to be
 *        used for logging purposes.  If iface_name is "syslog", the arg
 *        argument holds the facility code.  If iface_name is "console", arg is
 *        NULL.
 *
 * \param iface_name Interface name.  Can be "console", "file" or "syslog"
 * \param log_format Override for the global_log_format
 * \param log_level  Override for the global_log_level
 * \param log_level  Parameter required by a particular interface.  Explained in
 *                   the function description
 *
 * \retval iface_ctx Pointer to the newly created output interface
 */
SCLogOPIfaceCtx *SCLogInitOPIfaceCtx(const char *iface_name,
                                     const char *log_format,
                                     int log_level, const char *arg)
{
    int iface = SCMapEnumNameToValue(iface_name, sc_log_op_iface_map);

    if (log_level < SC_LOG_NONE || log_level > SC_LOG_DEBUG) {
#ifndef UNITTESTS
        printf("Warning: Supplied log_level_override for op_interface \"%s\" "
               "is invalid.  Defaulting to not specifing an override\n",
               iface_name);
#endif
        log_level = -1;
    }

    switch (iface) {
        case SC_LOG_OP_IFACE_CONSOLE:
            return SCLogInitConsoleOPIface(log_format, log_level);
        case SC_LOG_OP_IFACE_FILE:
            return SCLogInitFileOPIface(arg, log_format, log_level);
        case SC_LOG_OP_IFACE_SYSLOG:
            return SCLogInitSyslogOPIface(SCMapEnumNameToValue(arg, sc_syslog_facility_map), log_format, log_level);
        default:
#ifdef DEBUG
            printf("Output Interface \"%s\" not supported by the logging module",
                   iface_name);
#endif
            return NULL;
    }
}

/**
 * \brief Initializes the logging module
 *
 * \param sc_did The initialization data for the logging module
 *
 */
void SCLogInitLogModule(SCLogInitData *sc_lid)
{
    /* De-initialize the logging context, if it has already init by the
     * environment variables at the start of the engine */
    SCLogDeInitLogModule();

    /* sc_log_config is a global variable */
    if ( (sc_log_config = malloc(sizeof(SCLogConfig))) == NULL) {
        printf("Error Allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(sc_log_config, 0, sizeof(SCLogConfig));

    SCLogSetLogLevel(sc_lid, sc_log_config);
    SCLogSetLogFormat(sc_lid, sc_log_config);
    SCLogSetOPIface(sc_lid, sc_log_config);
    SCLogSetOPFilter(sc_lid, sc_log_config);

    sc_log_module_initialized = 1;
    sc_log_module_cleaned = 0;

    //SCOutputPrint(sc_did->startup_message);

    return;
}

void SCLogLoadConfig(void)
{
    ConfNode *outputs;

    outputs = ConfGetNode("logging.output");
    if (outputs == NULL) {
        SCLogDebug("No logging.output configuration section found.");
        return;
    }

    /* Process each output. */
    ConfNode *output;
    TAILQ_FOREACH(output, &outputs->head, next) {
        //ConfNode *param;
        char *interface = NULL;
        char *log_level = NULL;
        char *facility = NULL;
        //char *filename = NULL;
        char *format = NULL;

        interface = (char *)ConfNodeLookupChildValue(output, "interface");
        if (interface == NULL) {
            /* No interface in this item, ignore. */
            continue;
        }
        if (SCMapEnumNameToValue(interface, sc_log_op_iface_map) < 0) {
            SCLogError(SC_INVALID_ARGUMENT,
                "Invalid logging interface: %s", interface);
            exit(EXIT_FAILURE);
        }

        /* Any output may have a log-level set. */
        log_level = (char *)ConfNodeLookupChildValue(output, "log-level");

        /* Any output may have a format set. */
        format = (char *)ConfNodeLookupChildValue(output, "format");

        if (strcmp(interface, "console") == 0) {
            /* No other lookups required for console logging. */
            /* \todo Setup console logging... */
        }
        else if (strcmp(interface, "syslog") == 0) {
            facility = (char *)ConfNodeLookupChildValue(output, "facility");
            /* \todo Setup syslog logging. */
        }
        else {
            SCLogWarning(SC_UNIMPLEMENTED,
                "Ignoring unknown logging interface: %s", interface);
        }
    }
}

/**
 * \brief Initializes the logging module if the environment variables are set.
 *        Used at the start of the engine, for cases, where there is an error
 *        in the yaml parsing code, and we want to enable the logging module.
 */
void SCLogInitLogModuleIfEnvSet(void)
{
    SCLogConfig *sc_lc = NULL;
    const char *s = NULL;
    const char *filter = NULL;
    int opts = 0;
    const char *ep;
    int eo = 0;
    SCLogOPIfaceCtx *op_ifaces_ctx = NULL;
    int op_iface = 0;
    char *format = NULL;
    SCLogLevel log_level = -1;

    /* sc_log_config is a global variable */
    if ( (sc_log_config = malloc(sizeof(SCLogConfig))) == NULL) {
        printf("Error Allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(sc_log_config, 0, sizeof(SCLogConfig));
    sc_lc = sc_log_config;

    /* Check if the user has set the op_iface env var.  Only if it is set,
     * we proceed with the initialization */
    s = getenv(SC_LOG_ENV_LOG_OP_IFACE);
    if (s != NULL) {
        op_iface = SCMapEnumNameToValue(s, sc_log_op_iface_map);

        if(op_iface < 0 || op_iface >= SC_LOG_OP_IFACE_MAX) {
            op_iface = SC_LOG_DEF_LOG_OP_IFACE;
#ifndef UNITTESTS
            printf("Warning: Invalid output interface supplied by user.  "
                   "Falling back on default_output_interface \"%s\"\n",
                   SCMapEnumValueToName(op_iface, sc_log_op_iface_map));
#endif
        }
    } else {
        SCLogFreeLogConfig(sc_lc);
        sc_log_config = NULL;
        return;
    }

    switch (op_iface) {
        case SC_LOG_OP_IFACE_CONSOLE:
            op_ifaces_ctx = SCLogInitConsoleOPIface(NULL, -1);
            break;
        case SC_LOG_OP_IFACE_FILE:
            s = getenv(SC_LOG_ENV_LOG_FILE);
            if (s == NULL)
                s = SCLogGetLogFilename(SC_LOG_DEF_LOG_FILE);
            op_ifaces_ctx = SCLogInitFileOPIface(s, NULL, -1);
            break;
        case SC_LOG_OP_IFACE_SYSLOG:
            s = getenv(SC_LOG_ENV_LOG_FACILITY);
            if (s == NULL)
                s = SC_LOG_DEF_SYSLOG_FACILITY_STR;

            op_ifaces_ctx = SCLogInitSyslogOPIface(SCMapEnumNameToValue(s, sc_syslog_facility_map), NULL, -1);
            break;
        default:
            break;
    }
    sc_lc->op_ifaces = op_ifaces_ctx;


    /* Set the filter */
    filter = getenv(SC_LOG_ENV_LOG_OP_FILTER);
    if (filter != NULL && strcmp(filter, "") != 0) {
        sc_lc->op_filter_regex = pcre_compile(filter, opts, &ep, &eo, NULL);
        if (sc_lc->op_filter_regex == NULL) {
            printf("pcre compile of \"%s\" failed at offset %d : %s\n", filter,
                   eo, ep);
            return;
        }

        sc_lc->op_filter_regex_study = pcre_study(sc_lc->op_filter_regex, 0,
                                                  &ep);
        if (ep != NULL) {
            printf("pcre study failed: %s\n", ep);
            return;
        }
    }

    /* Set the log_format */
    format = getenv(SC_LOG_ENV_LOG_FORMAT);
    if (format == NULL || strlen(format) > SC_LOG_MAX_LOG_FORMAT_LEN) {
        format = SC_LOG_DEF_LOG_FORMAT;
#ifndef UNITTESTS
        printf("Warning: Invalid global_log_format supplied by user or format "
               "length exceeded limit of \"%d\" characters.  Falling back on "
               "default log_format \"%s\"\n", SC_LOG_MAX_LOG_FORMAT_LEN,
               format);
#endif
    }

    if (format != NULL &&
        (sc_lc->log_format = strdup(format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    /* Set the log_level */
    s = getenv(SC_LOG_ENV_LOG_LEVEL);
    if (s != NULL)
        log_level = SCMapEnumNameToValue(s, sc_log_level_map);

    if (log_level >= 0 && log_level < SC_LOG_LEVEL_MAX)
        sc_lc->log_level = log_level;
    else {
        sc_lc->log_level = SC_LOG_DEF_LOG_LEVEL;
#ifndef UNITTESTS
        printf("Warning: Invalid global_log_level assigned by user.  Falling "
               "back on default_log_level \"%s\"\n",
               SCMapEnumValueToName(sc_lc->log_level, sc_log_level_map));
#endif
    }

    /* we also set it to a global var, as it is easier to access it */
    sc_log_global_log_level = sc_lc->log_level;

    sc_log_module_initialized = 1;
    sc_log_module_cleaned = 0;

    return;
}

/**
 * \brief Returns a full file path given a filename uses log dir specified in
 *        conf or DEFAULT_LOG_DIR
 *
 * \param filearg The relative filename for which we want a full path include
 *                log directory
 *
 * \retval log_filename The fullpath of the logfile to open
 */
static char *SCLogGetLogFilename(char *filearg)
{
    char *log_dir;
    char *log_filename;

    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;

    log_filename = malloc(PATH_MAX);
    if (log_filename == NULL)
        return NULL;
    snprintf(log_filename, PATH_MAX, "%s/%s", log_dir, filearg);

    return log_filename;
}

/**
 * \brief De-Initializes the logging module
 */
void SCLogDeInitLogModule(void)
{
    SCLogFreeLogConfig(sc_log_config);

    /* reset the global logging_module variables */
    sc_log_global_log_level = 0;
    sc_log_module_initialized = 0;
    sc_log_module_cleaned = 1;
    sc_log_config = NULL;

    /* de-init the FD filters */
    SCLogReleaseFDFilters();
    /* de-init the FG filters */
    SCLogReleaseFGFilters();

    return;
}

//------------------------------------Unit_Tests--------------------------------

/* The logging engine should be tested to the maximum extent possible, since
 * logging code would be used throughout the codebase, and hence we can't afford
 * to have a single bug here(not that you can afford to have a bug
 * elsewhere ;) ). Please report a bug, if you get a slightest hint of a bug
 * from the logging module.
 */

#ifdef UNITTESTS

int SCLogTestInit01()
{
    int result = 1;

    /* unset any environment variables set for the logging module */
    unsetenv(SC_LOG_ENV_LOG_LEVEL);
    unsetenv(SC_LOG_ENV_LOG_OP_IFACE);
    unsetenv(SC_LOG_ENV_LOG_FORMAT);

    SCLogInitLogModule(NULL);

    if (sc_log_config == NULL)
        return 0;

    result &= (SC_LOG_DEF_LOG_LEVEL == sc_log_config->log_level);
    result &= (sc_log_config->op_ifaces != NULL &&
               SC_LOG_DEF_LOG_OP_IFACE == sc_log_config->op_ifaces->iface);
    result &= (sc_log_config->log_format != NULL &&
               strcmp(SC_LOG_DEF_LOG_FORMAT, sc_log_config->log_format) == 0);

    SCLogDeInitLogModule();

    setenv(SC_LOG_ENV_LOG_LEVEL, "Debug", 1);
    setenv(SC_LOG_ENV_LOG_OP_IFACE, "Console", 1);
    setenv(SC_LOG_ENV_LOG_FORMAT, "%n- %l", 1);

    SCLogInitLogModule(NULL);

    result &= (SC_LOG_DEBUG == sc_log_config->log_level);
    result &= (sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->iface);
    result &= (sc_log_config->log_format != NULL &&
               !strcmp("%n- %l", sc_log_config->log_format));

    unsetenv(SC_LOG_ENV_LOG_LEVEL);
    unsetenv(SC_LOG_ENV_LOG_OP_IFACE);
    unsetenv(SC_LOG_ENV_LOG_FORMAT);

    SCLogDeInitLogModule();

    return result;
}

int SCLogTestInit02()
{
    SCLogInitData *sc_lid = NULL;
    SCLogOPIfaceCtx *sc_iface_ctx = NULL;
    int result = 1;
    char *logfile = SCLogGetLogFilename("boo.txt");
    sc_lid = SCLogAllocLogInitData();
    sc_lid->startup_message = "Test02";
    sc_lid->global_log_level = SC_LOG_DEBUG;
    sc_lid->op_filter = "boo";
    sc_iface_ctx = SCLogInitOPIfaceCtx("file", "%m - %d", SC_LOG_ALERT,
                                       logfile);
    SCLogAppendOPIfaceCtx(sc_iface_ctx, sc_lid);
    sc_iface_ctx = SCLogInitOPIfaceCtx("console", NULL, SC_LOG_ERROR,
                                       NULL);
    SCLogAppendOPIfaceCtx(sc_iface_ctx, sc_lid);

    SCLogInitLogModule(sc_lid);

    if (sc_log_config == NULL)
        return 0;

    result &= (SC_LOG_DEBUG == sc_log_config->log_level);
    result &= (sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_FILE == sc_log_config->op_ifaces->iface);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->next->iface);
    result &= (sc_log_config->log_format != NULL &&
               strcmp(SC_LOG_DEF_LOG_FORMAT, sc_log_config->log_format) == 0);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->log_format != NULL &&
               strcmp("%m - %d", sc_log_config->op_ifaces->log_format) == 0);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next != NULL &&
               sc_log_config->op_ifaces->next->log_format == NULL);

    SCLogDeInitLogModule();

    sc_lid = SCLogAllocLogInitData();
    sc_lid->startup_message = "Test02";
    sc_lid->global_log_level = SC_LOG_DEBUG;
    sc_lid->op_filter = "boo";
    sc_lid->global_log_format = "kaboo";

    SCLogInitLogModule(sc_lid);

    if (sc_log_config == NULL)
        return 0;

    result &= (SC_LOG_DEBUG == sc_log_config->log_level);
    result &= (sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->iface);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next == NULL);
    result &= (sc_log_config->log_format != NULL &&
               strcmp("kaboo", sc_log_config->log_format) == 0);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->log_format == NULL);
    result &= (sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next == NULL);

    SCLogDeInitLogModule();

    return result;
}

int SCLogTestInit03()
{
    int result = 1;

    SCLogInitLogModule(NULL);

    SCLogAddFGFilterBL(NULL, "bamboo", -1);
    SCLogAddFGFilterBL(NULL, "soo", -1);
    SCLogAddFGFilterBL(NULL, "dummy", -1);

    result &= (SCLogPrintFGFilters() == 3);

    SCLogAddFGFilterBL(NULL, "dummy1", -1);
    SCLogAddFGFilterBL(NULL, "dummy2", -1);

    result &= (SCLogPrintFGFilters() == 5);

    SCLogDeInitLogModule();

    return result;
}

int SCLogTestInit04()
{
    int result = 1;

    SCLogInitLogModule(NULL);

    SCLogAddFDFilter("bamboo");
    SCLogAddFDFilter("soo");
    SCLogAddFDFilter("foo");
    SCLogAddFDFilter("roo");

    result &= (SCLogPrintFDFilters() == 4);

    SCLogAddFDFilter("loo");
    SCLogAddFDFilter("soo");

    result &= (SCLogPrintFDFilters() == 5);

    SCLogRemoveFDFilter("bamboo");
    SCLogRemoveFDFilter("soo");
    SCLogRemoveFDFilter("foo");
    SCLogRemoveFDFilter("noo");

    result &= (SCLogPrintFDFilters() == 2);

    SCLogDeInitLogModule();

    return result;
}

#endif /* UNITTESTS */

void SCLogRegisterTests()
{

#ifdef UNITTESTS

    UtRegisterTest("SCLogTestInit01", SCLogTestInit01, 1);
    UtRegisterTest("SCLogTestInit02", SCLogTestInit02, 1);
    UtRegisterTest("SCLogTestInit03", SCLogTestInit03, 1);
    UtRegisterTest("SCLogTestInit04", SCLogTestInit04, 1);

#endif /* UNITTESTS */

   return;
}
