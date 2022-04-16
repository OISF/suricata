/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Debug utility functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-enum.h"
#include "util-debug-filters.h"

#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threadvars.h"
#include "output.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-syslog.h"
#include "rust.h"


#include "conf.h"

/* holds the string-enum mapping for the enums held in the table SCLogLevel */
SCEnumCharMap sc_log_level_map[ ] = {
    { "Not set",        SC_LOG_NOTSET},
    { "None",           SC_LOG_NONE },
    { "Emergency",      SC_LOG_EMERGENCY },
    { "Alert",          SC_LOG_ALERT },
    { "Critical",       SC_LOG_CRITICAL },
    { "Error",          SC_LOG_ERROR },
    { "Warning",        SC_LOG_WARNING },
    { "Notice",         SC_LOG_NOTICE },
    { "Info",           SC_LOG_INFO },
    { "Perf",           SC_LOG_PERF },
    { "Config",         SC_LOG_CONFIG },
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

#if defined (OS_WIN32)
/**
 * \brief Used for synchronous output on WIN32
 */
static SCMutex sc_log_stream_lock;
#endif /* OS_WIN32 */

/**
 * \brief Holds the config state for the logging module
 */
static SCLogConfig *sc_log_config = NULL;

/**
 * \brief Returns the full path given a file and configured log dir
 */
static char *SCLogGetLogFilename(const char *);

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
            break;
        case SC_LOG_ALERT:
            syslog_log_level = LOG_ALERT;
            break;
        case SC_LOG_CRITICAL:
            syslog_log_level = LOG_CRIT;
            break;
        case SC_LOG_ERROR:
            syslog_log_level = LOG_ERR;
            break;
        case SC_LOG_WARNING:
            syslog_log_level = LOG_WARNING;
            break;
        case SC_LOG_NOTICE:
            syslog_log_level = LOG_NOTICE;
            break;
        case SC_LOG_INFO:
            syslog_log_level = LOG_INFO;
            break;
        case SC_LOG_CONFIG:
        case SC_LOG_DEBUG:
        case SC_LOG_PERF:
            syslog_log_level = LOG_DEBUG;
            break;
        default:
            syslog_log_level = LOG_EMERG;
            break;
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
    /* Would only happen if the log file failed to re-open during rotation. */
    if (fd == NULL) {
        return;
    }

#if defined (OS_WIN32)
	SCMutexLock(&sc_log_stream_lock);
#endif /* OS_WIN32 */

    if (fprintf(fd, "%s\n", msg) < 0)
        printf("Error writing to stream using fprintf\n");

    fflush(fd);

#if defined (OS_WIN32)
	SCMutexUnlock(&sc_log_stream_lock);
#endif /* OS_WIN32 */

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
 */
static int SCLogMessageJSON(struct timeval *tval, char *buffer, size_t buffer_size,
        SCLogLevel log_level, const char *file,
        unsigned line, const char *function, SCError error_code,
        const char *message)
{
    json_t *js = json_object();
    if (unlikely(js == NULL))
        goto error;
    json_t *ejs = json_object();
    if (unlikely(ejs == NULL))
        goto error;

    char timebuf[64];
    CreateIsoTimeString(tval, timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));

    const char *s = SCMapEnumValueToName(log_level, sc_log_level_map);
    if (s != NULL) {
        json_object_set_new(js, "log_level", json_string(s));
    } else {
        json_object_set_new(js, "log_level", json_string("INVALID"));
    }

    json_object_set_new(js, "event_type", json_string("engine"));

    if (error_code > 0) {
        json_object_set_new(ejs, "error_code", json_integer(error_code));
        json_object_set_new(ejs, "error", json_string(SCErrorToString(error_code)));
    }

    if (message)
        json_object_set_new(ejs, "message", json_string(message));

    if (log_level >= SC_LOG_DEBUG) {
        if (function)
            json_object_set_new(ejs, "function", json_string(function));

        if (file)
            json_object_set_new(ejs, "file", json_string(file));

        if (line > 0)
            json_object_set_new(ejs, "line", json_integer(line));
    }

    json_object_set_new(js, "engine", ejs);

    char *js_s = json_dumps(js,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);
    snprintf(buffer, buffer_size, "%s", js_s);
    free(js_s);

    json_object_del(js, "engine");
    json_object_clear(js);
    json_decref(js);

    return 0;
error:
    return -1;
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
static SCError SCLogMessageGetBuffer(
        struct timeval *tval, int color, SCLogOPType type,
                     char *buffer, size_t buffer_size,
                     const char *log_format,

                     const SCLogLevel log_level, const char *file,
                     const unsigned int line, const char *function,
                     const SCError error_code, const char *message)
{
    if (type == SC_LOG_OP_TYPE_JSON)
        return SCLogMessageJSON(tval, buffer, buffer_size, log_level, file, line, function, error_code, message);

    char *temp = buffer;
    const char *s = NULL;
    struct tm *tms = NULL;

    const char *redb = "";
    const char *red = "";
    const char *yellowb = "";
    const char *yellow = "";
    const char *green = "";
    const char *blue = "";
    const char *reset = "";
    if (color) {
        redb = "\x1b[1;31m";
        red = "\x1b[31m";
        yellowb = "\x1b[1;33m";
        yellow = "\x1b[33m";
        green = "\x1b[32m";
        blue = "\x1b[34m";
        reset = "\x1b[0m";
    }
    /* no of characters_written(cw) by snprintf */
    int cw = 0;

    BUG_ON(sc_log_module_initialized != 1);

    /* make a copy of the format string as it will be modified below */
    char local_format[strlen(log_format) + 1];
    strlcpy(local_format, log_format, sizeof(local_format));
    char *temp_fmt = local_format;
    char *substr = temp_fmt;

	while ( (temp_fmt = strchr(temp_fmt, SC_LOG_FMT_PREFIX)) ) {
        if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
            return SC_OK;
        }
        switch(temp_fmt[1]) {
            case SC_LOG_FMT_TIME:
                temp_fmt[0] = '\0';

                struct tm local_tm;
                tms = SCLocalTime(tval->tv_sec, &local_tm);

                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%d/%d/%04d -- %02d:%02d:%02d%s",
                              substr, green, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_PID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, yellow, getpid(), reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%lu%s", substr, yellow, SCGetThreadIdLong(), reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TM:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s%s", substr,
                        yellow, t_thread_name, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LOG_LEVEL:
                temp_fmt[0] = '\0';
                s = SCMapEnumValueToName(log_level, sc_log_level_map);
                if (s != NULL) {
                    if (log_level <= SC_LOG_ERROR)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, redb, s, reset);
                    else if (log_level == SC_LOG_WARNING)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, red, s, reset);
                    else if (log_level == SC_LOG_NOTICE)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, yellowb, s, reset);
                    else
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, yellow, s, reset);
                } else {
                    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s", substr, "INVALID");
                }
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FILE_NAME:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, blue, file, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LINE:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, green, line, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FUNCTION:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, green, function, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

        }
        temp_fmt++;
	}
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }
    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s", substr);
    if (cw < 0) {
        return SC_ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }

    if (error_code != SC_OK) {
        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                "[%sERRCODE%s: %s%s%s(%s%d%s)] - ", yellow, reset, red, SCErrorToString(error_code), reset, yellow, error_code, reset);
        if (cw < 0) {
            return SC_ERR_SPRINTF;
        }
        temp += cw;
        if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
            return SC_OK;
        }
    }

    const char *hi = "";
    if (error_code > SC_OK)
        hi = red;
    else if (log_level <= SC_LOG_NOTICE)
        hi = yellow;
    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s", hi, message, reset);
    if (cw < 0) {
        return SC_ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }

    if (sc_log_config->op_filter_regex != NULL) {
        if (pcre2_match(sc_log_config->op_filter_regex, (PCRE2_SPTR8)buffer, strlen(buffer), 0, 0,
                    sc_log_config->op_filter_regex_match, NULL) < 0) {
            return SC_ERR_LOG_FG_FILTER_MATCH; // bit hacky, but just return !0
        }
    }

    return SC_OK;
}

/** \internal
 *  \brief try to reopen file
 *  \note no error reporting here, as we're called by SCLogMessage
 *  \retval status 0 ok, -1 error */
static int SCLogReopen(SCLogOPIfaceCtx *op_iface_ctx)
{
    if (op_iface_ctx->file == NULL) {
        return 0;
    }

    if (op_iface_ctx->file_d != NULL) {
        fclose(op_iface_ctx->file_d);
    }
    op_iface_ctx->file_d = fopen(op_iface_ctx->file, "a");
    if (op_iface_ctx->file_d == NULL) {
        return -1;
    }
    return 0;
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
SCError SCLogMessage(const SCLogLevel log_level, const char *file,
                     const unsigned int line, const char *function,
                     const SCError error_code, const char *message)
{
    char buffer[SC_LOG_MAX_LOG_MSG_LEN] = "";
    SCLogOPIfaceCtx *op_iface_ctx = NULL;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return SC_OK;
    }

    /* get ts here so we log the same ts to each output */
    struct timeval tval;
    gettimeofday(&tval, NULL);

    op_iface_ctx = sc_log_config->op_ifaces;
    while (op_iface_ctx != NULL) {
        if (log_level != SC_LOG_NOTSET && log_level > op_iface_ctx->log_level) {
            op_iface_ctx = op_iface_ctx->next;
            continue;
        }

        switch (op_iface_ctx->iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                if (SCLogMessageGetBuffer(&tval, op_iface_ctx->use_color, op_iface_ctx->type,
                                          buffer, sizeof(buffer),
                                          op_iface_ctx->log_format ?
                                              op_iface_ctx->log_format : sc_log_config->log_format,
                                          log_level, file, line, function,
                                          error_code, message) == 0)
                {
                    SCLogPrintToStream((log_level == SC_LOG_ERROR)? stderr: stdout, buffer);
                }
                break;
            case SC_LOG_OP_IFACE_FILE:
                if (SCLogMessageGetBuffer(&tval, 0, op_iface_ctx->type, buffer, sizeof(buffer),
                                          op_iface_ctx->log_format ?
                                              op_iface_ctx->log_format : sc_log_config->log_format,
                                          log_level, file, line, function,
                                          error_code, message) == 0)
                {
                    int r = 0;
                    SCMutexLock(&op_iface_ctx->fp_mutex);
                    if (op_iface_ctx->rotation_flag) {
                        r = SCLogReopen(op_iface_ctx);
                        op_iface_ctx->rotation_flag = 0;
                    }
                    SCLogPrintToStream(op_iface_ctx->file_d, buffer);
                    SCMutexUnlock(&op_iface_ctx->fp_mutex);

                    /* report error outside of lock to avoid recursion */
                    if (r == -1) {
                        SCLogError(SC_ERR_FOPEN, "re-opening file \"%s\" failed: %s",
                                op_iface_ctx->file, strerror(errno));
                    }
                }
                break;
            case SC_LOG_OP_IFACE_SYSLOG:
                if (SCLogMessageGetBuffer(&tval, 0, op_iface_ctx->type, buffer, sizeof(buffer),
                                          op_iface_ctx->log_format ?
                                              op_iface_ctx->log_format : sc_log_config->log_format,
                                          log_level, file, line, function,
                                          error_code, message) == 0)
                {
                    SCLogPrintToSyslog(SCLogMapLogLevelToSyslogLevel(log_level), buffer);
                }
                break;
            default:
                break;
        }
        op_iface_ctx = op_iface_ctx->next;
    }
    return SC_OK;
}

void SCLog(int x, const char *file, const char *func, const int line,
        const char *fmt, ...)
{
    if (sc_log_global_log_level >= x &&
            (sc_log_fg_filters_present == 0 ||
             SCLogMatchFGFilterWL(file, func, line) == 1 ||
             SCLogMatchFGFilterBL(file, func, line) == 1) &&
            (sc_log_fd_filters_present == 0 ||
             SCLogMatchFDFilter(func) == 1))
    {
        char msg[SC_LOG_MAX_LOG_MSG_LEN];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        SCLogMessage(x, file, line, func, SC_OK, msg);
    }
}

void SCLogErr(int x, const char *file, const char *func, const int line,
        const int err, const char *fmt, ...)
{
    if (sc_log_global_log_level >= x &&
            (sc_log_fg_filters_present == 0 ||
             SCLogMatchFGFilterWL(file, func, line) == 1 ||
             SCLogMatchFGFilterBL(file, func, line) == 1) &&
            (sc_log_fd_filters_present == 0 ||
             SCLogMatchFDFilter(func) == 1))
    {
        char msg[SC_LOG_MAX_LOG_MSG_LEN];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        SCLogMessage(x, file, line, func, err, msg);
    }
}

/**
 * \brief Returns whether debug messages are enabled to be logged or not
 *
 * \retval 1 if debug messages are enabled to be logged
 * \retval 0 if debug messages are not enabled to be logged
 */
int SCLogDebugEnabled(void)
{
#ifdef DEBUG
    if (sc_log_global_log_level == SC_LOG_DEBUG)
        return 1;
    else
        return 0;
#else
    return 0;
#endif
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

    if ( (buffer = SCMalloc(sc_log_config->op_ifaces_cnt *
                          sizeof(SCLogOPBuffer))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogAllocLogOPBuffer. Exiting...");
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
 * \initonly
 */
static inline SCLogOPIfaceCtx *SCLogAllocLogOPIfaceCtx(void)
{
    SCLogOPIfaceCtx *iface_ctx = NULL;

    if ( (iface_ctx = SCMalloc(sizeof(SCLogOPIfaceCtx))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogallocLogOPIfaceCtx. Exiting...");
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
 * \initonly
 */
static inline SCLogOPIfaceCtx *SCLogInitFileOPIface(const char *file, uint32_t userid,
        uint32_t groupid, const char *log_format, int log_level, SCLogOPType type)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if (iface_ctx == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitFileOPIface. Exiting...");
    }

    if (file == NULL) {
        goto error;
    }

    iface_ctx->iface = SC_LOG_OP_IFACE_FILE;
    iface_ctx->type = type;

    if ( (iface_ctx->file_d = fopen(file, "a")) == NULL) {
        printf("Error opening file %s\n", file);
        goto error;
    }

#ifndef OS_WIN32
    if (userid != 0 || groupid != 0) {
        if (fchown(fileno(iface_ctx->file_d), userid, groupid) == -1) {
            SCLogWarning(SC_WARN_CHOWN, "Failed to change ownership of file %s: %s", file,
                    strerror(errno));
        }
    }
#endif

    if ((iface_ctx->file = SCStrdup(file)) == NULL) {
        goto error;
    }

    if (log_format != NULL && (iface_ctx->log_format = SCStrdup(log_format)) == NULL) {
        goto error;
    }

    SCMutexInit(&iface_ctx->fp_mutex, NULL);
    OutputRegisterFileRotationFlag(&iface_ctx->rotation_flag);

    iface_ctx->log_level = log_level;

    return iface_ctx;

error:
    if (iface_ctx->file != NULL) {
        SCFree((char *)iface_ctx->file);
        iface_ctx->file = NULL;
    }
    if (iface_ctx->log_format != NULL) {
        SCFree((char *)iface_ctx->log_format);
        iface_ctx->log_format = NULL;
    }
    if (iface_ctx->file_d != NULL) {
        fclose(iface_ctx->file_d);
        iface_ctx->file_d = NULL;
    }
    SCFree(iface_ctx);
    return NULL;
}

/**
 * \brief Initializes the console output interface and deals with possible
 *        env var overrides.
 *
 * \param log_format Pointer to the log_format for this op interface, that
 *                   overrides the global_log_format
 * \param log_level  Override of the global_log_level by this interface
 *
 * \retval iface_ctx Pointer to the console output interface context created
 * \initonly
 */
static inline SCLogOPIfaceCtx *SCLogInitConsoleOPIface(const char *log_format,
                                                       SCLogLevel log_level, SCLogOPType type)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if (iface_ctx == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitConsoleOPIface. Exiting...");
    }

    iface_ctx->iface = SC_LOG_OP_IFACE_CONSOLE;
    iface_ctx->type = type;

    /* console log format is overridden by envvars */
    const char *tmp_log_format = log_format;
    const char *s = getenv(SC_LOG_ENV_LOG_FORMAT);
    if (s != NULL) {
#if 0
        printf("Overriding setting for \"console.format\" because of env "
                "var SC_LOG_FORMAT=\"%s\".\n", s);
#endif
        tmp_log_format = s;
    }

    if (tmp_log_format != NULL &&
        (iface_ctx->log_format = SCStrdup(tmp_log_format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    /* console log level is overridden by envvars */
    SCLogLevel tmp_log_level = log_level;
    s = getenv(SC_LOG_ENV_LOG_LEVEL);
    if (s != NULL) {
        SCLogLevel l = SCMapEnumNameToValue(s, sc_log_level_map);
        if (l > SC_LOG_NOTSET && l < SC_LOG_LEVEL_MAX) {
#if 0
            printf("Overriding setting for \"console.level\" because of env "
                    "var SC_LOG_LEVEL=\"%s\".\n", s);
#endif
            tmp_log_level = l;
        }
    }
    iface_ctx->log_level = tmp_log_level;

#ifndef OS_WIN32
    if (isatty(fileno(stdout)) && isatty(fileno(stderr))) {
        iface_ctx->use_color = TRUE;
    }
#endif

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
                                                      SCLogLevel log_level,
                                                      SCLogOPType type)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if ( iface_ctx == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitSyslogOPIface. Exiting...");
    }

    iface_ctx->iface = SC_LOG_OP_IFACE_SYSLOG;
    iface_ctx->type = type;

    if (facility == -1)
        facility = SC_LOG_DEF_SYSLOG_FACILITY;
    iface_ctx->facility = facility;

    if (log_format != NULL &&
        (iface_ctx->log_format = SCStrdup(log_format)) == NULL) {
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

        if (iface_ctx->file_d != NULL) {
            fclose(iface_ctx->file_d);
            SCMutexDestroy(&iface_ctx->fp_mutex);
        }

        if (iface_ctx->file != NULL)
            SCFree((void *)iface_ctx->file);

        if (iface_ctx->log_format != NULL)
            SCFree((void *)iface_ctx->log_format);

        if (iface_ctx->iface == SC_LOG_OP_IFACE_SYSLOG) {
            closelog();
        }

        iface_ctx = iface_ctx->next;

        SCFree(temp);
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
    SCLogLevel log_level = SC_LOG_NOTSET;
    const char *s = NULL;

    /* envvar overrides config */
    s = getenv(SC_LOG_ENV_LOG_LEVEL);
    if (s != NULL) {
        log_level = SCMapEnumNameToValue(s, sc_log_level_map);
    } else if (sc_lid != NULL) {
        log_level = sc_lid->global_log_level;
    }

    /* deal with the global_log_level to be used */
    if (log_level > SC_LOG_NOTSET && log_level < SC_LOG_LEVEL_MAX)
        sc_lc->log_level = log_level;
    else {
        sc_lc->log_level = SC_LOG_DEF_LOG_LEVEL;
#ifndef UNITTESTS
        if (sc_lid != NULL) {
            printf("Warning: Invalid/No global_log_level assigned by user.  Falling "
                   "back on the default_log_level \"%s\"\n",
                   SCMapEnumValueToName(sc_lc->log_level, sc_log_level_map));
        }
#endif
    }

    /* we also set it to a global var, as it is easier to access it */
    sc_log_global_log_level = sc_lc->log_level;

    return;
}

SCLogLevel SCLogGetLogLevel(void)
{
    return sc_log_global_log_level;
}

static inline const char *SCLogGetDefaultLogFormat(void)
{
    const char *prog_ver = GetProgramVersion();
    if (strstr(prog_ver, "RELEASE") != NULL) {
        return SC_LOG_DEF_LOG_FORMAT_REL;
    }
    return SC_LOG_DEF_LOG_FORMAT_DEV;
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
    const char *format = NULL;

    /* envvar overrides config */
    format = getenv(SC_LOG_ENV_LOG_FORMAT);
    if (format == NULL) {
        if (sc_lid != NULL) {
            format = sc_lid->global_log_format;
        }
    }

    /* deal with the global log format to be used */
    if (format == NULL || strlen(format) > SC_LOG_MAX_LOG_FORMAT_LEN) {
        format = SCLogGetDefaultLogFormat();
#ifndef UNITTESTS
        if (sc_lid != NULL) {
            printf("Warning: Invalid/No global_log_format supplied by user or format "
                   "length exceeded limit of \"%d\" characters.  Falling back on "
                   "default log_format \"%s\"\n", SC_LOG_MAX_LOG_FORMAT_LEN,
                   format);
        }
#endif
    }

    if (format != NULL && (sc_lc->log_format = SCStrdup(format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

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
    } else {
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
            if (sc_lid != NULL) {
                printf("Warning: Output_interface not supplied by user.  Falling "
                       "back on default_output_interface \"%s\"\n",
                       SCMapEnumValueToName(op_iface, sc_log_op_iface_map));
            }
#endif
        }

        switch (op_iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                op_ifaces_ctx = SCLogInitConsoleOPIface(NULL, SC_LOG_LEVEL_MAX,0);
                break;
            case SC_LOG_OP_IFACE_FILE:
                s = getenv(SC_LOG_ENV_LOG_FILE);
                if (s == NULL) {
                    char *str = SCLogGetLogFilename(SC_LOG_DEF_LOG_FILE);
                    if (str != NULL) {
                        op_ifaces_ctx = SCLogInitFileOPIface(str, 0, 0, NULL, SC_LOG_LEVEL_MAX, 0);
                        SCFree(str);
                    }
                } else {
                    op_ifaces_ctx = SCLogInitFileOPIface(s, 0, 0, NULL, SC_LOG_LEVEL_MAX, 0);
                }
                break;
            case SC_LOG_OP_IFACE_SYSLOG:
                s = getenv(SC_LOG_ENV_LOG_FACILITY);
                if (s == NULL)
                    s = SC_LOG_DEF_SYSLOG_FACILITY_STR;

                op_ifaces_ctx = SCLogInitSyslogOPIface(SCMapEnumNameToValue(s, SCSyslogGetFacilityMap()), NULL, -1,0);
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
    int en;
    PCRE2_SIZE eo = 0;

    /* envvar overrides */
    filter = getenv(SC_LOG_ENV_LOG_OP_FILTER);
    if (filter == NULL) {
        if (sc_lid != NULL) {
            filter = sc_lid->op_filter;
        }
    }

    if (filter != NULL && strcmp(filter, "") != 0) {
        sc_lc->op_filter = SCStrdup(filter);
        if (sc_lc->op_filter == NULL) {
            printf("pcre filter alloc failed\n");
            return;
        }
        sc_lc->op_filter_regex =
                pcre2_compile((PCRE2_SPTR8)filter, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
        if (sc_lc->op_filter_regex == NULL) {
            SCFree(sc_lc->op_filter);
            PCRE2_UCHAR errbuffer[256];
            pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
            printf("pcre2 compile of \"%s\" failed at offset %d : %s\n", filter, (int)eo,
                    errbuffer);
            return;
        }
        sc_lc->op_filter_regex_match =
                pcre2_match_data_create_from_pattern(sc_lc->op_filter_regex, NULL);
    }

    return;
}

/**
 * \brief Returns a pointer to a new SCLogInitData.  This is a public interface
 *        intended to be used after the logging paramters are read from the
 *        conf file
 *
 * \retval sc_lid Pointer to the newly created SCLogInitData
 * \initonly
 */
SCLogInitData *SCLogAllocLogInitData(void)
{
    SCLogInitData *sc_lid = NULL;

    /* not using SCMalloc here because if it fails we can't log */
    if ( (sc_lid = SCMalloc(sizeof(SCLogInitData))) == NULL)
        return NULL;

    memset(sc_lid, 0, sizeof(SCLogInitData));

    return sc_lid;
}

#ifdef UNITTESTS
#ifndef OS_WIN32
/**
 * \brief Frees a SCLogInitData
 *
 * \param sc_lid Pointer to the SCLogInitData to be freed
 */
static void SCLogFreeLogInitData(SCLogInitData *sc_lid)
{
    if (sc_lid != NULL) {
        SCLogFreeLogOPIfaceCtx(sc_lid->op_ifaces);
        SCFree(sc_lid);
    }

    return;
}
#endif
#endif

/**
 * \brief Frees the logging module context
 */
static inline void SCLogFreeLogConfig(SCLogConfig *sc_lc)
{
    if (sc_lc != NULL) {
        if (sc_lc->startup_message != NULL)
            SCFree(sc_lc->startup_message);
        if (sc_lc->log_format != NULL)
            SCFree(sc_lc->log_format);
        if (sc_lc->op_filter != NULL)
            SCFree(sc_lc->op_filter);

        if (sc_lc->op_filter_regex != NULL)
            pcre2_code_free(sc_lc->op_filter_regex);
        if (sc_lc->op_filter_regex_match)
            pcre2_match_data_free(sc_lc->op_filter_regex_match);

        SCLogFreeLogOPIfaceCtx(sc_lc->op_ifaces);
        SCFree(sc_lc);
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
               "is invalid.  Defaulting to not specifying an override\n",
               iface_name);
#endif
        log_level = SC_LOG_NOTSET;
    }

    switch (iface) {
        case SC_LOG_OP_IFACE_CONSOLE:
            return SCLogInitConsoleOPIface(log_format, log_level, SC_LOG_OP_TYPE_REGULAR);
        case SC_LOG_OP_IFACE_FILE:
            return SCLogInitFileOPIface(arg, 0, 0, log_format, log_level, SC_LOG_OP_TYPE_REGULAR);
        case SC_LOG_OP_IFACE_SYSLOG:
            return SCLogInitSyslogOPIface(SCMapEnumNameToValue(arg, SCSyslogGetFacilityMap()),
                    log_format, log_level, SC_LOG_OP_TYPE_REGULAR);
        default:
#ifdef DEBUG
            printf("Output Interface \"%s\" not supported by the logging module",
                   iface_name);
#endif
            return NULL;
    }
}

/**
 * \brief Initializes the logging module.
 *
 * \param sc_lid The initialization data for the logging module.  If sc_lid is
 *               NULL, we would stick to the default configuration for the
 *               logging subsystem.
 * \initonly
 */
void SCLogInitLogModule(SCLogInitData *sc_lid)
{
    /* De-initialize the logging context, if it has already init by the
     * environment variables at the start of the engine */
    SCLogDeInitLogModule();

#if defined (OS_WIN32)
    if (SCMutexInit(&sc_log_stream_lock, NULL) != 0) {
        FatalError(SC_ERR_FATAL, "Failed to initialize log mutex.");
    }
#endif /* OS_WIN32 */

    /* sc_log_config is a global variable */
    if ( (sc_log_config = SCMalloc(sizeof(SCLogConfig))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitLogModule. Exiting...");
    }
    memset(sc_log_config, 0, sizeof(SCLogConfig));

    SCLogSetLogLevel(sc_lid, sc_log_config);
    SCLogSetLogFormat(sc_lid, sc_log_config);
    SCLogSetOPIface(sc_lid, sc_log_config);
    SCLogSetOPFilter(sc_lid, sc_log_config);

    sc_log_module_initialized = 1;
    sc_log_module_cleaned = 0;

    //SCOutputPrint(sc_did->startup_message);

    rs_log_set_level(sc_log_global_log_level);
    return;
}

void SCLogLoadConfig(int daemon, int verbose, uint32_t userid, uint32_t groupid)
{
    ConfNode *outputs;
    SCLogInitData *sc_lid;
    int have_logging = 0;
    int max_level = 0;
    SCLogLevel min_level = 0;

    /* If verbose logging was requested, set the minimum as
     * SC_LOG_NOTICE plus the extra verbosity. */
    if (verbose) {
        min_level = SC_LOG_NOTICE + verbose;
    }

    outputs = ConfGetNode("logging.outputs");
    if (outputs == NULL) {
        SCLogDebug("No logging.output configuration section found.");
        return;
    }

    sc_lid = SCLogAllocLogInitData();
    if (sc_lid == NULL) {
        SCLogDebug("Could not allocate memory for log init data");
        return;
    }

    /* Get default log level and format. */
    const char *default_log_level_s = NULL;
    if (ConfGet("logging.default-log-level", &default_log_level_s) == 1) {
        SCLogLevel default_log_level =
            SCMapEnumNameToValue(default_log_level_s, sc_log_level_map);
        if (default_log_level == -1) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid default log level: %s",
                default_log_level_s);
            exit(EXIT_FAILURE);
        }
        sc_lid->global_log_level = MAX(min_level, default_log_level);
    }
    else {
        sc_lid->global_log_level = MAX(min_level, SC_LOG_NOTICE);
    }

    if (ConfGet("logging.default-log-format", &sc_lid->global_log_format) != 1)
        sc_lid->global_log_format = SCLogGetDefaultLogFormat();

    (void)ConfGet("logging.default-output-filter", &sc_lid->op_filter);

    ConfNode *seq_node, *output;
    TAILQ_FOREACH(seq_node, &outputs->head, next) {
        SCLogLevel level = sc_lid->global_log_level;
        SCLogOPIfaceCtx *op_iface_ctx = NULL;
        const char *format;
        const char *level_s;

        output = ConfNodeLookupChild(seq_node, seq_node->val);
        if (output == NULL)
            continue;

        /* By default an output is enabled. */
        const char *enabled = ConfNodeLookupChildValue(output, "enabled");
        if (enabled != NULL && ConfValIsFalse(enabled))
            continue;

        SCLogOPType type = SC_LOG_OP_TYPE_REGULAR;
        const char *type_s = ConfNodeLookupChildValue(output, "type");
        if (type_s != NULL) {
            if (strcmp(type_s, "regular") == 0)
                type = SC_LOG_OP_TYPE_REGULAR;
            else if (strcmp(type_s, "json") == 0) {
                type = SC_LOG_OP_TYPE_JSON;
            }
        }

        /* if available use the log format setting for this output,
         * otherwise fall back to the global setting. */
        format = ConfNodeLookupChildValue(output, "format");
        if (format == NULL)
            format = sc_lid->global_log_format;

        level_s = ConfNodeLookupChildValue(output, "level");
        if (level_s != NULL) {
            level = SCMapEnumNameToValue(level_s, sc_log_level_map);
            if (level == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid log level: %s",
                    level_s);
                exit(EXIT_FAILURE);
            }
            max_level = MAX(max_level, level);
        }

        /* Increase the level of extra verbosity was requested. */
        level = MAX(min_level, level);

        if (strcmp(output->name, "console") == 0) {
            op_iface_ctx = SCLogInitConsoleOPIface(format, level, type);
        }
        else if (strcmp(output->name, "file") == 0) {
            const char *filename = ConfNodeLookupChildValue(output, "filename");
            if (filename == NULL) {
                    FatalError(SC_ERR_FATAL,
                               "Logging to file requires a filename");
            }
            char *path = NULL;
            if (!(PathIsAbsolute(filename))) {
                path = SCLogGetLogFilename(filename);
            } else {
                path = SCStrdup(filename);
            }
            if (path == NULL)
                FatalError(SC_ERR_FATAL, "failed to setup output to file");
            have_logging = 1;
            op_iface_ctx = SCLogInitFileOPIface(path, userid, groupid, format, level, type);
            SCFree(path);
        }
        else if (strcmp(output->name, "syslog") == 0) {
            int facility = SC_LOG_DEF_SYSLOG_FACILITY;
            const char *facility_s = ConfNodeLookupChildValue(output,
                "facility");
            if (facility_s != NULL) {
                facility = SCMapEnumNameToValue(facility_s, SCSyslogGetFacilityMap());
                if (facility == -1) {
                    SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid syslog "
                            "facility: \"%s\", now using \"%s\" as syslog "
                            "facility", facility_s, SC_LOG_DEF_SYSLOG_FACILITY_STR);
                    facility = SC_LOG_DEF_SYSLOG_FACILITY;
                }
            }
            SCLogDebug("Initializing syslog logging with format \"%s\"", format);
            have_logging = 1;
            op_iface_ctx = SCLogInitSyslogOPIface(facility, format, level, type);
        }
        else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid logging method: %s, "
                "ignoring", output->name);
        }
        if (op_iface_ctx != NULL) {
            SCLogAppendOPIfaceCtx(op_iface_ctx, sc_lid);
        }
    }

    if (daemon && (have_logging == 0)) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                   "NO logging compatible with daemon mode selected,"
                   " suricata won't be able to log. Please update "
                   " 'logging.outputs' in the YAML.");
    }

    /* Set the global log level to that of the max level used. */
    sc_lid->global_log_level = MAX(sc_lid->global_log_level, max_level);
    SCLogInitLogModule(sc_lid);

    SCLogDebug("sc_log_global_log_level: %d", sc_log_global_log_level);
    SCLogDebug("sc_lc->log_format: %s", sc_log_config->log_format);
    SCLogDebug("SCLogSetOPFilter: filter: %s", sc_log_config->op_filter);

    if (sc_lid != NULL)
        SCFree(sc_lid);
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
static char *SCLogGetLogFilename(const char *filearg)
{
    const char *log_dir = ConfigGetLogDirectory();
    char *log_filename = SCMalloc(PATH_MAX);
    if (unlikely(log_filename == NULL))
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

#if defined (OS_WIN32)
    SCMutexDestroy(&sc_log_stream_lock);
#endif /* OS_WIN32 */

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

static int SCLogTestInit01(void)
{
#ifndef OS_WIN32
    /* unset any environment variables set for the logging module */
    unsetenv(SC_LOG_ENV_LOG_LEVEL);
    unsetenv(SC_LOG_ENV_LOG_OP_IFACE);
    unsetenv(SC_LOG_ENV_LOG_FORMAT);

    SCLogInitLogModule(NULL);

    FAIL_IF_NULL(sc_log_config);

    FAIL_IF_NOT(SC_LOG_DEF_LOG_LEVEL == sc_log_config->log_level);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               SC_LOG_DEF_LOG_OP_IFACE == sc_log_config->op_ifaces->iface);
    FAIL_IF_NOT(sc_log_config->log_format != NULL &&
               strcmp(SCLogGetDefaultLogFormat(), sc_log_config->log_format) == 0);

    SCLogDeInitLogModule();

    setenv(SC_LOG_ENV_LOG_LEVEL, "Debug", 1);
    setenv(SC_LOG_ENV_LOG_OP_IFACE, "Console", 1);
    setenv(SC_LOG_ENV_LOG_FORMAT, "%n- %l", 1);

    SCLogInitLogModule(NULL);

    FAIL_IF_NOT(SC_LOG_DEBUG == sc_log_config->log_level);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->iface);
    FAIL_IF_NOT(sc_log_config->log_format != NULL &&
               !strcmp("%n- %l", sc_log_config->log_format));

    unsetenv(SC_LOG_ENV_LOG_LEVEL);
    unsetenv(SC_LOG_ENV_LOG_OP_IFACE);
    unsetenv(SC_LOG_ENV_LOG_FORMAT);

    SCLogDeInitLogModule();
#endif
    PASS;
}

static int SCLogTestInit02(void)
{
#ifndef OS_WIN32
    SCLogInitData *sc_lid = NULL;
    SCLogOPIfaceCtx *sc_iface_ctx = NULL;
    char *logfile = SCLogGetLogFilename("boo.txt");
    sc_lid = SCLogAllocLogInitData();
    FAIL_IF_NULL(sc_lid);
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

    FAIL_IF_NULL(sc_log_config);

    FAIL_IF_NOT(SC_LOG_DEBUG == sc_log_config->log_level);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_FILE == sc_log_config->op_ifaces->iface);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->next->iface);
    FAIL_IF_NOT(sc_log_config->log_format != NULL &&
               strcmp(SCLogGetDefaultLogFormat(), sc_log_config->log_format) == 0);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->log_format != NULL &&
               strcmp("%m - %d", sc_log_config->op_ifaces->log_format) == 0);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next != NULL &&
               sc_log_config->op_ifaces->next->log_format == NULL);

    SCLogFreeLogInitData(sc_lid);
    SCLogDeInitLogModule();

    sc_lid = SCLogAllocLogInitData();
    FAIL_IF_NULL(sc_lid);
    sc_lid->startup_message = "Test02";
    sc_lid->global_log_level = SC_LOG_DEBUG;
    sc_lid->op_filter = "boo";
    sc_lid->global_log_format = "kaboo";

    SCLogInitLogModule(sc_lid);

    FAIL_IF_NULL(sc_log_config);

    FAIL_IF_NOT(SC_LOG_DEBUG == sc_log_config->log_level);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               SC_LOG_OP_IFACE_CONSOLE == sc_log_config->op_ifaces->iface);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next == NULL);
    FAIL_IF_NOT(sc_log_config->log_format != NULL &&
               strcmp("kaboo", sc_log_config->log_format) == 0);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->log_format == NULL);
    FAIL_IF_NOT(sc_log_config->op_ifaces != NULL &&
               sc_log_config->op_ifaces->next == NULL);

    SCLogFreeLogInitData(sc_lid);
    SCLogDeInitLogModule();
    SCFree(logfile);
#endif
    PASS;
}

static int SCLogTestInit03(void)
{
    SCLogInitLogModule(NULL);

    SCLogAddFGFilterBL(NULL, "bamboo", -1);
    SCLogAddFGFilterBL(NULL, "soo", -1);
    SCLogAddFGFilterBL(NULL, "dummy", -1);

    FAIL_IF_NOT(SCLogPrintFGFilters() == 3);

    SCLogAddFGFilterBL(NULL, "dummy1", -1);
    SCLogAddFGFilterBL(NULL, "dummy2", -1);

    FAIL_IF_NOT(SCLogPrintFGFilters() == 5);

    SCLogDeInitLogModule();

    PASS;
}

static int SCLogTestInit04(void)
{
    SCLogInitLogModule(NULL);

    SCLogAddFDFilter("bamboo");
    SCLogAddFDFilter("soo");
    SCLogAddFDFilter("foo");
    SCLogAddFDFilter("roo");

    FAIL_IF_NOT(SCLogPrintFDFilters() == 4);

    SCLogAddFDFilter("loo");
    SCLogAddFDFilter("soo");

    FAIL_IF_NOT(SCLogPrintFDFilters() == 5);

    SCLogRemoveFDFilter("bamboo");
    SCLogRemoveFDFilter("soo");
    SCLogRemoveFDFilter("foo");
    SCLogRemoveFDFilter("noo");

    FAIL_IF_NOT(SCLogPrintFDFilters() == 2);

    SCLogDeInitLogModule();

    PASS;
}

static int SCLogTestInit05(void)
{
    char str[4096];
    memset(str, 'A', sizeof(str));
    SCLogInfo("%s", str);

    PASS;
}

#endif /* UNITTESTS */

void SCLogRegisterTests()
{

#ifdef UNITTESTS

    UtRegisterTest("SCLogTestInit01", SCLogTestInit01);
    UtRegisterTest("SCLogTestInit02", SCLogTestInit02);
    UtRegisterTest("SCLogTestInit03", SCLogTestInit03);
    UtRegisterTest("SCLogTestInit04", SCLogTestInit04);
    UtRegisterTest("SCLogTestInit05", SCLogTestInit05);

#endif /* UNITTESTS */

   return;
}
