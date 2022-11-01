/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 *
 * Common custom logging format
 */

#include "log-cf-common.h"
#include "util-print.h"
#include "util-time.h"
#include "util-debug.h"

/**
 *  \brief Creates a custom format node
 *  \retval LogCustomFormatNode * ptr if created
 *  \retval NULL if failed to allocate
 */
LogCustomFormatNode * LogCustomFormatNodeAlloc()
{
    LogCustomFormatNode * node = SCCalloc(1, sizeof(LogCustomFormatNode));
    if (unlikely(node == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to alloc custom format node");
        return NULL;
    }
    return node;
}

/**
 *  \brief Creates a custom format.
 *  \retval LogCustomFormat * ptr if created
 *  \retval NULL if failed to allocate
 */
LogCustomFormat * LogCustomFormatAlloc()
{
    LogCustomFormat * cf = SCCalloc(1, sizeof(LogCustomFormat));
    if (unlikely(cf == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to alloc custom format");
        return NULL;
    }
    return cf;
}

/**
 *  \brief Frees memory held by a custom format node
 *  \param LogCustomFormatNode * node - node to relaease
 */
void LogCustomFormatNodeFree(LogCustomFormatNode *node)
{
    if (node==NULL)
        return;

    SCFree(node);
}

/**
 *  \brief Frees memory held by a custom format
 *  \param LogCustomFormat * cf - format to relaease
 */
void LogCustomFormatFree(LogCustomFormat *cf)
{
    if (cf==NULL)
        return;

    for (size_t i = 0; i < cf->cf_n; ++i) {
        LogCustomFormatNodeFree(cf->cf_nodes[i]);
    }
    SCFree(cf);
}

/**
 *  \brief Parses and saves format nodes for custom format
 *  \param LogCustomFormat * cf - custom format to build
 *  \param const char * format - string with format specification
 */
int LogCustomFormatParse(LogCustomFormat *cf, const char *format)
{
    const char *p, *np;
    uint32_t n;
    LogCustomFormatNode *node = NULL;

    if (cf==NULL)
        return 0;

    if (format==NULL)
        return 0;

    p=format;

    for (cf->cf_n = 0; cf->cf_n < LOG_MAXN_NODES-1 && p && *p != '\0';){

        node = LogCustomFormatNodeAlloc();
        if (node == NULL) {
            goto parsererror;
        }
        node->maxlen = 0;

        if (*p != '%'){
            /* Literal found in format string */
            node->type = LOG_CF_LITERAL;
            np = strchr(p, '%');
            if (np == NULL){
                n = LOG_NODE_STRLEN-2;
                np = NULL; /* End */
            }else{
                n = np-p;
            }
            strlcpy(node->data,p,n+1);
            p = np;
        } else {
            /* Non Literal found in format string */
            p++;
            if (*p == '[') { /* Check if maxlength has been specified (ie: [25]) */
                p++;
                np = strchr(p, ']');
                if (np != NULL) {
                    if (np-p > 0 && np-p < 10){
                        long maxlen = strtol(p,NULL,10);
                        if (maxlen > 0 && maxlen < LOG_NODE_MAXOUTPUTLEN) {
                            node->maxlen = (uint32_t) maxlen;
                        }
                    } else {
                        goto parsererror;
                    }
                    p = np + 1;
                } else {
                    goto parsererror;
                }
            }
            if (*p == '{') { /* Simple format char */
                np = strchr(p, '}');
                if (np != NULL && np-p > 1 && np-p < LOG_NODE_STRLEN-2) {
                    p++;
                    n = np-p;
                    strlcpy(node->data, p, n+1);
                    p = np;
                } else {
                    goto parsererror;
                }
                p++;
            } else {
                node->data[0] = '\0';
            }
            node->type = *p;
            if (*p == '%'){
                node->type = LOG_CF_LITERAL;
                strlcpy(node->data, "%", 2);
            }
            p++;
        }
        LogCustomFormatAddNode(cf, node);
    }
    return 1;

parsererror:
    LogCustomFormatNodeFree(node);
    return 0;
}

/**
 *  \brief Adds a node to custom format
 *  \param LogCustomFormat * cf - custom format
 *  \param LogCustomFormatNode * node - node to add
 */
void LogCustomFormatAddNode(LogCustomFormat *cf, LogCustomFormatNode *node)
{
    if (cf == NULL || node == NULL)
        return;

    if (cf->cf_n == LOG_MAXN_NODES) {
        SCLogWarning(SC_WARN_LOG_CF_TOO_MANY_NODES, "Too many options for custom format");
        return;
    }

#ifdef DEBUG
    SCLogDebug("%d-> n.type=[%d] n.maxlen=[%d] n.data=[%s]",
            cf->cf_n, node->type, node->maxlen, node->data);
#endif

    cf->cf_nodes[cf->cf_n] = node;
    cf->cf_n++;
}

/**
 *  \brief Writes a timestamp with given format into a MemBuffer
 *  \param MemBuffer * buffer - where to write
 *  \param const char * fmt - format to be used write timestamp
 *  \param const struct timeveal *ts  - the timetstamp
 *
 */
void LogCustomFormatWriteTimestamp(MemBuffer *buffer, const char *fmt, const struct timeval *ts) {

    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *timestamp = SCLocalTime(time, &local_tm);
    char buf[128] = {0};
    const char * fmt_to_use = TIMESTAMP_DEFAULT_FORMAT;

    if (fmt && *fmt != '\0') {
        fmt_to_use = fmt;
    }

    CreateFormattedTimeString (timestamp, fmt_to_use, buf, sizeof(buf));
    PrintRawUriBuf((char *)buffer->buffer, &buffer->offset,
                   buffer->size, (uint8_t *)buf,strlen(buf));
}

#ifdef UNITTESTS
/**
 * \internal
 * \brief This test tests default timestamp format
 */
static int LogCustomFormatTest01(void)
{
    struct tm tm;
    tm.tm_sec = 0;
    tm.tm_min = 30;
    tm.tm_hour = 4;
    tm.tm_mday = 13;
    tm.tm_mon = 0;
    tm.tm_year = 114;
    tm.tm_wday = 1;
    tm.tm_yday = 13;
    tm.tm_isdst = 0;
    time_t secs = mktime(&tm);
    struct timeval ts = {secs, 0};

    MemBuffer *buffer = MemBufferCreateNew(62);
    if (!buffer) {
        return 0;
    }

    LogCustomFormatWriteTimestamp(buffer, "", &ts);
    /*
     * {buffer = "01/13/14-04:30:00", size = 62, offset = 17}
     */
    FAIL_IF_NOT( buffer->offset == 17);
    FAIL_IF(strcmp((char *)buffer->buffer, "01/13/14-04:30:00") != 0);

    MemBufferFree(buffer);

    return 1;
}

static void LogCustomFormatRegisterTests(void)
{
    UtRegisterTest("LogCustomFormatTest01", LogCustomFormatTest01);
}
#endif /* UNITTESTS */

void LogCustomFormatRegister(void)
{
#ifdef UNITTESTS
    LogCustomFormatRegisterTests();
#endif /* UNITTESTS */
}
