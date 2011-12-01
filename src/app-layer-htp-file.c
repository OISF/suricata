/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * This file provides HTTP protocol file handling support for the engine
 * using HTP library.
 */

#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp.h"
#include "util-time.h"
#include <htp/htp.h>

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

#include "util-memcmp.h"

/**
 *  \brief Open the file with "filename" and pass the first chunk
 *         of data if any.
 *
 *  \param s http state
 *  \param filename name of the file
 *  \param filename_len length of the name
 *  \param data data chunk (if any)
 *  \param data_len length of the data portion
 *  \param direction flow direction
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 not handling files on this flow
 */
int HTPFileOpen(HtpState *s, uint8_t *filename, uint16_t filename_len,
        uint8_t *data, uint32_t data_len, uint16_t txid, uint8_t direction)
{
    int retval = 0;
    uint8_t flags = 0;
    FileContainer *files = NULL;

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        if (s->files_tc == NULL) {
            s->files_tc = FileContainerAlloc();
            if (s->files_tc == NULL) {
                retval = -1;
                goto end;
            }
        }

        files = s->files_tc;

        if (s->flags & HTP_FLAG_STORE_FILES_TS ||
                (s->flags & HTP_FLAG_STORE_FILES_TX_TS && txid == s->store_tx_id)) {
            flags |= FILE_STORE;
        }
    } else {
        if (s->files_ts == NULL) {
            s->files_ts = FileContainerAlloc();
            if (s->files_ts == NULL) {
                retval = -1;
                goto end;
            }
        }

        files = s->files_ts;

        if (s->flags & HTP_FLAG_STORE_FILES_TC ||
                (s->flags & HTP_FLAG_STORE_FILES_TX_TC && txid == s->store_tx_id)) {
            flags |= FILE_STORE;
        }
    }

    /* if the previous file is in the same txid, we
     * reset the file part of the stateful detection
     * engine. */
    if (files != NULL && files->tail != NULL && files->tail->txid == txid) {
        SCLogDebug("new file in same tx, resetting de_state");
        DeStateResetFileInspection(s->f, direction);
    }

    if (!(flags & FILE_STORE) && s->f->flags & FLOW_FILE_NO_STORE) {
        flags |= FILE_NOSTORE;
    }
    if (s->f->flags & FLOW_FILE_NO_MAGIC) {
        flags |= FILE_NOMAGIC;
    }

    if (FileOpenFile(files, filename, filename_len,
                data, data_len, flags) == NULL)
    {
        retval = -1;
    }

    FileSetTx(files->tail, txid);

    FilePrune(files);
end:
    SCReturnInt(retval);
}

/**
 *  \brief Store a chunk of data in the flow
 *
 *  \param s http state
 *  \param data data chunk (if any)
 *  \param data_len length of the data portion
 *  \param direction flow direction
 *
 *  \retval 0 ok
 *  \retval -1 error
 *  \retval -2 file doesn't need storing
 */
int HTPFileStoreChunk(HtpState *s, uint8_t *data, uint32_t data_len,
        uint8_t direction)
{
    SCEnter();

    int retval = 0;
    int result = 0;
    FileContainer *files = NULL;

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        files = s->files_tc;
    } else {
        files = s->files_ts;
    }

    if (files == NULL) {
        SCLogDebug("no files in state");
        retval = -1;
        goto end;
    }

    result = FileAppendData(files, data, data_len);
    if (result == -1) {
        SCLogDebug("appending data failed");
        retval = -1;
    } else if (result == -2) {
        retval = -2;
    }

    FilePrune(files);
end:
    SCReturnInt(retval);
}

/**
 *  \brief Close the file in the flow
 *
 *  \param s http state
 *  \param data data chunk if any
 *  \param data_len length of the data portion
 *  \param flags flags to indicate events
 *  \param direction flow direction
 *
 *  Currently on the FLOW_FILE_TRUNCATED flag is implemented, indicating
 *  that the file isn't complete but we're stopping storing it.
 *
 *  \retval 0 ok
 *  \retval -1 error
 *  \retval -2 not storing files on this flow/tx
 */
int HTPFileClose(HtpState *s, uint8_t *data, uint32_t data_len,
        uint8_t flags, uint8_t direction)
{
    SCEnter();

    int retval = 0;
    int result = 0;
    FileContainer *files = NULL;

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        files = s->files_tc;
    } else {
        files = s->files_ts;
    }

    if (files == NULL) {
        retval = -1;
        goto end;
    }

    result = FileCloseFile(files, data, data_len, flags);
    if (result == -1) {
        retval = -1;
    } else if (result == -2) {
        retval = -2;
    }

    FilePrune(files);
end:
    SCReturnInt(retval);
}

#ifdef UNITTESTS
static int HTPFileParserTest01(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    TcpSession ssn;
    HtpState *http_state = NULL;
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        goto end;
    }

    if (tx->request_method == NULL || memcmp(bstr_tocstr(tx->request_method), "POST", 4) != 0)
    {
        printf("expected method POST, got %s \n", bstr_tocstr(tx->request_method));
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

static int HTPFileParserTest02(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 337\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    uint8_t httpbuf2[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"email\"\r\n"
                         "\r\n"
                         "someaddress@somedomain.lan\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    uint8_t httpbuf3[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 3 size %u <<<<\n", httplen3);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 4 size %u <<<<\n", httplen4);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        goto end;
    }

    if (tx->request_method == NULL || memcmp(bstr_tocstr(tx->request_method), "POST", 4) != 0)
    {
        printf("expected method POST, got %s \n", bstr_tocstr(tx->request_method));
        goto end;
    }

    if (http_state->files_ts == NULL || http_state->files_ts->tail == NULL ||
            http_state->files_ts->tail->state != FILE_STATE_CLOSED) {
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

static int HTPFileParserTest03(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 337\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    uint8_t httpbuf2[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"email\"\r\n"
                         "\r\n"
                         "someaddress@somedomain.lan\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    uint8_t httpbuf3[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "file";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    uint8_t httpbuf5[] = "content\r\n";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */

    uint8_t httpbuf6[] = "-----------------------------277531038314945--";
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */

    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 3 size %u <<<<\n", httplen3);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 4 size %u <<<<\n", httplen4);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 5 size %u <<<<\n", httplen5);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 6 size %u <<<<\n", httplen6);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        goto end;
    }

    if (tx->request_method == NULL || memcmp(bstr_tocstr(tx->request_method), "POST", 4) != 0)
    {
        printf("expected method POST, got %s \n", bstr_tocstr(tx->request_method));
        goto end;
    }

    if (http_state->files_ts == NULL || http_state->files_ts->tail == NULL ||
            http_state->files_ts->tail->state != FILE_STATE_CLOSED) {
        goto end;
    }

    if (http_state->files_ts->head->chunks_head->len != 11) {
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

static int HTPFileParserTest04(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 373\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    uint8_t httpbuf2[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"email\"\r\n"
                         "\r\n"
                         "someaddress@somedomain.lan\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    uint8_t httpbuf3[] = "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "file0123456789abcdefghijklmnopqrstuvwxyz";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    uint8_t httpbuf5[] = "content\r\n";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */

    uint8_t httpbuf6[] = "-----------------------------277531038314945--";
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */

    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 3 size %u <<<<\n", httplen3);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 4 size %u <<<<\n", httplen4);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 5 size %u <<<<\n", httplen5);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 6 size %u <<<<\n", httplen6);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        goto end;
    }

    if (tx->request_method == NULL || memcmp(bstr_tocstr(tx->request_method), "POST", 4) != 0)
    {
        printf("expected method POST, got %s: ", bstr_tocstr(tx->request_method));
        goto end;
    }

    if (http_state->files_ts == NULL || http_state->files_ts->tail == NULL ||
            http_state->files_ts->tail->state != FILE_STATE_CLOSED) {
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

static int HTPFileParserTest05(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 544\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent\r\n"
                         "-----------------------------277531038314945\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "Content-Disposition: form-data; name=\"uploadfile_1\"; filename=\"somepicture2.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "FILECONTENT\r\n"
        "-----------------------------277531038314945--";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */

    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 size %u <<<<\n", httplen1);
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);
    if (tx == NULL) {
        goto end;
    }

    if (tx->request_method == NULL || memcmp(bstr_tocstr(tx->request_method), "POST", 4) != 0)
    {
        printf("expected method POST, got %s \n", bstr_tocstr(tx->request_method));
        goto end;
    }

    if (http_state->files_ts == NULL || http_state->files_ts->tail == NULL ||
            http_state->files_ts->tail->state != FILE_STATE_CLOSED) {
        goto end;
    }

    if (http_state->files_ts->head == http_state->files_ts->tail)
        goto end;

    if (http_state->files_ts->head->next != http_state->files_ts->tail)
        goto end;

    if (http_state->files_ts->head->chunks_head->len != 11) {
        printf("expected 11 but file is %u bytes instead\n",
                http_state->files_ts->head->chunks_head->len);
        PrintRawDataFp(stdout, http_state->files_ts->head->chunks_head->data,
                http_state->files_ts->head->chunks_head->len);
        goto end;
    }

    if (memcmp("filecontent", http_state->files_ts->head->chunks_head->data,
                http_state->files_ts->head->chunks_head->len) != 0) {
        goto end;
    }

    if (http_state->files_ts->tail->chunks_head->len != 11) {
        printf("expected 11 but file is %u bytes instead\n",
                http_state->files_ts->tail->chunks_head->len);
        PrintRawDataFp(stdout, http_state->files_ts->tail->chunks_head->data,
                http_state->files_ts->tail->chunks_head->len);
        goto end;
    }

    if (memcmp("FILECONTENT", http_state->files_ts->tail->chunks_head->data,
                http_state->files_ts->tail->chunks_head->len) != 0) {
        goto end;
    }
    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

#endif /* UNITTESTS */

void HTPFileParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HTPFileParserTest01", HTPFileParserTest01, 1);
    UtRegisterTest("HTPFileParserTest02", HTPFileParserTest02, 1);
    UtRegisterTest("HTPFileParserTest03", HTPFileParserTest03, 1);
    UtRegisterTest("HTPFileParserTest04", HTPFileParserTest04, 1);
    UtRegisterTest("HTPFileParserTest05", HTPFileParserTest05, 1);
#endif /* UNITTESTS */
}
