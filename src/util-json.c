/* Copyright (C) 2017 Open Information Security Foundation
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

#include <stdbool.h>

#include "suricata-common.h"
#include "util-json.h"
#include "util-unittest.h"

#define INITIAL_SIZE 12000

#define STATES 256

enum SCJsonState {
    NEW = 0,
    OBJECT_FIRST,
    OBJECT_NTH,
    LIST_FIRST,
    LIST_NTH,
    CLOSED,
};

struct Mark {
    size_t offset;
    int    state[STATES];
    int    state_id;
};

typedef struct SCJson_ {
    char        *buf;
    size_t       size;
    int          state[STATES];
    int          state_id;
    bool         growable;
    struct Mark  mark;
} SCJson;

static uint8_t state(SCJson *js)
{
    return js->state[js->state_id];
}

static void state_set(SCJson *js, int state)
{
    js->state[js->state_id] = state;
}

static bool state_push(SCJson *js, int state)
{
    BUG_ON(js->state_id + 1 == STATES);
    if (js->state_id + 1 == STATES) {
        return false;
    }
    js->state[++js->state_id] = state;
    return true;
}

static void state_pop(SCJson *js)
{
    BUG_ON(js->state_id - 1 < 0);
    js->state_id--;
}

/**
 * \brief Encode a string into the JSON buffer. An assumption is made
 * that the buffer has already been checked to make sure the encoded
 * string fits.
 */
static size_t encode_string(SCJson *js, size_t offset, const char *val)
{
    size_t ioffset = offset;
    BUG_ON(js->size - offset < (strlen(val) * 2));
    js->buf[offset++] = '"';
    bool done = false;
    for (size_t i = 0; !done; i++) {
        switch (val[i]) {
            case '"': /* Double quote. */
            case '\\': /* Backslash. */
            case '/': /* Slash. */
                js->buf[offset++] = '\\';
                break;
            case '\n': /* New line. */
                js->buf[offset++] = '\\';
                js->buf[offset++] = 'n';
                continue;
            case '\r': /* Carriage return. */
                js->buf[offset++] = '\\';
                js->buf[offset++] = 'r';
                continue;
            case '\t': /* Tab. */
                js->buf[offset++] = '\\';
                js->buf[offset++] = 't';
                continue;
            case 0x0c: /* Form feed. */
                js->buf[offset++] = '\\';
                js->buf[offset++] = 'f';
                continue;
            case 0x08: /* Back space. */
                js->buf[offset++] = '\\';
                js->buf[offset++] = 'b';
                continue;
            case '\0':
                js->buf[offset++] = '"';
                done = true;
                break;
            default:
                break;
        }
        js->buf[offset++] = val[i];
    }
    return offset - ioffset;
}

/**
 * \brief Check the size of the buffer and grow as needed.
 *
 * \param js point to the json object
 * \param n number of remaining bytes in buffer required
 */
static bool SCJsonCheckSize(SCJson *js, size_t n)
{
    size_t required = strlen(js->buf) + n + 1;

    if (required > js->size) {
        if (!js->growable) {
            return false;
        }
        size_t len = required * 2;
        char *buf = SCRealloc(js->buf, len);
        if (buf != NULL) {
            js->buf = buf;
            js->size = len;
        } else {
            return false;
        }
    }
    return true;
}

/**
 * \brief Create a new JSON builder.
 */
SCJson *SCJsonNew(void)
{
    SCJson *js = SCCalloc(1, sizeof(*js));
    if (js != NULL) {
        js->buf = SCCalloc(1, INITIAL_SIZE);
        if (js->buf == NULL) {
            SCFree(js);
            return NULL;
        }
        js->size = INITIAL_SIZE;
        js->growable = true;
    }

    return js;
}

/**
 * \brief Create a new JSON builder using an existing buffer.
 *
 * The buffer will not be grown as needed so it should be of
 * sufficient size, and the return value of all operations should be
 * checked as they will return false if the buffer isn't large enough
 * to build the JSON.
 */
SCJson *SCJsonWrap(char *buf, size_t size)
{
    SCJson *js = SCCalloc(1, sizeof(*js));
    if (js != NULL) {
        js->buf = buf;
        js->size = size;
        js->growable = false;
    }

    return js;
}

/**
 * \brief Free the JSON builder.
 */
void SCJsonFree(SCJson *js)
{
    if (js != NULL) {
        if (js->growable) {
            SCFree(js->buf);
        }
        SCFree(js);
    }
}

/**
 * \brief Reset a JSON builder for re-use.
 */
void SCJsonReset(SCJson *js)
{
    js->state_id = 0;
    js->state[0] = NEW;
    js->buf[0] = '\0';
}


/**
 * \brief Get the pointer to the JSON buffer.
 */
const char *SCJsonGetBuf(SCJson *js)
{ 
    return js->buf;
}

/**
 * \brief Opens a JSON object, or more simply write a "{" to the
 *     buffer.
 */
bool SCJsonOpenObject(SCJson *js)
{
    if (!SCJsonCheckSize(js, 1)) {
        return false;
    }
    strncat(js->buf, "{", 1);
    state_set(js, CLOSED);
    state_push(js, OBJECT_FIRST);
    return true;
}

/**
 * \brief Close a JSON object, or more simply write a "}" to the
 *     buffer.
 */
bool SCJsonCloseObject(SCJson *js)
{
    if (!SCJsonCheckSize(js, 1)) {
        return false;
    }
    switch (state(js)) {
        case OBJECT_FIRST:
        case OBJECT_NTH:
            break;
        default:
            return false;
    }
    strncat(js->buf, "}", 1);
    state_pop(js);
    return true;
}

/**
 * \brief Start a new object with the given key.
 */
bool SCJsonStartObject(SCJson *js, const char *key)
{
    size_t len = strlen(key) + 5;
    char scratch[len];

    if (!SCJsonCheckSize(js, len)) {
        return false;
    }

    if (js->state[js->state_id] == OBJECT_NTH) {
        strncat(js->buf, ",", 1);
    } else if (js->state[js->state_id] != OBJECT_FIRST) {
        return false;
    }

    snprintf(scratch, len, "\"%s\":{", key);
    strncat(js->buf, scratch, len);
    state_set(js, OBJECT_NTH);
    state_push(js, OBJECT_FIRST);

    return true;
}

/**
 * \brief Start a list with the given key.
 */
bool SCJsonStartList(SCJson *js, const char *key)
{
    size_t len = strlen(key) + 5;
    char scratch[len];

    if (!SCJsonCheckSize(js, len)) {
        return false;
    }

    if (state(js) == OBJECT_NTH) {
        strncat(js->buf, ",", 1);
    } else if (state(js) != OBJECT_FIRST) {
        return false;
    }

    snprintf(scratch, len, "\"%s\":[", key);
    strncat(js->buf, scratch, len);
    state_push(js, LIST_FIRST);

    return true;
}

/**
 * \brief Close out a list by printing a "]".
 */
bool SCJsonCloseList(SCJson *js)
{
    if (!SCJsonCheckSize(js, 1)) {
        return false;
    }

    switch (state(js)) {
        case LIST_FIRST:
        case LIST_NTH:
            break;
        default:
            return false;
    }
    strncat(js->buf, "]", 1);
    state_pop(js);
    return true;
}

/**
 * \brief Set a key/value pair with a string value.
 */
bool SCJsonSetString(SCJson *js, const char *key, const char *val)
{
    if (val == NULL) {
        val = "";
    }

    /* The size is:
     * - quote
     * - strlen(key)
     * - quote
     * - colon
     * - quote
     * - strlen(val) * 2
     * - quote
     */
    size_t len = 5 + strlen(key);
    char scratch[len];

    if (!SCJsonCheckSize(js, len + (strlen(val) * 2))) {
        return false;
    }

    if (state(js) == OBJECT_NTH) {
        strncat(js->buf, ",", 1);
    }

    snprintf(scratch, len, "\"%s\":", key);
    strncat(js->buf, scratch, len);
    encode_string(js, strlen(js->buf), val);

    state_set(js, OBJECT_NTH);

    return true;
}

/**
 * \brief Set a key/value pair with an integer value.
 */
bool SCJsonSetInt(SCJson *js, const char *key, const intmax_t val)
{
    size_t len = strlen(key) + 32 + 4;
    char scratch[len];

    if (!SCJsonCheckSize(js, len)) {
        return false;
    }

    if (state(js) == OBJECT_NTH) {
        strncat(js->buf, ",", 1);
    }

    snprintf(scratch, len, "\"%s\":%"PRIiMAX, key, val);
    strncat(js->buf, scratch, len);

    state_set(js, OBJECT_NTH);

    return true;
}

/**
 * \brief Set a key/value pair with a boolean value.
 */
bool SCJsonSetBool(SCJson *js, const char *key, const bool val)
{
    /* 2->", 1->:, 1->false, 1->\0 = 9 */
    size_t len = strlen(key) + 9;
    char scratch[len];

    if (!SCJsonCheckSize(js, len)) {
        return false;
    }

    if (state(js) == OBJECT_NTH) {
        strncat(js->buf, ",", 1);
    }

    if (val) {
        snprintf(scratch, len, "\"%s\":true", key);
    } else {
        snprintf(scratch, len, "\"%s\":false", key);
    }

    strncat(js->buf, scratch, len);

    state_set(js, OBJECT_NTH);

    return true;
}

/**
 * \brief Append a string value to a list.
 */
bool SCJsonAppendString(SCJson *js, const char *val)
{
    if (!SCJsonCheckSize(js, strlen(val) * 2)) {
        return false;
    }

    switch (state(js)) {
        case LIST_NTH:
            strncat(js->buf, ",", 1);
        case LIST_FIRST:
            break;
        default:
            return false;
    }

    encode_string(js, strlen(js->buf), val);
    state_set(js, LIST_NTH);

    return true;
}

/**
 * \brief Append an integer value to a list.
 */
bool SCJsonAppendInt(SCJson *js, const intmax_t val)
{
    int len = 32 + 4;
    char scratch[len];

    if (!SCJsonCheckSize(js, len)) {
        return false;
    }

    switch (state(js)) {
        case LIST_NTH:
            strncat(js->buf, ",", 1);
        case LIST_FIRST:
            break;
        default:
            return false;
    }

    snprintf(scratch, len, "%"PRIiMAX, val);
    strncat(js->buf, scratch, len);

    state_set(js, LIST_NTH);

    return true;
}

/**
 * \brief Mark the current state of the SCJson object so it can be
 *     rewound to this state after some writes.
 *
 * Only one mark is allowed, meaning the buffer to can only be rewound
 * to the last call to SCJsonMark.
 *
 * Useful when sequential lines of JSON start with the same header,
 * the object can be marked and the end of the common data, written
 * to, then rewound for the next line.
 */
void SCJsonMark(SCJson *js)
{
    memcpy(&js->mark.state, &js->state, sizeof(js->state));
    js->mark.state_id = js->state_id;
    js->mark.offset = strlen(js->buf);
}

/**
 * \brief Rewind to the state of the last call to SCJsonMark.
 */
void SCJsonRewind(SCJson *js)
{
    memcpy(&js->state, &js->mark.state, sizeof(js->state));
    js->state_id = js->mark.state_id;
    js->buf[js->mark.offset] = '\0';
}

#ifdef UNITTESTS

static int UtilJsonTest01(void)
{
    SCJson *js = SCJsonNew();
    FAIL_IF_NULL(js);

    SCJsonOpenObject(js);
    FAIL_IF(strcmp(js->buf, "{"));

    SCJsonSetString(js, "one", "one");
    FAIL_IF(strcmp(js->buf, "{\"one\":\"one\""));

    SCJsonSetString(js, "two", "val with \"quote\"");
    char *expected = "{\"one\":\"one\","
        "\"two\":\"val with \\\"quote\\\"\"";
    FAIL_IF(strcmp(js->buf, expected));

    /* Add a list. */
    SCJsonStartList(js, "a-list");
    FAIL_IF(state(js) != LIST_FIRST);
    SCJsonAppendString(js, "with \"a\" quote");
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\"";
    FAIL_IF(strcmp(js->buf, expected));
    FAIL_IF(state(js) != LIST_NTH);

    SCJsonAppendInt(js, 2);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2";
    FAIL_IF(state(js) != LIST_NTH);
    FAIL_IF(strcmp(js->buf, expected));

    SCJsonCloseList(js);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2]";
    FAIL_IF(state(js) != OBJECT_NTH);
    FAIL_IF(strcmp(js->buf, expected));

    SCJsonStartObject(js, "nested");
    FAIL_IF(state(js) != OBJECT_FIRST);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2"
        "]"
        ",\"nested\":{";
    FAIL_IF(strcmp(js->buf, expected));

    SCJsonSetInt(js, "three", 3);
    FAIL_IF(state(js) != OBJECT_NTH);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2"
        "]"
        ",\"nested\":{"
        "\"three\":3";
    FAIL_IF(strcmp(js->buf, expected));

    SCJsonCloseObject(js);
    FAIL_IF(state(js) != OBJECT_NTH);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2"
        "]"
        ",\"nested\":{"
        "\"three\":3"
        "}";
    FAIL_IF(strcmp(js->buf, expected));

    FAIL_IF_NOT(SCJsonCloseObject(js));
    FAIL_IF(state(js) != CLOSED);
    expected = "{"
        "\"one\":\"one\""
        ",\"two\":\"val with \\\"quote\\\"\""
        ",\"a-list\":[\"with \\\"a\\\" quote\""
        ",2"
        "]"
        ",\"nested\":{"
        "\"three\":3"
        "}"
        "}";
    FAIL_IF(strcmp(js->buf, expected));

    /* Close on a fully closed object, should fail. */
    FAIL_IF(SCJsonCloseObject(js));

    SCJsonFree(js);
    PASS;
}

static int UtilJsonTestGrow(void)
{
    SCJson *js = SCJsonNew();
    FAIL_IF_NULL(js);

    char buf[(INITIAL_SIZE * 2) + 1];
    for (uint i = 0; i < INITIAL_SIZE * 2; i++) {
        strlcat(buf, "A", sizeof(buf));
    }
    FAIL_IF(strlen(buf) != INITIAL_SIZE * 2);

    SCJsonOpenObject(js);
    FAIL_IF_NOT(SCJsonSetString(js, "key", buf));
    SCJsonCloseObject(js);

    SCJsonFree(js);

    PASS;
}

static int UtilJsonTestWrapped(void)
{
    /* Create a buffer big enough for {"a":"aa"
     *
     * As this is 9 chars we need 10 for the NULL byte. But we also
     * require enough space fo the val to double size for escaping
     * reasons. So we actually need 12. */
    size_t size = 12;
    char wrapped[size];
    wrapped[0] = '\0';

    SCJson *js = SCJsonWrap(wrapped, size);
    FAIL_IF_NULL(js);

    FAIL_IF_NOT(SCJsonOpenObject(js));
    FAIL_IF(strlen(js->buf) != 1);

    /* This will add: "a":"aaa" (9 chars).  With a size of 12, and one
     * char already written we only have room for 8 chars to keep the
     * NUL byte.
     *
     * If this was allowed we'd overwrite the NUL byte.
     */
    FAIL_IF(SCJsonSetString(js, "a", "aaa"));

    /* But adding only 7 chars should work. */
    FAIL_IF_NOT(SCJsonSetString(js, "a", "aa"));
    FAIL_IF(strlen(js->buf) != 9);
    FAIL_IF(strcmp(js->buf, "{\"a\":\"aa\""));

    SCJsonFree(js);

    PASS;
}

static int UtilJsonTestMark(void)
{
    SCJson *js = SCJsonNew();

    SCJsonOpenObject(js);
    SCJsonSetString(js, "one", "one");
    SCJsonMark(js);
    SCJsonStartList(js, "list");
    SCJsonAppendInt(js, 1);
    char *expected = "{\"one\":\"one\",\"list\":[1";
    FAIL_IF(strcmp(js->buf, expected) != 0);

    SCJsonRewind(js);
    expected = "{\"one\":\"one\"";
    FAIL_IF(strlen(expected) != strlen(js->buf) ||
        strcmp(js->buf, expected) != 0);

    SCJsonSetString(js, "two", "two");
    expected = "{\"one\":\"one\",\"two\":\"two\"";
    FAIL_IF(strlen(expected) != strlen(js->buf) ||
        strcmp(js->buf, expected) != 0);

    SCJsonFree(js);
    PASS;
}

static int UtilJsonTestReset(void)
{
    SCJson *js = SCJsonNew();
    FAIL_IF_NULL(js);

    SCJsonOpenObject(js);
    SCJsonSetString(js, "key", "val");
    FAIL_IF(strcmp(js->buf, "{\"key\":\"val\"") != 0);

    SCJsonReset(js);
    FAIL_IF(strlen(js->buf) != 0);

    SCJsonFree(js);
    PASS;
}

#endif /* UNITTESTS */

void UtilJsonRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("UtilJsonTest01", UtilJsonTest01);
    UtRegisterTest("UtilJsonTestGrow", UtilJsonTestGrow);
    UtRegisterTest("UtilJsonTestWrapped", UtilJsonTestWrapped);
    UtRegisterTest("UtilJsonTestMark", UtilJsonTestMark);
    UtRegisterTest("UtilJsonTestReset", UtilJsonTestReset);
#endif
}
