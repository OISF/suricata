/* Copyright (C) 2012 BAE Systems
 * Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#include "suricata-common.h"
#ifdef DEBUG
#include "util-print.h"
#include "util-spm-bs.h"
#endif

#include "util-decode-mime.h"
#include "util-ip.h"
#include "util-unittest.h"
#include "util-memcmp.h"
#include "util-validate.h"
#include "rust.h"

/* Character constants */
#ifndef CR
#define CR  13
#define LF  10
#endif

#define CRLF             "\r\n"
#define COLON             58
#define DASH              45
#define PRINTABLE_START   33
#define PRINTABLE_END    126
#define UC_START          65
#define UC_END            90
#define LC_START          97
#define LC_END           122
#define UC_LC_DIFF        32
#define EOL_LEN            2

/* Base-64 constants */
#define BASE64_STR        "Base64"

/* Mime Constants */
#define MAX_LINE_LEN       998 /* Def in RFC 2045, excluding CRLF sequence */
#define MAX_ENC_LINE_LEN    76 /* Def in RFC 2045, excluding CRLF sequence */
#define MAX_HEADER_NAME     75 /* 75 + ":" = 76 */
#define MAX_HEADER_VALUE  2000 /* Default - arbitrary limit */
#define BOUNDARY_BUF       256
#define CTNT_TYPE_STR     "content-type"
#define CTNT_DISP_STR     "content-disposition"
#define CTNT_TRAN_STR     "content-transfer-encoding"
#define MSG_ID_STR        "message-id"
#define MSG_STR           "message/"
#define MULTIPART_STR     "multipart/"
#define QP_STR            "quoted-printable"
#define TXT_STR           "text/plain"
#define HTML_STR          "text/html"

/* Memory Usage Constants */
#define STACK_FREE_NODES  10

/* Other Constants */
#define MAX_IP4_CHARS  15
#define MAX_IP6_CHARS  39

/* Globally hold configuration data */
static MimeDecConfig mime_dec_config = { true, true, true, NULL, false, false, MAX_HEADER_VALUE };

/* Mime Parser String translation */
static const char *StateFlags[] = { "NONE",
        "HEADER_READY",
        "HEADER_STARTED",
        "HEADER_DONE",
        "BODY_STARTED",
        "BODY_DONE",
        "BODY_END_BOUND",
        "PARSE_DONE",
        "PARSE_ERROR",
        NULL };

/* URL executable file extensions */
static const char *UrlExeExts[] = { ".exe", ".vbs", ".bin", ".cmd", ".bat", ".jar", ".js", ".ps",
    ".ps1", ".sh", ".run", ".hta", ".bin", ".elf", NULL };

/**
 * \brief Function used to print character strings that are not null-terminated
 *
 * \param log_level The logging level in which to print
 * \param label A label for the string to print
 * \param src The source string
 * \param len The length of the string
 *
 * \return none
 */
static void PrintChars(int log_level, const char *label, const uint8_t *src, uint32_t len)
{
#ifdef DEBUG
    if (log_level <= sc_log_global_log_level) {
        printf("[%s]\n", label);
        PrintRawDataFp(stdout, (uint8_t *)src, len);
    }
#endif
}

/**
 * \brief Set global config policy
 *
 * \param config Config policy to set
 * \return none
 */
void MimeDecSetConfig(MimeDecConfig *config)
{
    if (config != NULL) {
        mime_dec_config = *config;

        /* Set to default */
        if (mime_dec_config.header_value_depth == 0) {
            mime_dec_config.header_value_depth = MAX_HEADER_VALUE;
        }
    } else {
        SCLogWarning(SC_ERR_MISSING_CONFIG_PARAM, "Invalid null configuration parameters");
    }
}

/**
 * \brief Get global config policy
 *
 * \return config data structure
 */
MimeDecConfig * MimeDecGetConfig(void)
{
    return &mime_dec_config;
}

/**
 * \brief Follow the 'next' pointers to the leaf
 *
 * \param node The root entity
 *
 * \return Pointer to leaf on 'next' side
 *
 */
static MimeDecEntity *findLastSibling(MimeDecEntity *node)
{
    if (node == NULL)
        return NULL;
    while(node->next != NULL)
        node = node->next;
    return node;
}

/**
 * \brief Frees a mime entity tree
 *
 * \param entity The root entity
 *
 * \return none
 *
 */
void MimeDecFreeEntity (MimeDecEntity *entity)
{
    if (entity == NULL)
        return;
    MimeDecEntity *lastSibling = findLastSibling(entity);
    while (entity != NULL)
    {
        /**
         * Move child to next
         * Transform tree into list
         */
        if (entity->child != NULL)
        {
            lastSibling->next = entity->child;
            lastSibling = findLastSibling(lastSibling);
        }

        /**
         * Move to next element
         */
        MimeDecEntity *old = entity;
        entity = entity->next;

        MimeDecFreeField(old->field_list);
        MimeDecFreeUrl(old->url_list);
        SCFree(old->filename);

        SCFree(old);
    }
}

/**
 * \brief Iteratively frees a header field entry list
 *
 * \param field The header field
 *
 * \return none
 *
 */
void MimeDecFreeField(MimeDecField *field)
{
    MimeDecField *temp, *curr;

    if (field != NULL) {

        curr = field;
        while (curr != NULL) {
            temp = curr;
            curr = curr->next;

            /* Free contents of node */
            SCFree(temp->name);
            SCFree(temp->value);

            /* Now free node data */
            SCFree(temp);
        }
    }
}

/**
 * \brief Iteratively frees a URL entry list
 *
 * \param url The url entry
 *
 * \return none
 *
 */
void MimeDecFreeUrl(MimeDecUrl *url)
{
    MimeDecUrl *temp, *curr;

    if (url != NULL) {

        curr = url;
        while (curr != NULL) {
            temp = curr;
            curr = curr->next;

            /* Now free node data */
            SCFree(temp->url);
            SCFree(temp);
        }
    }
}

/**
 * \brief Creates and adds a header field entry to an entity
 *
 * The entity is optional.  If NULL is specified, than a new stand-alone field
 * is created.
 *
 * \param entity The parent entity
 *
 * \return The field object, or NULL if the operation fails
 *
 */
MimeDecField * MimeDecAddField(MimeDecEntity *entity)
{
    MimeDecField *node = SCMalloc(sizeof(MimeDecField));
    if (unlikely(node == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return NULL;
    }
    memset(node, 0x00, sizeof(MimeDecField));

    /* If list is empty, then set as head of list */
    if (entity->field_list == NULL) {
        entity->field_list = node;
    } else {
        /* Otherwise add to beginning of list since these are out-of-order in
         * the message */
        node->next = entity->field_list;
        entity->field_list = node;
    }

    return node;
}


/**
 * \brief Searches for header fields with the specified name
 *
 * \param entity The entity to search
 * \param name The header name (lowercase)
 *
 * \return number of items found
 *
 */
int MimeDecFindFieldsForEach(const MimeDecEntity *entity, const char *name, int (*DataCallback)(const uint8_t *val, const size_t, void *data), void *data)
{
    MimeDecField *curr = entity->field_list;
    int found = 0;

    while (curr != NULL) {
        /* name is stored lowercase */
        if (strlen(name) == curr->name_len) {
            if (SCMemcmp(curr->name, name, curr->name_len) == 0) {
                if (DataCallback(curr->value, curr->value_len, data))
                    found++;
            }
        }
        curr = curr->next;
    }

    return found;
}

/**
 * \brief Searches for a header field with the specified name
 *
 * \param entity The entity to search
 * \param name The header name (lowercase)
 *
 * \return The field object, or NULL if not found
 *
 */
MimeDecField * MimeDecFindField(const MimeDecEntity *entity, const char *name) {
    MimeDecField *curr = entity->field_list;

    while (curr != NULL) {
        /* name is stored lowercase */
        if (strlen(name) == curr->name_len) {
            if (SCMemcmp(curr->name, name, curr->name_len) == 0) {
                break;
            }
        }
        curr = curr->next;
    }

    return curr;
}

/**
 * \brief Creates and adds a URL entry to the specified entity
 *
 * The entity is optional and if NULL is specified, then a new list will be created.
 *
 * \param entity The entity
 *
 * \return URL entry or NULL if the operation fails
 *
 */
static MimeDecUrl * MimeDecAddUrl(MimeDecEntity *entity, uint8_t *url, uint32_t url_len, uint8_t flags)
{
    MimeDecUrl *node = SCMalloc(sizeof(MimeDecUrl));
    if (unlikely(node == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return NULL;
    }
    memset(node, 0x00, sizeof(MimeDecUrl));

    node->url = url;
    node->url_len = url_len;
    node->url_flags = flags;

    /* If list is empty, then set as head of list */
    if (entity->url_list == NULL) {
        entity->url_list = node;
    } else {
        /* Otherwise add to beginning of list since these are out-of-order in
         * the message */
        node->next = entity->url_list;
        entity->url_list = node;
    }

    return node;
}

/**
 * \brief Creates and adds a child entity to the specified parent entity
 *
 * \param parent The parent entity
 *
 * \return The child entity, or NULL if the operation fails
 *
 */
MimeDecEntity * MimeDecAddEntity(MimeDecEntity *parent)
{
    MimeDecEntity *curr, *node = SCMalloc(sizeof(MimeDecEntity));
    if (unlikely(node == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return NULL;
    }
    memset(node, 0x00, sizeof(MimeDecEntity));

    /* If parent is NULL then just return the new pointer */
    if (parent != NULL) {
        if (parent->child == NULL) {
            parent->child = node;
        } else {
            curr = parent->child;
            while (curr->next != NULL) {
                curr = curr->next;
            }
            curr->next = node;
        }
    }

    return node;
}

/**
 * \brief Creates a mime header field and fills in its values and adds it to the
 * specified entity
 *
 * \param entity Entity in which to add the field
 * \param name String containing the name
 * \param nlen Length of the name
 * \param value String containing the value
 * \param vlen Length of the value
 *
 * \return The field or NULL if the operation fails
 */
static MimeDecField * MimeDecFillField(MimeDecEntity *entity, uint8_t *name,
        uint32_t nlen, const uint8_t *value, uint32_t vlen)
{
    if (nlen == 0 && vlen == 0)
        return NULL;

    MimeDecField *field = MimeDecAddField(entity);
    if (unlikely(field == NULL)) {
        return NULL;
    }

    if (nlen > 0) {
        /* convert to lowercase and store */
        uint32_t u;
        for (u = 0; u < nlen; u++)
            name[u] = u8_tolower(name[u]);

        field->name = (uint8_t *)name;
        field->name_len = nlen;
    }

    if (vlen > 0) {
        field->value = (uint8_t *)value;
        field->value_len = vlen;
    }

    return field;
}

/**
 * \brief Pushes a node onto a stack and returns the new node.
 *
 * \param stack The top of the stack
 *
 * \return pointer to a new node, otherwise NULL if it fails
 */
static MimeDecStackNode * PushStack(MimeDecStack *stack)
{
    /* Attempt to pull from free nodes list */
    MimeDecStackNode *node = stack->free_nodes;
    if (node == NULL) {
        node = SCMalloc(sizeof(MimeDecStackNode));
        if (unlikely(node == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
            return NULL;
        }
    } else {
        /* Move free nodes pointer over */
        stack->free_nodes = stack->free_nodes->next;
        stack->free_nodes_cnt--;
    }
    memset(node, 0x00, sizeof(MimeDecStackNode));

    /* Push to top of stack */
    node->next = stack->top;
    stack->top = node;

    /* Return a pointer to the top of the stack */
    return node;
}

/**
 * \brief Pops the top node from the stack and returns the next node.
 *
 * \param stack The top of the stack
 *
 * \return pointer to the next node, otherwise NULL if no nodes remain
 */
static MimeDecStackNode * PopStack(MimeDecStack *stack)
{
    /* Move stack pointer to next item */
    MimeDecStackNode *curr = stack->top;
    if (curr != NULL) {
        curr = curr->next;
    }

    /* Always free alloc'd memory */
    SCFree(stack->top->bdef);

    /* Now move head to free nodes list */
    if (stack->free_nodes_cnt < STACK_FREE_NODES) {
        stack->top->next = stack->free_nodes;
        stack->free_nodes = stack->top;
        stack->free_nodes_cnt++;
    } else {
        SCFree(stack->top);
    }
    stack->top = curr;

    /* Return a pointer to the top of the stack */
    return curr;
}

/**
 * \brief Frees the stack along with the free-nodes list
 *
 * \param stack The stack pointer
 *
 * \return none
 */
static void FreeMimeDecStack(MimeDecStack *stack)
{
    MimeDecStackNode *temp, *curr;

    if (stack != NULL) {
        /* Top of stack */
        curr = stack->top;
        while (curr != NULL) {
            temp = curr;
            curr = curr->next;

            /* Now free node */
            SCFree(temp->bdef);
            SCFree(temp);
        }

        /* Free nodes */
        curr = stack->free_nodes;
        while (curr != NULL) {
            temp = curr;
            curr = curr->next;

            /* Now free node */
            SCFree(temp);
        }

        SCFree(stack);
    }
}

/**
 * \brief Adds a data value to the data values linked list
 *
 * \param dv The head of the linked list (NULL if new list)
 *
 * \return pointer to a new node, otherwise NULL if it fails
 */
static DataValue * AddDataValue(DataValue *dv)
{
    DataValue *curr, *node = SCMalloc(sizeof(DataValue));
    if (unlikely(node == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return NULL;
    }
    memset(node, 0x00, sizeof(DataValue));

    if (dv != NULL) {
        curr = dv;
        while (curr->next != NULL) {
            curr = curr->next;
        }

        curr->next = node;
    }

    return node;
}

/**
 * \brief Frees a linked list of data values starting at the head
 *
 * \param dv The head of the linked list
 *
 * \return none
 */
static void FreeDataValue(DataValue *dv)
{
    DataValue *temp, *curr;

    if (dv != NULL) {
        curr = dv;
        while (curr != NULL) {
            temp = curr;
            curr = curr->next;

            /* Now free node */
            SCFree(temp->value);
            SCFree(temp);
        }
    }
}

/**
 * \brief Converts a list of data values into a single value (returns dynamically
 * allocated memory)
 *
 * \param dv The head of the linked list (NULL if new list)
 * \param olen The output length of the single value
 *
 * \return pointer to a single value, otherwise NULL if it fails or is zero-length
 */
static uint8_t *GetFullValue(const DataValue *dv, uint32_t *olen)
{
    uint32_t offset = 0;
    uint8_t *val = NULL;
    uint32_t len = 0;
    *olen = 0;

    /* First calculate total length */
    for (const DataValue *curr = dv; curr != NULL; curr = curr->next) {
        len += curr->value_len;
    }
    /* Must have at least one character in the value */
    if (len > 0) {
        val = SCCalloc(1, len);
        if (unlikely(val == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
            return NULL;
        }
        for (const DataValue *curr = dv; curr != NULL; curr = curr->next) {
            memcpy(val + offset, curr->value, curr->value_len);
            offset += curr->value_len;
        }
    }
    *olen = len;
    return val;
}

/**
 * \brief Find a string while searching up to N characters within a source
 *        buffer
 *
 * \param src The source string (not null-terminated)
 * \param len The length of the source string
 * \param find The string to find (null-terminated)
 * \param find_len length of the 'find' string
 *
 * \return Pointer to the position it was found, otherwise NULL if not found
 */
static inline uint8_t *FindBuffer(
        const uint8_t *src, uint32_t len, const uint8_t *find, uint16_t find_len)
{
    /* Use utility search function */
    return BasicSearchNocase(src, len, find, find_len);
}

/**
 * \brief Get a line (CRLF or just CR or LF) from a buffer (similar to GetToken)
 *
 * \param buf The input buffer (not null-terminated)
 * \param blen The length of the input buffer
 * \param remainPtr Pointer to remaining after tokenizing iteration
 * \param tokLen Output token length (if non-null line)
 *
 * \return Pointer to line
 */
static uint8_t * GetLine(uint8_t *buf, uint32_t blen, uint8_t **remainPtr,
        uint32_t *tokLen)
{
    uint32_t i;
    uint8_t *tok;

    /* So that it can be used just like strtok_r */
    if (buf == NULL) {
        buf = *remainPtr;
    } else {
        *remainPtr = buf;
    }
    if (buf == NULL)
        return NULL;

    tok = buf;

    /* length must be specified */
    for (i = 0; i < blen && buf[i] != 0; i++) {

        /* Found delimiter */
        if (buf[i] == CR || buf[i] == LF) {

            /* Add another if we find either CRLF or LFCR */
            *remainPtr += (i + 1);
            if ((i + 1 < blen) && buf[i] != buf[i + 1] &&
                    (buf[i + 1] == CR || buf[i + 1] == LF)) {
                (*remainPtr)++;
            }
            break;
        }
    }

    /* If no delimiter found, then point to end of buffer */
    if (buf == *remainPtr) {
        (*remainPtr) += i;
    }

    /* Calculate token length */
    *tokLen = (buf + i) - tok;

    return tok;
}

/**
 * \brief Get token from buffer and return pointer to it
 *
 * \param buf The input buffer (not null-terminated)
 * \param blen The length of the input buffer
 * \param delims Character delimiters (null-terminated)
 * \param remainPtr Pointer to remaining after tokenizing iteration
 * \param tokLen Output token length (if non-null line)
 *
 * \return Pointer to token, or NULL if not found
 */
static uint8_t * GetToken(uint8_t *buf, uint32_t blen, const char *delims,
        uint8_t **remainPtr, uint32_t *tokenLen)
{
    uint32_t i, j, delimFound = 0;
    uint8_t *tok = NULL;

    /* So that it can be used just like strtok_r */
    if (buf == NULL) {
        buf = *remainPtr;
    } else {
        *remainPtr = buf;
    }
    if (buf == NULL)
        return NULL;

    /* Must specify length */
    for (i = 0; i < blen && buf[i] != 0; i++) {

        /* Look for delimiters */
        for (j = 0; delims[j] != 0; j++) {
            if (buf[i] == delims[j]) {
                /* Data must be found before delimiter matters */
                if (tok != NULL) {
                    (*remainPtr) += (i + 1);
                }
                delimFound = 1;
                break;
            }
        }

        /* If at least one non-delimiter found, then a token is found */
        if (tok == NULL && !delimFound) {
            tok = buf + i;
        } else {
            /* Reset delimiter */
            delimFound = 0;
        }

        /* If delimiter found, then break out of loop */
        if (buf != *remainPtr) {
            break;
        }
    }

    /* Make sure remaining points to end of buffer if delimiters not found */
    if (tok != NULL) {
        if (buf == *remainPtr) {
            (*remainPtr) += i;
        }

        /* Calculate token length */
        *tokenLen = (buf + i) - tok;
    }

    return tok;
}

/**
 * \brief Stores the final MIME header value into the current entity on the
 * stack.
 *
 * \param state The parser state
 *
 * \return MIME_DEC_OK if stored, otherwise a negative number indicating error
 */
static int StoreMimeHeader(MimeDecParseState *state)
{
    int ret = MIME_DEC_OK, stored = 0;
    uint8_t *val;
    uint32_t vlen;

    /* Lets save the most recent header */
    if (state->hname != NULL || state->hvalue != NULL) {
        SCLogDebug("Storing last header");
        val = GetFullValue(state->hvalue, &vlen);
        if (val != NULL) {
            if (state->hname == NULL) {
                SCLogDebug("Error: Invalid parser state - header value without"
                        " name");
                ret = MIME_DEC_ERR_PARSE;
            } else if (state->stack->top != NULL) {
                /* Store each header name and value */
                if (MimeDecFillField(state->stack->top->data, state->hname,
                            state->hlen, val, vlen) == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "MimeDecFillField() function failed");
                    ret = MIME_DEC_ERR_MEM;
                } else {
                    stored = 1;
                }
            } else {
                SCLogDebug("Error: Stack pointer missing");
                ret = MIME_DEC_ERR_DATA;
            }
        } else if (state->hvalue != NULL) {
            /* Memory allocation must have failed since val is NULL */
            SCLogError(SC_ERR_MEM_ALLOC, "GetFullValue() function failed");
            ret = MIME_DEC_ERR_MEM;
        }

        /* Do cleanup here */
        if (!stored) {
            SCFree(state->hname);
            SCFree(val);
        }
        state->hname = NULL;
        FreeDataValue(state->hvalue);
        state->hvalue = NULL;
        state->hvlen = 0;
    }

    return ret;
}

/**
 * \brief Function determines whether a url string points to an executable
 * based on file extension only.
 *
 * \param url The url string
 * \param len The url string length
 *
 * \retval 1 The url points to an EXE
 * \retval 0 The url does NOT point to an EXE
 */
static int IsExeUrl(const uint8_t *url, uint32_t len)
{
    int isExeUrl = 0;
    uint32_t i, extLen;
    uint8_t *ext;

    /* Now check for executable extensions and if not found, cut off at first '/' */
    for (i = 0; UrlExeExts[i] != NULL; i++) {
        extLen = strlen(UrlExeExts[i]);
        ext = FindBuffer(url, len, (uint8_t *)UrlExeExts[i], (uint16_t)strlen(UrlExeExts[i]));
        if (ext != NULL && (ext + extLen - url == (int)len || ext[extLen] == '?')) {
            isExeUrl = 1;
            break;
        }
    }

    return isExeUrl;
}

/**
 * \brief Function determines whether a host string is a numeric IP v4 address
 *
 * \param urlhost The host string
 * \param len The host string length
 *
 * \retval 1 The host is a numeric IP
 * \retval 0 The host is NOT a numeric IP
 */
static int IsIpv4Host(const uint8_t *urlhost, uint32_t len)
{
    struct sockaddr_in sa;
    char tempIp[MAX_IP4_CHARS + 1];

    /* Cut off at '/'  */
    uint32_t i = 0;
    for ( ; i < len && urlhost[i] != 0; i++) {

        if (urlhost[i] == '/') {
            break;
        }
    }

    /* Too many chars */
    if (i > MAX_IP4_CHARS) {
        return 0;
    }

    /* Create null-terminated string */
    memcpy(tempIp, urlhost, i);
    tempIp[i] = '\0';

    if (!IPv4AddressStringIsValid(tempIp))
        return 0;

    return inet_pton(AF_INET, tempIp, &(sa.sin_addr));
}

/**
 * \brief Function determines whether a host string is a numeric IP v6 address
 *
 * \param urlhost The host string
 * \param len The host string length
 *
 * \retval 1 The host is a numeric IP
 * \retval 0 The host is NOT a numeric IP
 */
static int IsIpv6Host(const uint8_t *urlhost, uint32_t len)
{
    struct in6_addr in6;
    char tempIp[MAX_IP6_CHARS + 1];

    /* Cut off at '/'  */
    uint32_t i = 0;
    for (i = 0; i < len && urlhost[i] != 0; i++) {
        if (urlhost[i] == '/') {
            break;
        }
    }

    /* Too many chars */
    if (i > MAX_IP6_CHARS) {
        return 0;
    }

    /* Create null-terminated string */
    memcpy(tempIp, urlhost, i);
    tempIp[i] = '\0';

    if (!IPv6AddressStringIsValid(tempIp))
        return 0;

    return inet_pton(AF_INET6, tempIp, &in6);
}

/**
 * \brief Traverses through the list of URLs for an exact match of the specified
 * string
 *
 * \param entity The MIME entity
 * \param url The matching URL string (lowercase)
 * \param url_len The matching URL string length
 *
 * \return URL object or NULL if not found
 */
static MimeDecUrl *FindExistingUrl(MimeDecEntity *entity, uint8_t *url, uint32_t url_len)
{
    MimeDecUrl *curr = entity->url_list;

    while (curr != NULL) {
        if (url_len == curr->url_len) {
            /* search url and stored url are both in
             * lowercase, so we can do an exact match */
            if (SCMemcmp(curr->url, url, url_len) == 0) {
                break;
            }
        }
        curr = curr->next;
    }

    return curr;
}

/**
 * \brief This function searches a text or html line for a URL string
 *
 * The URL strings are searched for using the URL schemes defined in the global
 * MIME config e.g. "http", "https".
 *
 * The found URL strings are stored in lowercase and with their schemes
 * stripped unless the MIME config flag for log_url_scheme is set.
 *
 * Numeric IPs, malformed numeric IPs, and URLs pointing to executables are
 * also flagged as URLs of interest.
 *
 * \param line the line
 * \param len the line length
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int FindUrlStrings(const uint8_t *line, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;
    MimeDecConfig *mdcfg = MimeDecGetConfig();
    uint8_t *fptr, *remptr, *tok = NULL, *tempUrl, *urlHost;
    uint32_t tokLen = 0, i, tempUrlLen, urlHostLen;
    uint16_t schemeStrLen = 0;
    uint8_t flags = 0;
    ConfNode *scheme = NULL;
    char *schemeStr = NULL;

    if (mdcfg != NULL && mdcfg->extract_urls_schemes == NULL) {
        SCLogDebug("Error: MIME config extract_urls_schemes was NULL.");
        return MIME_DEC_ERR_DATA;
    }

    TAILQ_FOREACH (scheme, &mdcfg->extract_urls_schemes->head, next) {
        schemeStr = scheme->val;
        // checked against UINT16_MAX when setting in SMTPConfigure
        schemeStrLen = (uint16_t)strlen(schemeStr);

        remptr = (uint8_t *)line;
        do {
            SCLogDebug("Looking for URL String starting with: %s", schemeStr);

            /* Check for token definition */
            fptr = FindBuffer(remptr, len - (remptr - line), (uint8_t *)schemeStr, schemeStrLen);
            if (fptr != NULL) {
                if (!mdcfg->log_url_scheme) {
                    fptr += schemeStrLen; /* Strip scheme from stored URL */
                }
                tok = GetToken(fptr, len - (fptr - line), " \"\'<>]\t", &remptr, &tokLen);
                if (tok == fptr) {
                    SCLogDebug("Found url string");

                    /* First copy to temp URL string */
                    tempUrl = SCMalloc(tokLen);
                    if (unlikely(tempUrl == NULL)) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
                        return MIME_DEC_ERR_MEM;
                    }

                    PrintChars(SC_LOG_DEBUG, "RAW URL", tok, tokLen);

                    /* Copy over to temp URL while decoding */
                    tempUrlLen = 0;
                    for (i = 0; i < tokLen && tok[i] != 0; i++) {
                        /* url is all lowercase */
                        tempUrl[tempUrlLen] = u8_tolower(tok[i]);
                        tempUrlLen++;
                    }

                    urlHost = tempUrl;
                    urlHostLen = tempUrlLen;
                    if (mdcfg->log_url_scheme) {
                        /* tempUrl contains the scheme in the string but
                         * IsIpv4Host & IsPv6Host methods below require
                         * an input URL string with scheme stripped. Get a
                         * reference sub-string urlHost which starts with
                         * the host instead of the scheme. */
                        urlHost += schemeStrLen;
                        urlHostLen -= schemeStrLen;
                    }

                    /* Determine if URL points to an EXE */
                    if (IsExeUrl(tempUrl, tempUrlLen)) {
                        flags |= URL_IS_EXE;

                        PrintChars(SC_LOG_DEBUG, "EXE URL", tempUrl, tempUrlLen);
                    }

                    /* Make sure remaining URL exists */
                    if (tempUrlLen > 0) {
                        if (!(FindExistingUrl(entity, tempUrl, tempUrlLen))) {
                            /* Now look for numeric IP */
                            if (IsIpv4Host(urlHost, urlHostLen)) {
                                flags |= URL_IS_IP4;

                                PrintChars(SC_LOG_DEBUG, "IP URL4", tempUrl, tempUrlLen);
                            } else if (IsIpv6Host(urlHost, urlHostLen)) {
                                flags |= URL_IS_IP6;

                                PrintChars(SC_LOG_DEBUG, "IP URL6", tempUrl, tempUrlLen);
                            }

                            /* Add URL list item */
                            MimeDecAddUrl(entity, tempUrl, tempUrlLen, flags);
                        } else {
                            SCFree(tempUrl);
                        }
                    } else {
                        SCFree(tempUrl);
                    }

                    /* Reset flags for next URL */
                    flags = 0;
                }
            }
        } while (fptr != NULL);
    }

    return ret;
}

/**
 * \brief This function is a pre-processor for handling decoded data chunks that
 * then invokes the caller's callback function for further processing
 *
 * \param chunk The decoded chunk
 * \param len The decoded chunk length (varies)
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessDecodedDataChunk(const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint8_t *remainPtr, *tok;
    uint32_t tokLen;

    if ((state->stack != NULL) && (state->stack->top != NULL) &&
        (state->stack->top->data != NULL)) {
        MimeDecConfig *mdcfg = MimeDecGetConfig();
        if (mdcfg != NULL && mdcfg->extract_urls) {
            MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;
            /* If plain text or html, then look for URLs */
            if (((entity->ctnt_flags & CTNT_IS_TEXT) ||
                (entity->ctnt_flags & CTNT_IS_MSG) ||
                (entity->ctnt_flags & CTNT_IS_HTML)) &&
                ((entity->ctnt_flags & CTNT_IS_ATTACHMENT) == 0)) {

                /* Parse each line one by one */
                remainPtr = (uint8_t *)chunk;
                do {
                    tok = GetLine(
                            remainPtr, len - (remainPtr - (uint8_t *)chunk), &remainPtr, &tokLen);
                    if (tok != remainPtr) {
                        /* If last token found without CR/LF delimiter, then save
                         * and reconstruct with next chunk
                         */
                        if (tok + tokLen - (uint8_t *)chunk == (int)len) {
                            PrintChars(SC_LOG_DEBUG, "LAST CHUNK LINE - CUTOFF", tok, tokLen);
                            SCLogDebug("\nCHUNK CUTOFF CHARS: %u delim %u\n", tokLen,
                                    len - (uint32_t)(tok + tokLen - (uint8_t *)chunk));
                        } else {
                            /* Search line for URL */
                            ret = FindUrlStrings(tok, tokLen, state);
                            if (ret != MIME_DEC_OK) {
                                SCLogDebug("Error: FindUrlStrings() function"
                                           " failed: %d",
                                        ret);
                                break;
                            }
                        }
                    }
                } while (tok != remainPtr && remainPtr - (uint8_t *)chunk < (int)len);
            }
        }

        /* Now invoke callback */
        if (state->DataChunkProcessorFunc != NULL) {
            ret = state->DataChunkProcessorFunc(chunk, len, state);
            if (ret != MIME_DEC_OK) {
                SCLogDebug("Error: state->dataChunkProcessor() callback function"
                            " failed");
            }
        }
    } else {
        SCLogDebug("Error: Stack pointer missing");
        ret = MIME_DEC_ERR_DATA;
    }

    /* Reset data chunk buffer */
    state->data_chunk_len = 0;

    /* Mark body / file as no longer at beginning */
    state->body_begin = 0;

    return ret;
}

/**
 * \brief Processes a remainder (line % 4 = remainder) from the previous line
 * such that all base64 decoding attempts are divisible by 4
 *
 * \param buf The current line
 * \param len The length of the line
 * \param state The current parser state
 * \param force Flag indicating whether decoding should always occur
 *
 * \return Number of bytes consumed from `buf`
 */
static uint8_t ProcessBase64Remainder(
        const uint8_t *buf, const uint32_t len, MimeDecParseState *state, int force)
{
    uint8_t buf_consumed = 0; /* consumed bytes from 'buf' */
    uint8_t cnt = 0;
    uint8_t block[B64_BLOCK];

    SCLogDebug("len %u force %d", len, force);

    /* should be impossible, but lets be defensive */
    DEBUG_VALIDATE_BUG_ON(state->bvr_len > B64_BLOCK);
    if (state->bvr_len > B64_BLOCK) {
        state->bvr_len = 0;
        return 0;
    }

    /* Strip spaces in remainder */
    for (uint8_t i = 0; i < state->bvr_len; i++) {
        if (state->bvremain[i] != ' ') {
            block[cnt++] = state->bvremain[i];
        }
    }

    /* if we don't have 4 bytes see if we can fill it from `buf` */
    if (buf && len > 0 && cnt != B64_BLOCK) {
        for (uint32_t i = 0; i < len && cnt < B64_BLOCK; i++) {
            if (buf[i] != ' ') {
                block[cnt++] = buf[i];
            }
            buf_consumed++;
        }
        if (cnt != 0) {
            memcpy(state->bvremain, block, cnt);
        }
        state->bvr_len = cnt;
    } else if (!force && cnt != B64_BLOCK) {
        SCLogDebug("incomplete data and no buffer to backfill");
        return 0;
    }

    /* in force mode pad the block */
    if (force && cnt != B64_BLOCK) {
        SCLogDebug("force and cnt %u != %u", cnt, B64_BLOCK);
        for (uint8_t i = state->bvr_len; i < B64_BLOCK; i++) {
            state->bvremain[state->bvr_len++] = '=';
        }
    }

    /* If data chunk buffer will be full, then clear it now */
    if (DATA_CHUNK_SIZE - state->data_chunk_len < ASCII_BLOCK) {

        /* Invoke pre-processor and callback */
        uint32_t ret = ProcessDecodedDataChunk(state->data_chunk, state->data_chunk_len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessDecodedDataChunk() function failed");
        }
    }

    if (state->bvr_len == B64_BLOCK || force) {
        uint32_t consumed_bytes = 0;
        uint32_t remdec = 0;
        const uint32_t avail_space = DATA_CHUNK_SIZE - state->data_chunk_len;
        PrintChars(SC_LOG_DEBUG, "BASE64 INPUT (bvremain)", state->bvremain, state->bvr_len);
        Base64Ecode code = DecodeBase64(state->data_chunk + state->data_chunk_len, avail_space,
                state->bvremain, state->bvr_len, &consumed_bytes, &remdec, BASE64_MODE_RFC2045);
        SCLogDebug("DecodeBase64 result %u", code);
        if (remdec > 0 && (code == BASE64_ECODE_OK || code == BASE64_ECODE_BUF)) {
            PrintChars(SC_LOG_DEBUG, "BASE64 DECODED (bvremain)",
                    state->data_chunk + state->data_chunk_len, remdec);

            state->data_chunk_len += remdec;

            /* If data chunk buffer is now full, then clear */
            if (DATA_CHUNK_SIZE - state->data_chunk_len < ASCII_BLOCK) {

                /* Invoke pre-processor and callback */
                uint32_t ret =
                        ProcessDecodedDataChunk(state->data_chunk, state->data_chunk_len, state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("Error: ProcessDecodedDataChunk() function "
                            "failed");
                }
            }
        } else if (code == BASE64_ECODE_ERR) {
            /* Track failed base64 */
            state->stack->top->data->anomaly_flags |= ANOM_INVALID_BASE64;
            state->msg->anomaly_flags |= ANOM_INVALID_BASE64;
            SCLogDebug("Error: DecodeBase64() function failed");
            PrintChars(SC_LOG_DEBUG, "Base64 failed string", state->bvremain, state->bvr_len);
        }

        /* Reset remaining */
        state->bvr_len = 0;
    }

    DEBUG_VALIDATE_BUG_ON(buf_consumed > len);
    return buf_consumed;
}

/**
 * \brief Processes a body line by base64-decoding and passing to the data chunk
 * processing callback function when the buffer is read
 *
 * \param buf The current line
 * \param len The length of the line
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessBase64BodyLine(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint32_t numDecoded, remaining = len, offset = 0;

    /* Track long line TODO should we count space padding too? */
    if (len > MAX_ENC_LINE_LEN) {
        state->stack->top->data->anomaly_flags |= ANOM_LONG_ENC_LINE;
        state->msg->anomaly_flags |= ANOM_LONG_ENC_LINE;
        SCLogDebug("Error: Max encoded input line length exceeded %u > %u",
                len, MAX_ENC_LINE_LEN);
    }

    if (state->bvr_len + len < B64_BLOCK) {
        memcpy(state->bvremain + state->bvr_len, buf, len);
        state->bvr_len += len;
        return MIME_DEC_OK;
    }

    /* First process remaining from previous line. We will consume
     * state->bvremain, filling it from 'buf' until we have a properly
     * sized block. Spaces are skipped (rfc2045). If state->bvr_len
     * is not 0 after procesing we have no data left at 'buf'. */
    if (state->bvr_len > 0) {
        uint32_t consumed = ProcessBase64Remainder(buf, len, state, 0);
        DEBUG_VALIDATE_BUG_ON(consumed > len);
        if (consumed > len)
            return MIME_DEC_ERR_PARSE;

        uint32_t left = len - consumed;
        if (left < B64_BLOCK) {
            DEBUG_VALIDATE_BUG_ON(left + state->bvr_len > B64_BLOCK);
            if (left + state->bvr_len > B64_BLOCK)
                return MIME_DEC_ERR_PARSE;
            memcpy(state->bvremain, buf + consumed, left);
            state->bvr_len += left;
            return MIME_DEC_OK;
        }

        remaining -= consumed;
        offset = consumed;
    }

    while (remaining > 0 && remaining >= B64_BLOCK) {
        uint32_t consumed_bytes = 0;
        uint32_t avail_space = DATA_CHUNK_SIZE - state->data_chunk_len;
        PrintChars(SC_LOG_DEBUG, "BASE64 INPUT (line)", buf + offset, remaining);
        Base64Ecode code = DecodeBase64(state->data_chunk + state->data_chunk_len, avail_space,
                buf + offset, remaining, &consumed_bytes, &numDecoded, BASE64_MODE_RFC2045);
        SCLogDebug("DecodeBase64 result %u", code);
        DEBUG_VALIDATE_BUG_ON(consumed_bytes > remaining);
        if (consumed_bytes > remaining)
            return MIME_DEC_ERR_PARSE;

        uint32_t leftover_bytes = remaining - consumed_bytes;
        if (numDecoded > 0 && (code == BASE64_ECODE_OK || code == BASE64_ECODE_BUF)) {
            PrintChars(SC_LOG_DEBUG, "BASE64 DECODED (line)",
                    state->data_chunk + state->data_chunk_len, numDecoded);

            state->data_chunk_len += numDecoded;

            if ((int)(DATA_CHUNK_SIZE - state->data_chunk_len) < 0) {
                SCLogDebug("Error: Invalid Chunk length: %u", state->data_chunk_len);
                return MIME_DEC_ERR_PARSE;
            }
            /* If buffer full, then invoke callback */
            if (DATA_CHUNK_SIZE - state->data_chunk_len < ASCII_BLOCK) {
                /* Invoke pre-processor and callback */
                ret = ProcessDecodedDataChunk(state->data_chunk, state->data_chunk_len, state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("Error: ProcessDecodedDataChunk() function failed");
                    break;
                }
            }
        } else if (code == BASE64_ECODE_ERR) {
            /* Track failed base64 */
            state->stack->top->data->anomaly_flags |= ANOM_INVALID_BASE64;
            state->msg->anomaly_flags |= ANOM_INVALID_BASE64;
            SCLogDebug("Error: DecodeBase64() function failed");
            return MIME_DEC_ERR_DATA;
        }

        /* corner case: multiples spaces in the last data, leading it to exceed the block
         * size. We strip of spaces this while storing it in bvremain */
        if (consumed_bytes == 0 && leftover_bytes > B64_BLOCK) {
            DEBUG_VALIDATE_BUG_ON(state->bvr_len != 0);
            for (uint32_t i = 0; i < leftover_bytes; i++) {
                if (buf[offset] != ' ') {
                    DEBUG_VALIDATE_BUG_ON(state->bvr_len >= B64_BLOCK);
                    if (state->bvr_len >= B64_BLOCK)
                        return MIME_DEC_ERR_DATA;
                    state->bvremain[state->bvr_len++] = buf[offset];
                }
                offset++;
            }
            return MIME_DEC_OK;

        } else if (leftover_bytes > 0 && leftover_bytes <= B64_BLOCK) {
            /* If remaining is 4 by this time, we encountered spaces during processing */
            DEBUG_VALIDATE_BUG_ON(state->bvr_len != 0);
            memcpy(state->bvremain, buf + offset + consumed_bytes, leftover_bytes);
            state->bvr_len = (uint8_t)leftover_bytes;
            return MIME_DEC_OK;
        }

        /* Update counts */
        remaining = leftover_bytes;
        offset += consumed_bytes;
    }
    return ret;
}

/**
 * \brief Decoded a hex character into its equivalent byte value for
 * quoted-printable decoding
 *
 * \param h The hex char
 *
 * \return byte value on success, -1 if failed
 **/
static int8_t DecodeQPChar(char h)
{
    int8_t res = 0;

    /* 0-9 */
    if (h >= 48 && h <= 57) {
        res = h - 48;
    } else if (h >= 65 && h <= 70) {
        /* A-F */
        res = h - 55;
    } else {
        /* Invalid */
        res = -1;
    }

    return res;

}

/**
 * \brief Processes a quoted-printable encoded body line by decoding and passing
 * to the data chunk processing callback function when the buffer is read
 *
 * \param buf The current line
 * \param len The length of the line
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessQuotedPrintableBodyLine(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint32_t remaining, offset;
    MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;
    uint8_t c, h1, h2, val;
    int16_t res;

    /* Track long line */
    if (len > MAX_ENC_LINE_LEN) {
        state->stack->top->data->anomaly_flags |= ANOM_LONG_ENC_LINE;
        state->msg->anomaly_flags |= ANOM_LONG_ENC_LINE;
        SCLogDebug("Error: Max encoded input line length exceeded %u > %u",
                len, MAX_ENC_LINE_LEN);
    }

    remaining = len;
    offset = 0;
    while (remaining > 0) {

        c = *(buf + offset);

        /* Copy over normal character */
        if (c != '=') {
            state->data_chunk[state->data_chunk_len] = c;
            state->data_chunk_len++;

            /* Add CRLF sequence if end of line, unless its a partial line */
            if (remaining == 1 && state->current_line_delimiter_len > 0) {
                memcpy(state->data_chunk + state->data_chunk_len, CRLF, EOL_LEN);
                state->data_chunk_len += EOL_LEN;
            }
        } else if (remaining > 1) {
            /* If last character handle as soft line break by ignoring,
                       otherwise process as escaped '=' character */

            /* Not enough characters */
            if (remaining < 3) {
                entity->anomaly_flags |= ANOM_INVALID_QP;
                state->msg->anomaly_flags |= ANOM_INVALID_QP;
                SCLogDebug("Error: Quoted-printable decoding failed");
            } else {
                h1 = *(buf + offset + 1);
                res = DecodeQPChar(h1);
                if (res < 0) {
                    entity->anomaly_flags |= ANOM_INVALID_QP;
                    state->msg->anomaly_flags |= ANOM_INVALID_QP;
                    SCLogDebug("Error: Quoted-printable decoding failed");
                } else {
                    val = (uint8_t)(res << 4); /* Shift result left */
                    h2 = *(buf + offset + 2);
                    res = DecodeQPChar(h2);
                    if (res < 0) {
                        entity->anomaly_flags |= ANOM_INVALID_QP;
                        state->msg->anomaly_flags |= ANOM_INVALID_QP;
                        SCLogDebug("Error: Quoted-printable decoding failed");
                    } else {
                        /* Decoding sequence succeeded */
                        val += res;

                        state->data_chunk[state->data_chunk_len] = val;
                        state->data_chunk_len++;

                        /* Add CRLF sequence if end of line, unless for partial lines */
                        if (remaining == 3 && state->current_line_delimiter_len > 0) {
                            memcpy(state->data_chunk + state->data_chunk_len,
                                    CRLF, EOL_LEN);
                            state->data_chunk_len += EOL_LEN;
                        }

                        /* Account for extra 2 characters in 3-characted QP
                         * sequence */
                        remaining -= 2;
                        offset += 2;
                    }
                }
            }
        }

        /* Change by 1 */
        remaining--;
        offset++;

        /* If buffer full, then invoke callback */
        if (DATA_CHUNK_SIZE - state->data_chunk_len < EOL_LEN + 1) {

            /* Invoke pre-processor and callback */
            ret = ProcessDecodedDataChunk(state->data_chunk, state->data_chunk_len,
                    state);
            if (ret != MIME_DEC_OK) {
                SCLogDebug("Error: ProcessDecodedDataChunk() function "
                        "failed");
            }
        }
    }

    return ret;
}

/**
 * \brief Processes a body line by base64-decoding (if applicable) and passing to
 * the data chunk processing callback function
 *
 * \param buf The current line
 * \param len The length of the line
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessBodyLine(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint32_t remaining, offset, avail, tobuf;
    MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;

    SCLogDebug("Processing body line");

    /* Process base-64 content if enabled */
    MimeDecConfig *mdcfg = MimeDecGetConfig();
    if (mdcfg != NULL && mdcfg->decode_base64 &&
            (entity->ctnt_flags & CTNT_IS_BASE64)) {

        ret = ProcessBase64BodyLine(buf, len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessBase64BodyLine() function failed");
        }
    } else if (mdcfg != NULL && mdcfg->decode_quoted_printable &&
            (entity->ctnt_flags & CTNT_IS_QP)) {
        /* Process quoted-printable content if enabled */
        ret = ProcessQuotedPrintableBodyLine(buf, len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessQuotedPrintableBodyLine() function "
                    "failed");
        }
    } else {
        /* Process non-decoded content */
        remaining = len + state->current_line_delimiter_len;
        offset = 0;
        while (remaining > 0) {
            /* Plan to add CRLF to the end of each line */
            avail = DATA_CHUNK_SIZE - state->data_chunk_len;
            tobuf = avail > remaining ? remaining : avail;

            /* Copy over to buffer */
            memcpy(state->data_chunk + state->data_chunk_len, buf + offset, tobuf);
            state->data_chunk_len += tobuf;

            if ((int) (DATA_CHUNK_SIZE - state->data_chunk_len) < 0) {
                SCLogDebug("Error: Invalid Chunk length: %u",
                        state->data_chunk_len);
                ret = MIME_DEC_ERR_PARSE;
                break;
            }

            /* If buffer full, then invoke callback */
            if (DATA_CHUNK_SIZE - state->data_chunk_len == 0) {
                /* Invoke pre-processor and callback */
                ret = ProcessDecodedDataChunk(state->data_chunk,
                        state->data_chunk_len, state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("Error: ProcessDecodedDataChunk() function "
                            "failed");
                }
            }

            remaining -= tobuf;
            offset += tobuf;
        }
    }

    return ret;
}

/**
 * \brief Find the start of a header name on the current line
 *
 * \param buf The input line (not null-terminated)
 * \param blen The length of the input line
 * \param glen The output length of the header name
 *
 * \return Pointer to header name, or NULL if not found
 */
static uint8_t * FindMimeHeaderStart(const uint8_t *buf, uint32_t blen, uint32_t *hlen)
{
    uint32_t i, valid = 0;
    uint8_t *hname = NULL;

    /* Init */
    *hlen = 0;

    /* Look for sequence of printable characters followed by ':', or
       CRLF then printable characters followed by ':' */
    for (i = 0; i < blen && buf[i] != 0; i++) {

        /* If ready for printable characters and found one, then increment */
        if (buf[i] != COLON && buf[i] >= PRINTABLE_START &&
                buf[i] <= PRINTABLE_END) {
            valid++;
        } else if (valid > 0 && buf[i] == COLON) {
            /* If ready for printable characters, found some, and found colon
             * delimiter, then a match is found */
            hname = (uint8_t *) buf + i - valid;
            *hlen = valid;
            break;
        } else {
            /* Otherwise reset and quit */
            break;
        }
    }

    return hname;
}

/**
 * \brief Find full header name and value on the current line based on the
 * current state
 *
 * \param buf The current line (no CRLF)
 * \param blen The length of the current line
 * \param state The current state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int FindMimeHeader(const uint8_t *buf, uint32_t blen,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint8_t *hname, *hval = NULL;
    DataValue *dv;
    uint32_t hlen, vlen;
    int finish_header = 0, new_header = 0;
    MimeDecConfig *mdcfg = MimeDecGetConfig();

    /* should not get here with incomplete lines */
    DEBUG_VALIDATE_BUG_ON(state->current_line_delimiter_len == 0);

    /* Find first header */
    hname = FindMimeHeaderStart(buf, blen, &hlen);
    if (hname != NULL) {

        /* Warn and track but don't do anything yet */
        if (hlen > MAX_HEADER_NAME) {
            state->stack->top->data->anomaly_flags |= ANOM_LONG_HEADER_NAME;
            state->msg->anomaly_flags |= ANOM_LONG_HEADER_NAME;
            SCLogDebug("Error: Header name exceeds limit (%u > %u)",
                    hlen, MAX_HEADER_NAME);
        }

        /* Value starts after 'header:' (normalize spaces) */
        hval = hname + hlen + 1;
        if (hval - buf >= (int)blen) {
            SCLogDebug("No Header value found");
            hval = NULL;
        } else {
            while (hval[0] == ' ') {

                /* If last character before end of bounds, set to NULL */
                if (hval - buf >= (int)blen - 1) {
                    SCLogDebug("No Header value found");
                    hval = NULL;
                    break;
                }

                hval++;
            }
        }

        /* If new header found, then previous header is finished */
        if (state->state_flag == HEADER_STARTED) {
            finish_header = 1;
        }

        /* Now process new header */
        new_header = 1;

        /* Must wait for next line to determine if finished */
        state->state_flag = HEADER_STARTED;
    } else if (blen == 0) {
        /* Found body */
        /* No more headers */
        state->state_flag = HEADER_DONE;

        finish_header = 1;

        SCLogDebug("All Header processing finished");
    } else if (state->state_flag == HEADER_STARTED) {
        /* Found multi-line value (ie. Received header) */
        /* If max header value exceeded, flag it */
        vlen = blen;
        if ((mdcfg != NULL) && (state->hvlen + vlen > mdcfg->header_value_depth)) {
            SCLogDebug("Error: Header value of length (%u) is too long",
                    state->hvlen + vlen);
            vlen = mdcfg->header_value_depth - state->hvlen;
            state->stack->top->data->anomaly_flags |= ANOM_LONG_HEADER_VALUE;
            state->msg->anomaly_flags |= ANOM_LONG_HEADER_VALUE;
        }
        if (vlen > 0) {
            dv = AddDataValue(state->hvalue);
            if (dv == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "AddDataValue() function failed");
                return MIME_DEC_ERR_MEM;
            }
            if (state->hvalue == NULL) {
                state->hvalue = dv;
            }

            dv->value = SCMalloc(vlen);
            if (unlikely(dv->value == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
                return MIME_DEC_ERR_MEM;
            }
            memcpy(dv->value, buf, vlen);
            dv->value_len = vlen;
            state->hvlen += vlen;
        }
    } else {
        /* Likely a body without headers */
        SCLogDebug("No headers found");

        state->state_flag = BODY_STARTED;

        /* Flag beginning of body */
        state->body_begin = 1;
        state->body_end = 0;

        ret = ProcessBodyLine(buf, blen, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessBodyLine() function failed");
            return ret;
        }
    }

    /* If we need to finish a header, then do so below and then cleanup */
    if (finish_header) {
        /* Store the header value */
        ret = StoreMimeHeader(state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: StoreMimeHeader() function failed");
            return ret;
        }
    }

    /* When next header is found, we always create a new one */
    if (new_header) {
        /* Copy name and value to state */
        state->hname = SCMalloc(hlen);
        if (unlikely(state->hname == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
            return MIME_DEC_ERR_MEM;
        }
        memcpy(state->hname, hname, hlen);
        state->hlen = hlen;

        if (state->hvalue != NULL) {
            SCLogDebug("Error: Parser failed due to unexpected header "
                    "value");
            return MIME_DEC_ERR_DATA;
        }

        if (hval != NULL) {
            /* If max header value exceeded, flag it */
            vlen = blen - (hval - buf);
            if ((mdcfg != NULL) && (state->hvlen + vlen > mdcfg->header_value_depth)) {
                SCLogDebug("Error: Header value of length (%u) is too long",
                        state->hvlen + vlen);
                vlen = mdcfg->header_value_depth - state->hvlen;
                state->stack->top->data->anomaly_flags |= ANOM_LONG_HEADER_VALUE;
                state->msg->anomaly_flags |= ANOM_LONG_HEADER_VALUE;
            }

            if (vlen > 0) {
                state->hvalue = AddDataValue(NULL);
                if (state->hvalue == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "AddDataValue() function failed");
                    return MIME_DEC_ERR_MEM;
                }
                state->hvalue->value = SCMalloc(vlen);
                if (unlikely(state->hvalue->value == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
                    return MIME_DEC_ERR_MEM;
                }
                memcpy(state->hvalue->value, hval, vlen);
                state->hvalue->value_len = vlen;
                state->hvlen += vlen;
            }
        }
    }

    return ret;
}

/**
 * \brief Processes the current line for mime headers and also does post-processing
 * when all headers found
 *
 * \param buf The current line
 * \param len The length of the line
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessMimeHeaders(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    MimeDecField *field;
    uint8_t *rptr = NULL;
    uint32_t blen = 0;
    MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;
    uint8_t bptr[RS_MIME_MAX_TOKEN_LEN];

    /* Look for mime header in current line */
    ret = FindMimeHeader(buf, len, state);
    if (ret != MIME_DEC_OK) {
        SCLogDebug("Error: FindMimeHeader() function failed: %d", ret);
        return ret;
    }

    /* Post-processing after all headers done */
    if (state->state_flag == HEADER_DONE) {
        /* First determine encoding by looking at Content-Transfer-Encoding */
        field = MimeDecFindField(entity, CTNT_TRAN_STR);
        if (field != NULL) {
            /* Look for base64 */
            if (FindBuffer(field->value, field->value_len, (const uint8_t *)BASE64_STR,
                        (uint16_t)strlen(BASE64_STR))) {
                SCLogDebug("Base64 encoding found");
                entity->ctnt_flags |= CTNT_IS_BASE64;
            } else if (FindBuffer(field->value, field->value_len, (const uint8_t *)QP_STR,
                               (uint16_t)strlen(QP_STR))) {
                /* Look for quoted-printable */
                SCLogDebug("quoted-printable encoding found");
                entity->ctnt_flags |= CTNT_IS_QP;
            }
        }

        /* Check for file attachment in content disposition */
        field = MimeDecFindField(entity, CTNT_DISP_STR);
        if (field != NULL) {
            bool truncated_name = false;
            if (rs_mime_find_header_token(field->value, field->value_len,
                        (const uint8_t *)"filename", strlen("filename"), &bptr, &blen)) {
                SCLogDebug("File attachment found in disposition");
                entity->ctnt_flags |= CTNT_IS_ATTACHMENT;

                if (blen > RS_MIME_MAX_TOKEN_LEN) {
                    blen = RS_MIME_MAX_TOKEN_LEN;
                    truncated_name = true;
                }

                /* Copy over using dynamic memory */
                entity->filename = SCMalloc(blen);
                if (unlikely(entity->filename == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
                    return MIME_DEC_ERR_MEM;
                }
                memcpy(entity->filename, bptr, blen);
                entity->filename_len = blen;

                if (truncated_name) {
                    state->stack->top->data->anomaly_flags |= ANOM_LONG_FILENAME;
                    state->msg->anomaly_flags |= ANOM_LONG_FILENAME;
                }
            }
        }

        /* Check for boundary, encapsulated message, and file name in Content-Type */
        field = MimeDecFindField(entity, CTNT_TYPE_STR);
        if (field != NULL) {
            /* Check if child entity boundary definition found */
            // RS_MIME_MAX_TOKEN_LEN is RS_MIME_MAX_TOKEN_LEN on the rust side
            if (rs_mime_find_header_token(field->value, field->value_len,
                        (const uint8_t *)"boundary", strlen("boundary"), &bptr, &blen)) {
                state->found_child = 1;
                entity->ctnt_flags |= CTNT_IS_MULTIPART;

                if (blen > (BOUNDARY_BUF - 2)) {
                    state->stack->top->data->anomaly_flags |= ANOM_LONG_BOUNDARY;
                    return MIME_DEC_ERR_PARSE;
                }

                /* Store boundary in parent node */
                state->stack->top->bdef = SCMalloc(blen);
                if (unlikely(state->stack->top->bdef == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
                    return MIME_DEC_ERR_MEM;
                }
                memcpy(state->stack->top->bdef, bptr, blen);
                state->stack->top->bdef_len = (uint16_t)blen;
            }

            /* Look for file name (if not already found) */
            if (!(entity->ctnt_flags & CTNT_IS_ATTACHMENT)) {
                bool truncated_name = false;
                if (rs_mime_find_header_token(field->value, field->value_len,
                            (const uint8_t *)"name", strlen("name"), &bptr, &blen)) {
                    SCLogDebug("File attachment found");
                    entity->ctnt_flags |= CTNT_IS_ATTACHMENT;

                    if (blen > RS_MIME_MAX_TOKEN_LEN) {
                        blen = RS_MIME_MAX_TOKEN_LEN;
                        truncated_name = true;
                    }

                    /* Copy over using dynamic memory */
                    entity->filename = SCMalloc(blen);
                    if (unlikely(entity->filename == NULL)) {
                        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
                        return MIME_DEC_ERR_MEM;
                    }
                    memcpy(entity->filename, bptr, blen);
                    entity->filename_len = blen;

                    if (truncated_name) {
                        state->stack->top->data->anomaly_flags |= ANOM_LONG_FILENAME;
                        state->msg->anomaly_flags |= ANOM_LONG_FILENAME;
                    }
                }
            }

            /* Pull out short-hand content type */
            entity->ctnt_type = GetToken(field->value, field->value_len, " \r\n;",
                    &rptr, &entity->ctnt_type_len);
            if (entity->ctnt_type != NULL) {
                /* Check for encapsulated message */
                if (FindBuffer(entity->ctnt_type, entity->ctnt_type_len, (const uint8_t *)MSG_STR,
                            (uint16_t)strlen(MSG_STR))) {
                    SCLogDebug("Found encapsulated message entity");

                    entity->ctnt_flags |= CTNT_IS_ENV;

                    /* Create and push child to stack */
                    MimeDecEntity *child = MimeDecAddEntity(entity);
                    if (child == NULL)
                        return MIME_DEC_ERR_MEM;
                    child->ctnt_flags |= (CTNT_IS_ENCAP | CTNT_IS_MSG);
                    PushStack(state->stack);
                    state->stack->top->data = child;

                    /* Mark as encapsulated child */
                    state->stack->top->is_encap = 1;

                    /* Ready to parse headers */
                    state->state_flag = HEADER_READY;
                } else if (FindBuffer(entity->ctnt_type, entity->ctnt_type_len,
                                   (const uint8_t *)MULTIPART_STR,
                                   (uint16_t)strlen(MULTIPART_STR))) {
                    /* Check for multipart */
                    SCLogDebug("Found multipart entity");
                    entity->ctnt_flags |= CTNT_IS_MULTIPART;
                } else if (FindBuffer(entity->ctnt_type, entity->ctnt_type_len,
                                   (const uint8_t *)TXT_STR, (uint16_t)strlen(TXT_STR))) {
                    /* Check for plain text */
                    SCLogDebug("Found plain text entity");
                    entity->ctnt_flags |= CTNT_IS_TEXT;
                } else if (FindBuffer(entity->ctnt_type, entity->ctnt_type_len,
                                   (const uint8_t *)HTML_STR, (uint16_t)strlen(HTML_STR))) {
                    /* Check for html */
                    SCLogDebug("Found html entity");
                    entity->ctnt_flags |= CTNT_IS_HTML;
                }
            }
        }

        /* Store pointer to Message-ID */
        field = MimeDecFindField(entity, MSG_ID_STR);
        if (field != NULL) {
            entity->msg_id = field->value;
            entity->msg_id_len = field->value_len;
        }

        /* Flag beginning of body */
        state->body_begin = 1;
        state->body_end = 0;
    }

    return ret;
}

/**
 * \brief Indicates to the parser that the body of an entity has completed
 * processing on the previous line
 *
 * \param state The current parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */

static int ProcessBodyComplete(MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;

    SCLogDebug("Process body complete called");

    /* Mark the file as hitting the end */
    state->body_end = 1;

    if (state->bvr_len > 0) {
        SCLogDebug("Found (%u) remaining base64 bytes not processed",
                state->bvr_len);

        /* Process the remainder */
        ret = ProcessBase64Remainder(NULL, 0, state, 1);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessBase64BodyLine() function failed");
        }
    }

    /* Invoke pre-processor and callback with remaining data */
    ret = ProcessDecodedDataChunk(state->data_chunk, state->data_chunk_len, state);
    if (ret != MIME_DEC_OK) {
        SCLogDebug("Error: ProcessDecodedDataChunk() function failed");
    }

    /* Now reset */
    state->body_begin = 0;
    state->body_end = 0;

    return ret;
}

/**
 * \brief When a mime boundary is found, look for end boundary and also do stack
 * management
 *
 * \param buf The current line
 * \param len The length of the line
 * \param bdef_len The length of the current boundary
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessMimeBoundary(
        const uint8_t *buf, uint32_t len, uint16_t bdef_len, MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint8_t *rptr;
    MimeDecEntity *child;

    SCLogDebug("PROCESSING BOUNDARY - START: %d",
            state->state_flag);

    /* If previous line was not an end boundary, then we process the body as
     * completed */
    if (state->state_flag != BODY_END_BOUND) {

        /* First lets complete the body */
        ret = ProcessBodyComplete(state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessBodyComplete() function failed");
            return ret;
        }
    } else {
        /* If last line was an end boundary, then now we are ready to parse
         * headers again */
        state->state_flag = HEADER_READY;
    }

    /* Update remaining buffer */
    rptr = (uint8_t *) buf + bdef_len + 2;

    /* If entity is encapsulated and current and parent didn't define the boundary,
     * then pop out */
    if (state->stack->top->is_encap && state->stack->top->bdef_len == 0) {

        if (state->stack->top->next == NULL) {
            SCLogDebug("Error: Missing parent entity from stack");
            return MIME_DEC_ERR_DATA;
        }

        if (state->stack->top->next->bdef_len == 0) {

            SCLogDebug("POPPED ENCAPSULATED CHILD FROM STACK: %p=%p",
                    state->stack->top, state->stack->top->data);

            /* If end of boundary found, pop the child off the stack */
            PopStack(state->stack);
            if (state->stack->top == NULL) {
                SCLogDebug("Error: Message is malformed");
                return MIME_DEC_ERR_DATA;
            }
        }
    }

    /* Now check for end of nested boundary */
    if (len - (rptr - buf) > 1 && rptr[0] == DASH && rptr[1] == DASH) {
        SCLogDebug("FOUND END BOUNDARY, POPPING: %p=%p",
                state->stack->top, state->stack->top->data);

        /* If end of boundary found, pop the child off the stack */
        PopStack(state->stack);
        if (state->stack->top == NULL) {
            SCLogDebug("Error: Message is malformed");
            return MIME_DEC_ERR_DATA;
        }

        /* If current is an encapsulated message with a boundary definition,
         * then pop him as well */
        if (state->stack->top->is_encap && state->stack->top->bdef_len != 0) {
            SCLogDebug("FOUND END BOUNDARY AND ENCAP, POPPING: %p=%p",
                    state->stack->top, state->stack->top->data);

            PopStack(state->stack);
            if (state->stack->top == NULL) {
                SCLogDebug("Error: Message is malformed");
                return MIME_DEC_ERR_DATA;
            }
        }

        state->state_flag = BODY_END_BOUND;
    } else if (state->found_child) {
        /* Otherwise process new child */
        SCLogDebug("Child entity created");

        /* Create and push child to stack */
        child = MimeDecAddEntity(state->stack->top->data);
        if (child == NULL)
            return MIME_DEC_ERR_MEM;
        child->ctnt_flags |= CTNT_IS_BODYPART;
        PushStack(state->stack);
        state->stack->top->data = child;

        /* Reset flag */
        state->found_child = 0;
    } else {
        /* Otherwise process sibling */
        if (state->stack->top->next == NULL) {
            SCLogDebug("Error: Missing parent entity from stack");
            return MIME_DEC_ERR_DATA;
        }

        SCLogDebug("SIBLING CREATED, POPPING PARENT: %p=%p",
                state->stack->top, state->stack->top->data);

        /* First pop current to get access to parent */
        PopStack(state->stack);
        if (state->stack->top == NULL) {
            SCLogDebug("Error: Message is malformed");
            return MIME_DEC_ERR_DATA;
        }

        /* Create and push child to stack */
        child = MimeDecAddEntity(state->stack->top->data);
        if (child == NULL)
            return MIME_DEC_ERR_MEM;
        child->ctnt_flags |= CTNT_IS_BODYPART;
        PushStack(state->stack);
        state->stack->top->data = child;
    }

    /* After boundary look for headers */
    if (state->state_flag != BODY_END_BOUND) {
        state->state_flag = HEADER_READY;
    }

    SCLogDebug("PROCESSING BOUNDARY - END: %d", state->state_flag);
    return ret;
}

/**
 * \brief Processes the MIME Entity body based on the input line and current
 * state of the parser
 *
 * \param buf The current line
 * \param len The length of the line
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessMimeBody(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;
    uint8_t temp[BOUNDARY_BUF];
    uint8_t *bstart;
    int body_found = 0;
    uint16_t tlen;

    if (!g_disable_hashing) {
        if (MimeDecGetConfig()->body_md5) {
            if (state->body_begin == 1) {
                if (state->md5_ctx == NULL) {
                    state->md5_ctx = SCMd5New();
                }
            }
            SCMd5Update(state->md5_ctx, buf, len + state->current_line_delimiter_len);
        }
    }

    /* pass empty lines on if we're parsing the body, otherwise we have no use
     * for them, and in fact they would disrupt the state tracking */
    if (len == 0) {
        /* don't start a new body after an end bound based on an empty line */
        if (state->state_flag == BODY_END_BOUND) {
            SCLogDebug("skip empty line");
            return MIME_DEC_OK;
        } else if (state->state_flag == HEADER_DONE) {
            SCLogDebug("empty line, lets see if we skip it. We're in state %s",
                    MimeDecParseStateGetStatus(state));
            MimeDecEntity *entity = (MimeDecEntity *)state->stack->top->data;
            MimeDecConfig *mdcfg = MimeDecGetConfig();
            if (entity != NULL && mdcfg != NULL) {
                if (mdcfg->decode_base64 && (entity->ctnt_flags & CTNT_IS_BASE64)) {
                    SCLogDebug("skip empty line");
                    return MIME_DEC_OK;
                } else if (mdcfg->decode_quoted_printable && (entity->ctnt_flags & CTNT_IS_QP)) {
                    SCLogDebug("skip empty line");
                    return MIME_DEC_OK;
                }
                SCLogDebug("not skipping empty line");
            }
        } else {
            SCLogDebug("not skipping line at state %s", MimeDecParseStateGetStatus(state));
        }
    }

    /* First look for boundary */
    MimeDecStackNode *node = state->stack->top;
    if (node == NULL) {
        SCLogDebug("Error: Invalid stack state");
        return MIME_DEC_ERR_PARSE;
    }

    /* Traverse through stack to find a boundary definition */
    if (state->state_flag == BODY_END_BOUND || node->bdef == NULL) {

        /* If not found, then use parent's boundary */
        node = node->next;
        while (node != NULL && node->bdef == NULL) {
            SCLogDebug("Traversing through stack for node with boundary");
            node = node->next;
        }
    }

    /* This means no boundary / parent w/boundary was found so we are in the body */
    if (node == NULL) {
        body_found = 1;
    } else {

        /* Now look for start of boundary */
        if (len > 1 && buf[0] == '-' && buf[1] == '-') {

            tlen = node->bdef_len + 2;
            if (tlen > BOUNDARY_BUF) {
                if (state->stack->top->data)
                    state->stack->top->data->anomaly_flags |= ANOM_LONG_BOUNDARY;
                SCLogDebug("Error: Long boundary: tlen %u > %d. Set ANOM_LONG_BOUNDARY", tlen,
                        BOUNDARY_BUF);
                return MIME_DEC_ERR_PARSE;
            }

            memcpy(temp, "--", 2);
            memcpy(temp + 2, node->bdef, node->bdef_len);

            /* Find either next boundary or end boundary */
            bstart = FindBuffer(buf, len, temp, tlen);
            if (bstart != NULL) {
                ret = ProcessMimeBoundary(buf, len, node->bdef_len, state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("Error: ProcessMimeBoundary() function "
                            "failed");
                    return ret;
                }
            } else {
                /* Otherwise add value to body */
                body_found = 1;
            }
        } else {
            /* Otherwise add value to body */
            body_found = 1;
        }
    }

    /* Process body line */
    if (body_found) {
        state->state_flag = BODY_STARTED;

        ret = ProcessBodyLine(buf, len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessBodyLine() function failed");
            return ret;
        }
    }

    return ret;
}

const char *MimeDecParseStateGetStatus(MimeDecParseState *state)
{
    return StateFlags[state->state_flag];
}

/**
 * \brief Processes the MIME Entity based on the input line and current state of
 * the parser
 *
 * \param buf The current line
 * \param len The length of the line
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
static int ProcessMimeEntity(const uint8_t *buf, uint32_t len,
        MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;

    SCLogDebug("START FLAG: %s", StateFlags[state->state_flag]);

    if (state->state_flag == PARSE_ERROR) {
        SCLogDebug("START FLAG: PARSE_ERROR, bail");
        return MIME_DEC_ERR_STATE;
    }

    /* Track long line */
    if (len > MAX_LINE_LEN) {
        state->stack->top->data->anomaly_flags |= ANOM_LONG_LINE;
        state->msg->anomaly_flags |= ANOM_LONG_LINE;
        SCLogDebug("Error: Max input line length exceeded %u > %u", len,
                MAX_LINE_LEN);
    }

    /* Looking for headers */
    if (state->state_flag == HEADER_READY ||
            state->state_flag == HEADER_STARTED) {

        SCLogDebug("Processing Headers");

        /* Process message headers */
        ret = ProcessMimeHeaders(buf, len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessMimeHeaders() function failed: %d",
                    ret);
            return ret;
        }
    } else {
        /* Processing body */
        SCLogDebug("Processing Body of: %p", state->stack->top);

        ret = ProcessMimeBody(buf, len, state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: ProcessMimeBody() function failed: %d",
                    ret);
            return ret;
        }
    }

    SCLogDebug("END FLAG: %s", StateFlags[state->state_flag]);

    return ret;
}

/**
 * \brief Init the parser by allocating memory for the state and top-level entity
 *
 * \param data A caller-specified pointer to data for access within the data chunk
 * processor callback function
 * \param dcpfunc The data chunk processor callback function
 *
 * \return A pointer to the state object, or NULL if the operation fails
 */
MimeDecParseState * MimeDecInitParser(void *data,
        int (*DataChunkProcessorFunc)(const uint8_t *chunk, uint32_t len,
                MimeDecParseState *state))
{
    MimeDecParseState *state;
    MimeDecEntity *mimeMsg;

    state = SCMalloc(sizeof(MimeDecParseState));
    if (unlikely(state == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return NULL;
    }
    memset(state, 0x00, sizeof(MimeDecParseState));

    state->stack = SCMalloc(sizeof(MimeDecStack));
    if (unlikely(state->stack == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        SCFree(state);
        return NULL;
    }
    memset(state->stack, 0x00, sizeof(MimeDecStack));

    mimeMsg = SCMalloc(sizeof(MimeDecEntity));
    if (unlikely(mimeMsg == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        SCFree(state->stack);
        SCFree(state);
        return NULL;
    }
    memset(mimeMsg, 0x00, sizeof(MimeDecEntity));
    mimeMsg->ctnt_flags |= CTNT_IS_MSG;

    /* Init state */
    state->msg = mimeMsg;
    PushStack(state->stack);
    if (state->stack->top == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        SCFree(state->stack);
        SCFree(state);
        return NULL;
    }
    state->stack->top->data = mimeMsg;
    state->state_flag = HEADER_READY;
    state->data = data;
    state->DataChunkProcessorFunc = DataChunkProcessorFunc;

    return state;
}

/**
 * \brief De-Init parser by freeing up any residual memory
 *
 * \param state The parser state
 *
 * \return none
 */
void MimeDecDeInitParser(MimeDecParseState *state)
{
    uint32_t cnt = 0;

    while (state->stack->top != NULL) {
        SCLogDebug("Remaining on stack: [%p]=>[%p]",
                state->stack->top, state->stack->top->data);

        PopStack(state->stack);
        cnt++;
    }

    if (cnt > 1) {
        state->msg->anomaly_flags |= ANOM_MALFORMED_MSG;
        SCLogDebug("Warning: Stack is not empty upon completion of "
                "processing (%u items remaining)", cnt);
    }

    SCFree(state->hname);
    FreeDataValue(state->hvalue);
    FreeMimeDecStack(state->stack);
    if (state->md5_ctx)
        SCMd5Free(state->md5_ctx);
    SCFree(state);
}

/**
 * \brief Called to indicate that the last message line has been processed and
 * the parsing operation is complete
 *
 * This function should be called directly by the caller.
 *
 * \param state The parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
int MimeDecParseComplete(MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;

    SCLogDebug("Parsing flagged as completed");

    if (state->state_flag == PARSE_ERROR) {
        SCLogDebug("parser in error state: PARSE_ERROR");
        return MIME_DEC_ERR_STATE;
    }

    /* Store the header value */
    ret = StoreMimeHeader(state);
    if (ret != MIME_DEC_OK) {
        SCLogDebug("Error: StoreMimeHeader() function failed");
        return ret;
    }

    /* Lets complete the body */
    ret = ProcessBodyComplete(state);
    if (ret != MIME_DEC_OK) {
        SCLogDebug("Error: ProcessBodyComplete() function failed");
        return ret;
    }

    if (state->md5_ctx) {
        SCMd5Finalize(state->md5_ctx, state->md5, sizeof(state->md5));
        state->md5_ctx = NULL;
        state->has_md5 = true;
    }

    if (state->stack->top == NULL) {
        state->msg->anomaly_flags |= ANOM_MALFORMED_MSG;
        SCLogDebug("Error: Message is malformed");
        return MIME_DEC_ERR_DATA;
    }

    /* If encapsulated, pop off the stack */
    if (state->stack->top->is_encap) {
        PopStack(state->stack);
        if (state->stack->top == NULL) {
            state->msg->anomaly_flags |= ANOM_MALFORMED_MSG;
            SCLogDebug("Error: Message is malformed");
            return MIME_DEC_ERR_DATA;
        }
    }

    /* Look extra stack items remaining */
    if (state->stack->top->next != NULL) {
        state->msg->anomaly_flags |= ANOM_MALFORMED_MSG;
        SCLogDebug("Warning: Message has unclosed message part boundary");
    }

    state->state_flag = PARSE_DONE;

    return ret;
}

/**
 * \brief Parse a line of a MIME message and update the parser state
 *
 * \param line A string representing the line (w/out CRLF)
 * \param len The length of the line
 * \param delim_len The length of the line end delimiter
 * \param state The parser state
 *
 * \return MIME_DEC_OK on success, otherwise < 0 on failure
 */
int MimeDecParseLine(const uint8_t *line, const uint32_t len,
        const uint8_t delim_len, MimeDecParseState *state)
{
    int ret = MIME_DEC_OK;

    /* For debugging purposes */
    if (len > 0) {
        PrintChars(SC_LOG_DEBUG, "SMTP LINE", line, len);
    } else {
        SCLogDebug("SMTP LINE - EMPTY");
    }

    state->current_line_delimiter_len = delim_len;
    /* Process the entity */
    ret = ProcessMimeEntity(line, len, state);
    if (ret != MIME_DEC_OK) {
        state->state_flag = PARSE_ERROR;
        SCLogDebug("Error: ProcessMimeEntity() function failed: %d", ret);
    }

    return ret;
}

/**
 * \brief Parses an entire message when available in its entirety (wraps the
 * line-based parsing functions)
 *
 * \param buf Buffer pointing to the full message
 * \param blen Length of the buffer
 * \param data Caller data to be available in callback
 * \param dcpfunc Callback for processing each decoded body data chunk
 *
 * \return A pointer to the decoded MIME message, or NULL if the operation fails
 */
MimeDecEntity * MimeDecParseFullMsg(const uint8_t *buf, uint32_t blen, void *data,
        int (*dcpfunc)(const uint8_t *chunk, uint32_t len,
                MimeDecParseState *state))
{
    int ret = MIME_DEC_OK;
    uint8_t *remainPtr, *tok;
    uint32_t tokLen;

    MimeDecParseState *state = MimeDecInitParser(data, dcpfunc);
    if (state == NULL) {
        SCLogDebug("Error: MimeDecInitParser() function failed to create "
                "state");
        return NULL;
    }

    MimeDecEntity *msg = state->msg;

    /* Parse each line one by one */
    remainPtr = (uint8_t *) buf;
    uint8_t *line = NULL;
    do {
        tok = GetLine(remainPtr, blen - (remainPtr - buf), &remainPtr, &tokLen);
        if (tok != remainPtr) {

            line = tok;

            if ((remainPtr - tok) - tokLen > UINT8_MAX) {
                SCLogDebug("Error: MimeDecParseLine() overflow: %ld", (remainPtr - tok) - tokLen);
                ret = MIME_DEC_ERR_OVERFLOW;
                break;
            }
            state->current_line_delimiter_len = (uint8_t)((remainPtr - tok) - tokLen);
            /* Parse the line */
            ret = MimeDecParseLine(line, tokLen, state->current_line_delimiter_len, state);
            if (ret != MIME_DEC_OK) {
                SCLogDebug("Error: MimeDecParseLine() function failed: %d",
                        ret);
                break;
            }
        }

    } while (tok != remainPtr && remainPtr - buf < (int)blen);

    if (ret == MIME_DEC_OK) {
        SCLogDebug("Message parser was successful");

        /* Now complete message */
        ret = MimeDecParseComplete(state);
        if (ret != MIME_DEC_OK) {
            SCLogDebug("Error: MimeDecParseComplete() function failed");
        }
    }

    /* De-allocate memory for parser */
    MimeDecDeInitParser(state);

    if (ret != MIME_DEC_OK) {
        MimeDecFreeEntity(msg);
        msg = NULL;
    }

    return msg;
}

#ifdef UNITTESTS

/* Helper body chunk callback function */
static int TestDataChunkCallback(const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state)
{
    uint32_t *line_count = (uint32_t *) state->data;

    if (state->body_begin) {
        SCLogDebug("Body begin (len=%u)", len);
    }

    /* Add up the line counts */
    if (len > 0) {

        uint8_t *remainPtr;
        uint8_t *tok;
        uint32_t tokLen;

        PrintChars(SC_LOG_DEBUG, "CHUNK", chunk, len);

        /* Parse each line one by one */
        remainPtr = (uint8_t *) chunk;
        do {
            tok = GetLine(remainPtr, len - (remainPtr - (uint8_t *) chunk),
                    &remainPtr, &tokLen);
            if (tok != NULL && tok != remainPtr) {
                (*line_count)++;
            }

        } while (tok != NULL && tok != remainPtr &&
                (uint32_t)(remainPtr - (uint8_t *) chunk) < len);

        SCLogDebug("line count (len=%u): %u", len, *line_count);
    }

    if (state->body_end) {
        SCLogDebug("Body end (len=%u)", len);
    }

    return MIME_DEC_OK;
}

/* Test simple case of line counts */
static int MimeDecParseLineTest01(void)
{
    uint32_t line_count = 0;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count,
            TestDataChunkCallback);

    const char *str = "From: Sender1\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "To: Recipient1\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "Content-Type: text/plain\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "A simple message line 1\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "A simple message line 2\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    str = "A simple message line 3\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 1, 1, state) == MIME_DEC_OK);

    /* Completed */
    FAIL_IF_NOT(MimeDecParseComplete(state) == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT_NULL(msg->next);
    FAIL_IF_NOT_NULL(msg->child);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    FAIL_IF_NOT(line_count == 3);
    PASS;
}

/* Test simple case of EXE URL extraction */
static int MimeDecParseLineTest02(void)
{
    uint32_t line_count = 0;

    ConfNode *url_schemes = ConfNodeNew();
    ConfNode *scheme = ConfNodeNew();
    FAIL_IF_NULL(url_schemes);
    FAIL_IF_NULL(scheme);

    url_schemes->is_seq = 1;
    scheme->val = SCStrdup("http://");
    FAIL_IF_NULL(scheme->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme, next);

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = url_schemes;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count,
            TestDataChunkCallback);

    const char *str = "From: Sender1\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    str = "To: Recipient1\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    str = "Content-Type: text/plain\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    str = "\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    str = "A simple message line 1\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    str = "A simple message line 2 click on http://www.test.com/malware.exe?"
          "hahah hopefully you click this link\r\n";
    FAIL_IF_NOT(MimeDecParseLine((uint8_t *)str, strlen(str) - 2, 2, state) == MIME_DEC_OK);

    /* Completed */
    FAIL_IF_NOT(MimeDecParseComplete(state) == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NULL(msg);
    FAIL_IF_NULL(msg->url_list);
    FAIL_IF_NOT((msg->url_list->url_flags & URL_IS_EXE));
    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);
    ConfNodeFree(url_schemes);
    MimeDecGetConfig()->extract_urls_schemes = NULL;

    FAIL_IF_NOT(line_count == 2);
    PASS;
}

/* Test error case where no url schemes set in config */
static int MimeFindUrlStringsTest01(void)
{
    int ret = MIME_DEC_OK;
    uint32_t line_count = 0;

    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = NULL;
    MimeDecGetConfig()->log_url_scheme = false;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);

    const char *str = "test";
    ret = FindUrlStrings((uint8_t *)str, strlen(str), state);
    /* Expected error since extract_url_schemes is NULL */
    FAIL_IF_NOT(ret == MIME_DEC_ERR_DATA);

    /* Completed */
    ret = MimeDecParseComplete(state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;
    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

/* Test simple case of URL extraction */
static int MimeFindUrlStringsTest02(void)
{
    int ret = MIME_DEC_OK;
    uint32_t line_count = 0;
    ConfNode *url_schemes = ConfNodeNew();
    ConfNode *scheme = ConfNodeNew();
    FAIL_IF_NULL(url_schemes);
    FAIL_IF_NULL(scheme);

    url_schemes->is_seq = 1;
    scheme->val = SCStrdup("http://");
    FAIL_IF_NULL(scheme->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme, next);

    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = url_schemes;
    MimeDecGetConfig()->log_url_scheme = false;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);

    const char *str = "A simple message click on "
                      "http://www.test.com/malware.exe? "
                      "hahah hopefully you click this link";
    ret = FindUrlStrings((uint8_t *)str, strlen(str), state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    /* Completed */
    ret = MimeDecParseComplete(state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;

    FAIL_IF(msg->url_list == NULL);

    FAIL_IF_NOT(msg->url_list->url_flags & URL_IS_EXE);
    FAIL_IF_NOT(
            memcmp("www.test.com/malware.exe?", msg->url_list->url, msg->url_list->url_len) == 0);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    ConfNodeFree(url_schemes);
    MimeDecGetConfig()->extract_urls_schemes = NULL;

    PASS;
}

/* Test URL extraction with multiple schemes and URLs */
static int MimeFindUrlStringsTest03(void)
{
    int ret = MIME_DEC_OK;
    uint32_t line_count = 0;
    ConfNode *url_schemes = ConfNodeNew();
    ConfNode *scheme1 = ConfNodeNew();
    ConfNode *scheme2 = ConfNodeNew();
    FAIL_IF_NULL(url_schemes);
    FAIL_IF_NULL(scheme1);
    FAIL_IF_NULL(scheme2);

    url_schemes->is_seq = 1;
    scheme1->val = SCStrdup("http://");
    FAIL_IF_NULL(scheme1->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme1, next);
    scheme2->val = SCStrdup("https://");
    FAIL_IF_NULL(scheme2->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme2, next);

    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = url_schemes;
    MimeDecGetConfig()->log_url_scheme = false;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);

    const char *str = "A simple message click on "
                      "http://www.test.com/malware.exe? "
                      "hahah hopefully you click this link, or "
                      "you can go to http://www.test.com/test/01.html and "
                      "https://www.test.com/test/02.php";
    ret = FindUrlStrings((uint8_t *)str, strlen(str), state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    /* Completed */
    ret = MimeDecParseComplete(state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;

    FAIL_IF(msg->url_list == NULL);

    MimeDecUrl *url = msg->url_list;
    FAIL_IF_NOT(memcmp("www.test.com/test/02.php", url->url, url->url_len) == 0);

    url = url->next;
    FAIL_IF_NOT(memcmp("www.test.com/test/01.html", url->url, url->url_len) == 0);

    url = url->next;
    FAIL_IF_NOT(memcmp("www.test.com/malware.exe?", url->url, url->url_len) == 0);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    ConfNodeFree(url_schemes);
    MimeDecGetConfig()->extract_urls_schemes = NULL;

    PASS;
}

/* Test URL extraction with multiple schemes and URLs with
 * log_url_scheme enabled in the MIME config */
static int MimeFindUrlStringsTest04(void)
{
    int ret = MIME_DEC_OK;
    uint32_t line_count = 0;
    ConfNode *url_schemes = ConfNodeNew();
    ConfNode *scheme1 = ConfNodeNew();
    ConfNode *scheme2 = ConfNodeNew();
    FAIL_IF_NULL(url_schemes);
    FAIL_IF_NULL(scheme1);
    FAIL_IF_NULL(scheme2);

    url_schemes->is_seq = 1;
    scheme1->val = SCStrdup("http://");
    FAIL_IF_NULL(scheme1->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme1, next);
    scheme2->val = SCStrdup("https://");
    FAIL_IF_NULL(scheme2->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme2, next);

    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = url_schemes;
    MimeDecGetConfig()->log_url_scheme = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);

    const char *str = "A simple message click on "
                      "http://www.test.com/malware.exe? "
                      "hahah hopefully you click this link, or "
                      "you can go to http://www.test.com/test/01.html and "
                      "https://www.test.com/test/02.php";
    ret = FindUrlStrings((uint8_t *)str, strlen(str), state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    /* Completed */
    ret = MimeDecParseComplete(state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;

    FAIL_IF(msg->url_list == NULL);

    MimeDecUrl *url = msg->url_list;
    FAIL_IF_NOT(memcmp("https://www.test.com/test/02.php", url->url, url->url_len) == 0);

    url = url->next;
    FAIL_IF_NOT(memcmp("http://www.test.com/test/01.html", url->url, url->url_len) == 0);

    url = url->next;
    FAIL_IF_NOT(memcmp("http://www.test.com/malware.exe?", url->url, url->url_len) == 0);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    ConfNodeFree(url_schemes);
    MimeDecGetConfig()->extract_urls_schemes = NULL;

    PASS;
}

/* Test URL extraction of IPV4 and IPV6 URLs with log_url_scheme
 * enabled in the MIME config */
static int MimeFindUrlStringsTest05(void)
{
    int ret = MIME_DEC_OK;
    uint32_t line_count = 0;
    ConfNode *url_schemes = ConfNodeNew();
    ConfNode *scheme = ConfNodeNew();
    FAIL_IF_NULL(url_schemes);
    FAIL_IF_NULL(scheme);

    url_schemes->is_seq = 1;
    scheme->val = SCStrdup("http://");
    FAIL_IF_NULL(scheme->val);
    TAILQ_INSERT_TAIL(&url_schemes->head, scheme, next);

    MimeDecGetConfig()->extract_urls = true;
    MimeDecGetConfig()->extract_urls_schemes = url_schemes;
    MimeDecGetConfig()->log_url_scheme = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);

    const char *str = "A simple message click on "
                      "http://192.168.1.1/test/01.html "
                      "hahah hopefully you click this link or this one "
                      "http://0:0:0:0:0:0:0:0/test/02.php";
    ret = FindUrlStrings((uint8_t *)str, strlen(str), state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    /* Completed */
    ret = MimeDecParseComplete(state);
    FAIL_IF_NOT(ret == MIME_DEC_OK);

    MimeDecEntity *msg = state->msg;

    FAIL_IF(msg->url_list == NULL);

    MimeDecUrl *url = msg->url_list;
    FAIL_IF_NOT(url->url_flags & URL_IS_IP6);
    FAIL_IF_NOT(memcmp("http://0:0:0:0:0:0:0:0/test/02.php", url->url, url->url_len) == 0);

    url = url->next;
    FAIL_IF_NOT(url->url_flags & URL_IS_IP4);
    FAIL_IF_NOT(memcmp("http://192.168.1.1/test/01.html", url->url, url->url_len) == 0);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    ConfNodeFree(url_schemes);
    MimeDecGetConfig()->extract_urls_schemes = NULL;

    PASS;
}

/* Test full message with linebreaks */
static int MimeDecParseFullMsgTest01(void)
{
    uint32_t expected_count = 3;
    uint32_t line_count = 0;

    char msg[] = "From: Sender1\r\n"
            "To: Recipient1\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Line 1\r\n"
            "Line 2\r\n"
            "Line 3\r\n";

    MimeDecEntity *entity = MimeDecParseFullMsg((uint8_t *)msg, strlen(msg), &line_count,
            TestDataChunkCallback);
    if (entity == NULL) {
        SCLogInfo("Warning: Message failed to parse");
        return 0;
    }

    MimeDecFreeEntity(entity);

    if (expected_count != line_count) {
        SCLogInfo("Warning: Line count is invalid: expected - %d actual - %d",
                expected_count, line_count);
        return 0;
    }

    return 1;
}

/* Test full message with linebreaks */
static int MimeDecParseFullMsgTest02(void)
{
    uint32_t expected_count = 3;
    uint32_t line_count = 0;

    char msg[] = "From: Sender2\r\n"
            "To: Recipient2\r\n"
            "Subject: subject2\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Line 1\r\n"
            "Line 2\r\n"
            "Line 3\r\n";

    MimeDecEntity *entity = MimeDecParseFullMsg((uint8_t *)msg, strlen(msg), &line_count,
            TestDataChunkCallback);

    if (entity == NULL) {
        SCLogInfo("Warning: Message failed to parse");
        return 0;
    }

    MimeDecField *field = MimeDecFindField(entity, "subject");
    if (field == NULL) {
        SCLogInfo("Warning: Message failed to parse");
        return 0;
    }

    if (field->value_len != sizeof("subject2") - 1) {
        SCLogInfo("Warning: failed to get subject");
        return 0;
    }

    if (memcmp(field->value, "subject2", field->value_len) != 0) {
        SCLogInfo("Warning: failed to get subject");
        return 0;
    }


    MimeDecFreeEntity(entity);

    if (expected_count != line_count) {
        SCLogInfo("Warning: Line count is invalid: expected - %d actual - %d", expected_count,
                line_count);
        return 0;
    }

    return 1;
}

static int MimeBase64DecodeTest01(void)
{
    int ret = 0;
    uint32_t consumed_bytes = 0, num_decoded = 0;

    const char *msg = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@"
            "#$%^&*()-=_+,./;'[]<>?:";
    const char *base64msg = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QU"
            "VJTVFVWV1hZWjEyMzQ1Njc4OTBAIyQlXiYqKCktPV8rLC4vOydbXTw+Pzo=";

    uint8_t *dst = SCMalloc(strlen(msg) + 1);
    if (dst == NULL)
        return 0;

    ret = DecodeBase64(dst, strlen(msg) + 1, (const uint8_t *)base64msg, strlen(base64msg),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);

    if (memcmp(dst, msg, strlen(msg)) == 0) {
        ret = 1;
    }

    SCFree(dst);

    return ret;
}

static int MimeIsExeURLTest01(void)
{
    int ret = 0;
    const char *url1 = "http://www.google.com/";
    const char *url2 = "http://www.google.com/test.exe";

    if(IsExeUrl((const uint8_t *)url1, strlen(url1)) != 0){
        SCLogDebug("Debug: URL1 error");
        goto end;
    }
    if(IsExeUrl((const uint8_t *)url2, strlen(url2)) != 1){
        SCLogDebug("Debug: URL2 error");
        goto end;
    }
    ret = 1;

    end:

    return ret;
}

#define TEST(str, len, expect) {                        \
    SCLogDebug("str %s", (str));                        \
    int r = IsIpv4Host((const uint8_t *)(str),(len));   \
    FAIL_IF_NOT(r == (expect));                         \
}
static int MimeIsIpv4HostTest01(void)
{
    TEST("192.168.1.1", 11, 1);
    TEST("192.168.1.1.4", 13, 0);
    TEST("999.168.1.1", 11, 0);
    TEST("1111.168.1.1", 12, 0);
    TEST("999.oogle.com", 14, 0);
    TEST("0:0:0:0:0:0:0:0", 15, 0);
    TEST("192.168.255.255", 15, 1);
    TEST("192.168.255.255/testurl.html", 28, 1);
    TEST("www.google.com", 14, 0);
    PASS;
}
#undef TEST

#define TEST(str, len, expect) {                        \
    SCLogDebug("str %s", (str));                        \
    int r = IsIpv6Host((const uint8_t *)(str),(len));   \
    FAIL_IF_NOT(r == (expect));                         \
}
static int MimeIsIpv6HostTest01(void)
{
    TEST("0:0:0:0:0:0:0:0", 19, 1);
    TEST("0000:0000:0000:0000:0000:0000:0000:0000", 39, 1);
    TEST("XXXX:0000:0000:0000:0000:0000:0000:0000", 39, 0);
    TEST("00001:0000:0000:0000:0000:0000:0000:0000", 40, 0);
    TEST("0:0:0:0:0:0:0:0", 19, 1);
    TEST("0:0:0:0:0:0:0:0:0", 20, 0);
    TEST("192:168:1:1:0:0:0:0", 19, 1);
    TEST("999.oogle.com", 14, 0);
    TEST("192.168.255.255", 15, 0);
    TEST("192.168.255.255/testurl.html", 28, 0);
    TEST("www.google.com", 14, 0);
    PASS;
}
#undef TEST

static int MimeDecParseLongFilename01(void)
{
    /* contains 276 character filename -- length restricted to 255 chars */
    char mimemsg[] = "Content-Disposition: attachment; filename=\""
                     "12characters12characters12characters12characters"
                     "12characters12characters12characters12characters"
                     "12characters12characters12characters12characters"
                     "12characters12characters12characters12characters"
                     "12characters12characters12characters12characters"
                     "12characters12characters12characters.exe\"";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count,
            TestDataChunkCallback);

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Contains 276 character filename */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "A simple message line 1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    FAIL_IF_NOT(msg->anomaly_flags & ANOM_LONG_FILENAME);
    FAIL_IF_NOT(msg->filename_len == RS_MIME_MAX_TOKEN_LEN);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

static int MimeDecParseSmallRemInp(void)
{
    // Remainder dA
    // New input: AAAA
    char mimemsg[] = "TWltZSBkZWNvZGluZyB pcyBzbyBO T1QgZnV uISBJIGNhbm5vdA";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);
    state->stack->top->data->ctnt_flags |= CTNT_IS_ATTACHMENT;

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Transfer-Encoding: base64";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));

    str = "AAAA";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    /* filename is not too long */
    FAIL_IF(msg->anomaly_flags & ANOM_LONG_FILENAME);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

static int MimeDecParseRemSp(void)
{
    // Should have remainder vd A
    char mimemsg[] = "TWltZSBkZWNvZGluZyBpc yBzbyBOT1QgZnVuISBJIGNhbm5vd A";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);
    state->stack->top->data->ctnt_flags |= CTNT_IS_ATTACHMENT;

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Transfer-Encoding: base64";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));
    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    /* filename is not too long */
    FAIL_IF(msg->anomaly_flags & ANOM_LONG_FILENAME);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

static int MimeDecVerySmallInp(void)
{
    // Remainder: A
    // New input: aA
    char mimemsg[] = "TWltZSBkZWNvZGluZyB pcyBzbyBO T1QgZnV uISBJIGNhbm5vA";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);
    state->stack->top->data->ctnt_flags |= CTNT_IS_ATTACHMENT;

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Transfer-Encoding: base64";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));

    str = "aA";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    /* filename is not too long */
    FAIL_IF(msg->anomaly_flags & ANOM_LONG_FILENAME);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

static int MimeDecParseOddLen(void)
{
    char mimemsg[] = "TWltZSBkZWNvZGluZyB pcyBzbyBO T1QgZnV uISBJIGNhbm5vdA";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count, TestDataChunkCallback);
    state->stack->top->data->ctnt_flags |= CTNT_IS_ATTACHMENT;

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Transfer-Encoding: base64";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));
    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    /* filename is not too long */
    FAIL_IF(msg->anomaly_flags & ANOM_LONG_FILENAME);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

static int MimeDecParseLongFilename02(void)
{
    /* contains 40 character filename and 500+ characters following filename */
    char mimemsg[] = "Content-Disposition: attachment; filename=\""
                     "12characters12characters12characters.exe\"; "
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd"
                     "somejunkasfdasfsafasafdsasdasassdssdsd";

    uint32_t line_count = 0;

    MimeDecGetConfig()->decode_base64 = true;
    MimeDecGetConfig()->decode_quoted_printable = true;
    MimeDecGetConfig()->extract_urls = true;

    /* Init parser */
    MimeDecParseState *state = MimeDecInitParser(&line_count,
            TestDataChunkCallback);

    const char *str = "From: Sender1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "To: Recipient1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "Content-Type: text/plain";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Contains 40 character filename */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)mimemsg, strlen(mimemsg), 1, state));

    str = "";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    str = "A simple message line 1";
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseLine((uint8_t *)str, strlen(str), 1, state));

    /* Completed */
    FAIL_IF_NOT(MIME_DEC_OK == MimeDecParseComplete(state));

    MimeDecEntity *msg = state->msg;
    FAIL_IF_NOT(msg);

    /* filename is not too long */
    FAIL_IF(msg->anomaly_flags & ANOM_LONG_FILENAME);

    MimeDecFreeEntity(msg);

    /* De Init parser */
    MimeDecDeInitParser(state);

    PASS;
}

#endif /* UNITTESTS */

void MimeDecRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MimeDecParseLineTest01", MimeDecParseLineTest01);
    UtRegisterTest("MimeDecParseLineTest02", MimeDecParseLineTest02);
    UtRegisterTest("MimeFindUrlStringsTest01", MimeFindUrlStringsTest01);
    UtRegisterTest("MimeFindUrlStringsTest02", MimeFindUrlStringsTest02);
    UtRegisterTest("MimeFindUrlStringsTest03", MimeFindUrlStringsTest03);
    UtRegisterTest("MimeFindUrlStringsTest04", MimeFindUrlStringsTest04);
    UtRegisterTest("MimeFindUrlStringsTest05", MimeFindUrlStringsTest05);
    UtRegisterTest("MimeDecParseFullMsgTest01", MimeDecParseFullMsgTest01);
    UtRegisterTest("MimeDecParseFullMsgTest02", MimeDecParseFullMsgTest02);
    UtRegisterTest("MimeBase64DecodeTest01", MimeBase64DecodeTest01);
    UtRegisterTest("MimeIsExeURLTest01", MimeIsExeURLTest01);
    UtRegisterTest("MimeIsIpv4HostTest01", MimeIsIpv4HostTest01);
    UtRegisterTest("MimeIsIpv6HostTest01", MimeIsIpv6HostTest01);
    UtRegisterTest("MimeDecParseLongFilename01", MimeDecParseLongFilename01);
    UtRegisterTest("MimeDecParseLongFilename02", MimeDecParseLongFilename02);
    UtRegisterTest("MimeDecParseSmallRemInp", MimeDecParseSmallRemInp);
    UtRegisterTest("MimeDecParseRemSp", MimeDecParseRemSp);
    UtRegisterTest("MimeDecVerySmallInp", MimeDecVerySmallInp);
    UtRegisterTest("MimeDecParseOddLen", MimeDecParseOddLen);
#endif /* UNITTESTS */
}
