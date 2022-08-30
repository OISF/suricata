/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Functions used to generate JA3 fingerprint.
 */

#include "suricata-common.h"
#include "app-layer-ssl.h"
#include "util-validate.h"
#include "util-ja3.h"

#define MD5_STRING_LENGTH 33

/**
 * \brief Allocate new buffer.
 *
 * \return pointer to buffer on success.
 * \return NULL on failure.
 */
JA3Buffer *Ja3BufferInit(void)
{
    JA3Buffer *buffer = SCCalloc(1, sizeof(JA3Buffer));
    if (buffer == NULL) {
        return NULL;
    }

    return buffer;
}

/**
 * \brief Free allocated buffer.
 *
 * \param buffer The buffer to free.
 */
void Ja3BufferFree(JA3Buffer **buffer)
{
    DEBUG_VALIDATE_BUG_ON(*buffer == NULL);

    if ((*buffer)->data != NULL) {
        SCFree((*buffer)->data);
        (*buffer)->data = NULL;
    }

    SCFree(*buffer);
    *buffer = NULL;
}

/**
 * \internal
 * \brief Resize buffer if it is full.
 *
 * \param buffer The buffer.
 * \param len    The length of the data that should fit into the buffer.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
static int Ja3BufferResizeIfFull(JA3Buffer *buffer, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(buffer == NULL);

    while (buffer->used + len + 2 > buffer->size)
    {
        buffer->size *= 2;
        char *tmp = SCRealloc(buffer->data, buffer->size * sizeof(char));
        if (tmp == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error resizing JA3 buffer");
            return -1;
        }
        buffer->data = tmp;
    }

    return 0;
}

/**
 * \brief Append buffer to buffer.
 *
 * Append the second buffer to the first and then free it.
 *
 * \param buffer1 The first buffer.
 * \param buffer2 The second buffer.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int Ja3BufferAppendBuffer(JA3Buffer **buffer1, JA3Buffer **buffer2)
{
    if (*buffer1 == NULL || *buffer2 == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Buffers should not be NULL");
        return -1;
    }

    /* If buffer1 contains no data, then we just copy the second buffer
       instead of appending its data. */
    if ((*buffer1)->data == NULL) {
        (*buffer1)->data = (*buffer2)->data;
        (*buffer1)->used = (*buffer2)->used;
        (*buffer1)->size = (*buffer2)->size;
        SCFree(*buffer2);
        return 0;
    }

    int rc = Ja3BufferResizeIfFull(*buffer1, (*buffer2)->used);
    if (rc != 0) {
        Ja3BufferFree(buffer1);
        Ja3BufferFree(buffer2);
        return -1;
    }

    if ((*buffer2)->used == 0) {
        (*buffer1)->used += snprintf((*buffer1)->data + (*buffer1)->used,
                                     (*buffer1)->size - (*buffer1)->used, ",");
    } else {
        (*buffer1)->used += snprintf((*buffer1)->data + (*buffer1)->used,
                                     (*buffer1)->size - (*buffer1)->used, ",%s",
                                     (*buffer2)->data);
    }

    Ja3BufferFree(buffer2);

    return 0;
}

/**
 * \internal
 * \brief Return number of digits in number.
 *
 * \param num The number.
 *
 * \return digits Number of digits.
 */
static uint32_t NumberOfDigits(uint32_t num)
{
    if (num < 10) {
        return 1;
    }

    return 1 + NumberOfDigits(num / 10);
}

/**
 * \brief Add value to buffer.
 *
 * \param buffer The buffer.
 * \param value  The value.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int Ja3BufferAddValue(JA3Buffer **buffer, uint32_t value)
{
    if (*buffer == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Buffer should not be NULL");
        return -1;
    }

    if ((*buffer)->data == NULL) {
        (*buffer)->data = SCMalloc(JA3_BUFFER_INITIAL_SIZE * sizeof(char));
        if ((*buffer)->data == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC,
                       "Error allocating memory for JA3 data");
            Ja3BufferFree(buffer);
            return -1;
        }
        (*buffer)->size = JA3_BUFFER_INITIAL_SIZE;
    }

    uint32_t value_len = NumberOfDigits(value);

    int rc = Ja3BufferResizeIfFull(*buffer, value_len);
    if (rc != 0) {
        Ja3BufferFree(buffer);
        return -1;
    }

    if ((*buffer)->used == 0) {
        (*buffer)->used += snprintf((*buffer)->data, (*buffer)->size, "%u", value);
    }
    else {
        (*buffer)->used += snprintf(
                (*buffer)->data + (*buffer)->used, (*buffer)->size - (*buffer)->used, "-%u", value);
    }

    return 0;
}

/**
 * \brief Generate Ja3 hash string.
 *
 * \param buffer The Ja3 buffer.
 *
 * \retval pointer to hash string on success.
 * \retval NULL on failure.
 */
char *Ja3GenerateHash(JA3Buffer *buffer)
{
    if (buffer == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Buffer should not be NULL");
        return NULL;
    }

    if (buffer->data == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Buffer data should not be NULL");
        return NULL;
    }

    char *ja3_hash = SCMalloc(MD5_STRING_LENGTH * sizeof(char));
    if (ja3_hash == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "Error allocating memory for JA3 hash");
        return NULL;
    }

    SCMd5HashBufferToHex((unsigned char *)buffer->data, buffer->used, ja3_hash,
            MD5_STRING_LENGTH * sizeof(char));
    return ja3_hash;
}

/**
 * \brief Check if JA3 is disabled.
 *
 * Issue warning if JA3 is disabled or if we are lacking support for JA3.
 *
 * \param type Type to add to warning.
 *
 * \retval 1 if disabled.
 * \retval 0 otherwise.
 */
int Ja3IsDisabled(const char *type)
{
    bool is_enabled = SSLJA3IsEnabled();
    if (is_enabled == 0) {
        if (strcmp(type, "rule") != 0) {
            SCLogWarning(SC_WARN_JA3_DISABLED, "JA3 is disabled, skipping %s",
                    type);
        }
        return 1;
    }

    return 0;
}
