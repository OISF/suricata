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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#ifndef __FLOW_FILE_H__
#define __FLOW_FILE_H__

#include "flow.h"
#include "util-hash.h"

#define FLOW_FILE_TRUNCATED 0x01
#define FLOW_FILE_NOSTORE   0x02

typedef enum FlowFileState_ {
    FLOWFILE_STATE_NONE = 0,    /**< no state */
    FLOWFILE_STATE_OPENED,      /**< flow file is opened */
    FLOWFILE_STATE_CLOSED,      /**< flow file is completed,
                                     there will be no more data. */
    FLOWFILE_STATE_TRUNCATED,   /**< flow file is not complete, but
                                     there will be no more data. */
    FLOWFILE_STATE_STORED,      /**< all fully written to disk */
    FLOWFILE_STATE_ERROR,       /**< file is in an error state */
    FLOWFILE_STATE_MAX
} FlowFileState;

typedef struct FlowFileData_ {
    uint8_t *data;
    uint32_t len;
    int stored;     /* true if this chunk has been stored already
                     * false otherwise */
    struct FlowFileData_ *next;
} FlowFileData;

typedef struct FlowFile_ {
    int16_t store;                  /**< need storing? 0: no, 1: yes, -1: won't */
    uint16_t txid;                  /**< tx this file is part of */
    uint8_t *name;
    uint16_t name_len;
    int16_t state;
    int fd;                         /**< file discriptor for storing files */
    const char *magic;
    FlowFileData *chunks_head;
    FlowFileData *chunks_tail;
    struct FlowFile_ *next;
} FlowFile;

typedef struct FlowFileContainer_ {
    FlowFile *head;
    FlowFile *tail;
} FlowFileContainer;

FlowFileContainer *FlowFileContainerAlloc();
void FlowFileContainerFree(FlowFileContainer *);

void FlowFileContainerRecycle(FlowFileContainer *);

void FlowFileContainerAdd(FlowFileContainer *, FlowFile *);

/**
 *  \brief Open a new FlowFile
 *
 *  \param ffc flow container
 *  \param name filename character array
 *  \param name_len filename len
 *  \param data initial data
 *  \param data_len initial data len
 *
 *  \retval ff flowfile object
 *
 *  \note filename is not a string, so it's not nul terminated.
 */
FlowFile *FlowFileOpenFile(FlowFileContainer *, uint8_t *name, uint16_t name_len,
        uint8_t *data, uint32_t data_len);
/**
 *  \brief Close a FlowFile
 *
 *  \param ffc the container
 *  \param data final data if any
 *  \param data_len data len if any
 *  \param flags flags
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FlowFileCloseFile(FlowFileContainer *, uint8_t *data, uint32_t data_len, uint8_t flags);

/**
 *  \brief Store a chunk of file data in the flow. The open "flowfile"
 *         will be used.
 *
 *  \param ffc the container
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FlowFileAppendData(FlowFileContainer *, uint8_t *data, uint32_t data_len);

/**
 *  \brief Tag a file for storing
 *
 *  \param ff The file to store
 */
int FlowFileStore(FlowFile *);

/**
 *  \brief Set the TX id for a file
 *
 *  \param ff The file to store
 *  \param txid the tx id
 */
int FlowFileSetTx(FlowFile *, uint16_t txid);

/**
 *  \brief disable file storage for a flow
 *
 *  \param f *LOCKED* flow
 */
void FlowFileDisableStoring(struct Flow_ *);

/**
 *  \brief disable file storing for a transaction
 *
 *  \param f flow
 *  \param tx_id transaction id
 */
void FlowFileDisableStoringForTransaction(struct Flow_ *, uint16_t);

#endif /* __FLOW_FILE_H__ */
