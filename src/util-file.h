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
 */

#ifndef __UTIL_FILE_H__
#define __UTIL_FILE_H__

#ifdef HAVE_NSS
#include <sechash.h>
#endif

#define FILE_TRUNCATED  0x0001
#define FILE_NOMAGIC    0x0002
#define FILE_NOMD5      0x0004
#define FILE_MD5        0x0008
#define FILE_LOGGED     0x0010
#define FILE_NOSTORE    0x0020
#define FILE_STORE      0x0040
#define FILE_STORED     0x0080
#define FILE_NOTRACK    0x0100 /**< track size of file */

typedef enum FileState_ {
    FILE_STATE_NONE = 0,    /**< no state */
    FILE_STATE_OPENED,      /**< flow file is opened */
    FILE_STATE_CLOSED,      /**< flow file is completed,
                                     there will be no more data. */
    FILE_STATE_TRUNCATED,   /**< flow file is not complete, but
                                     there will be no more data. */
    FILE_STATE_ERROR,       /**< file is in an error state */
    FILE_STATE_MAX
} FileState;

typedef struct FileData_ {
    uint8_t *data;
    uint32_t len;
    uint64_t stream_offset;
    int stored;     /* true if this chunk has been stored already
                     * false otherwise */
    struct FileData_ *next;
} FileData;

typedef struct File_ {
    uint16_t flags;
    uint64_t txid;                  /**< tx this file is part of */
    unsigned int file_id;
    uint8_t *name;
    uint16_t name_len;
    int16_t state;
    uint64_t size;                  /**< size tracked so far */
    char *magic;
    FileData *chunks_head;
    FileData *chunks_tail;
    struct File_ *next;
#ifdef HAVE_NSS
    HASHContext *md5_ctx;
    uint8_t md5[MD5_LENGTH];
#endif
#ifdef DEBUG
    uint64_t chunks_cnt;
    uint64_t chunks_cnt_max;
#endif
    uint64_t content_len_so_far;
    uint64_t content_inspected;
} File;

typedef struct FileContainer_ {
    File *head;
    File *tail;
} FileContainer;

FileContainer *FileContainerAlloc();
void FileContainerFree(FileContainer *);

void FileContainerRecycle(FileContainer *);

void FileContainerAdd(FileContainer *, File *);

/**
 *  \brief Open a new File
 *
 *  \param ffc flow container
 *  \param name filename character array
 *  \param name_len filename len
 *  \param data initial data
 *  \param data_len initial data len
 *  \param flags open flags
 *
 *  \retval ff flowfile object
 *
 *  \note filename is not a string, so it's not nul terminated.
 */
File *FileOpenFile(FileContainer *, uint8_t *name, uint16_t name_len,
        uint8_t *data, uint32_t data_len, uint8_t flags);
/**
 *  \brief Close a File
 *
 *  \param ffc the container
 *  \param data final data if any
 *  \param data_len data len if any
 *  \param flags flags
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FileCloseFile(FileContainer *, uint8_t *data, uint32_t data_len, uint8_t flags);

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
int FileAppendData(FileContainer *, uint8_t *data, uint32_t data_len);

/**
 *  \brief Tag a file for storing
 *
 *  \param ff The file to store
 */
int FileStore(File *);

/**
 *  \brief Set the TX id for a file
 *
 *  \param ff The file to store
 *  \param txid the tx id
 */
int FileSetTx(File *, uint64_t txid);

/**
 *  \brief disable file storage for a flow
 *
 *  \param f *LOCKED* flow
 */
void FileDisableStoring(struct Flow_ *, uint8_t);

void FileDisableFilesize(Flow *f, uint8_t direction);

/**
 *  \brief disable file storing for a transaction
 *
 *  \param f flow
 *  \param tx_id transaction id
 */
void FileDisableStoringForTransaction(Flow *f, uint8_t direction, uint64_t tx_id);

void FlowFileDisableStoringForTransaction(struct Flow_ *f, uint16_t tx_id);
void FilePrune(FileContainer *ffc);


void FileDisableMagic(Flow *f, uint8_t);
void FileForceMagicEnable(void);
int FileForceMagic(void);

void FileDisableMd5(Flow *f, uint8_t);
void FileForceMd5Enable(void);
int FileForceMd5(void);

void FileForceTrackingEnable(void);

void FileStoreAllFiles(FileContainer *);
void FileStoreAllFilesForTx(FileContainer *, uint16_t);
void FileStoreFileById(FileContainer *fc, uint16_t);

void FileTruncateAllOpenFiles(FileContainer *);

#endif /* __UTIL_FILE_H__ */
