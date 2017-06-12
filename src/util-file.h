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

#include "conf.h"

#include "util-streaming-buffer.h"

#define FILE_TRUNCATED  BIT_U16(0)
#define FILE_NOMAGIC    BIT_U16(1)
#define FILE_NOMD5      BIT_U16(2)
#define FILE_MD5        BIT_U16(3)
#define FILE_NOSHA1     BIT_U16(4)
#define FILE_SHA1       BIT_U16(5)
#define FILE_NOSHA256   BIT_U16(6)
#define FILE_SHA256     BIT_U16(7)
#define FILE_LOGGED     BIT_U16(8)
#define FILE_NOSTORE    BIT_U16(9)
#define FILE_STORE      BIT_U16(10)
#define FILE_STORED     BIT_U16(11)
#define FILE_NOTRACK    BIT_U16(12) /**< track size of file */
#define FILE_USE_DETECT BIT_U16(13) /**< use content_inspected tracker */
#define FILE_USE_TRACKID    BIT_U16(14) /**< File::file_track_id field is in use */
#define FILE_HAS_GAPS   BIT_U16(15)

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

typedef struct File_ {
    uint16_t flags;
    uint16_t name_len;
    int16_t state;
    StreamingBuffer *sb;
    uint64_t txid;                  /**< tx this file is part of */
    uint32_t file_track_id;         /**< id used by protocol parser. Optional
                                     *   only used if FILE_USE_TRACKID flag set */
    uint32_t file_store_id;         /**< id used in store file name file.<id> */
    int fd;                         /**< file descriptor for filestore, not
                                        open if equal to -1 */
    uint8_t *name;
#ifdef HAVE_MAGIC
    char *magic;
#endif
    struct File_ *next;
#ifdef HAVE_NSS
    HASHContext *md5_ctx;
    uint8_t md5[MD5_LENGTH];
    HASHContext *sha1_ctx;
    uint8_t sha1[SHA1_LENGTH];
    HASHContext *sha256_ctx;
    uint8_t sha256[SHA256_LENGTH];
#endif
    uint64_t content_inspected;     /**< used in pruning if FILE_USE_DETECT
                                     *   flag is set */
    uint64_t content_stored;
    uint64_t size;
} File;

typedef struct FileContainer_ {
    File *head;
    File *tail;
} FileContainer;

FileContainer *FileContainerAlloc(void);
void FileContainerFree(FileContainer *);

void FileContainerRecycle(FileContainer *);

void FileContainerAdd(FileContainer *, File *);

/**
 *  \brief Open a new File
 *
 *  \param ffc flow container
 *  \param sbcfg buffer config
 *  \param name filename character array
 *  \param name_len filename len
 *  \param data initial data
 *  \param data_len initial data len
 *  \param flags open flags
 *
 *  \retval ff flowfile object
 *
 *  \note filename is not a string, so it's not nul terminated.
 *
 *  If flags contains the FILE_USE_DETECT bit, the pruning code will
 *  consider not just the content_stored tracker, but also content_inspected.
 *  It's the responsibility of the API user to make sure this tracker is
 *  properly updated.
 */
File *FileOpenFile(FileContainer *, const StreamingBufferConfig *,
        const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags);
File *FileOpenFileWithId(FileContainer *, const StreamingBufferConfig *,
        uint32_t track_id, const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags);

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
int FileCloseFile(FileContainer *, const uint8_t *data, uint32_t data_len,
        uint16_t flags);
int FileCloseFileById(FileContainer *, uint32_t track_id,
        const uint8_t *data, uint32_t data_len, uint16_t flags);

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
int FileAppendData(FileContainer *, const uint8_t *data, uint32_t data_len);
int FileAppendDataById(FileContainer *, uint32_t track_id,
        const uint8_t *data, uint32_t data_len);
int FileAppendGAPById(FileContainer *ffc, uint32_t track_id,
        const uint8_t *data, uint32_t data_len);

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
void FileContainerSetTx(FileContainer *ffc, uint64_t tx_id);

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

void FlowFileDisableStoringForTransaction(struct Flow_ *f, uint64_t tx_id);
void FilePrune(FileContainer *ffc);

void FileForceFilestoreEnable(void);
int FileForceFilestore(void);
void FileReassemblyDepthEnable(uint32_t size);
uint32_t FileReassemblyDepth(void);

void FileDisableMagic(Flow *f, uint8_t);
void FileForceMagicEnable(void);
int FileForceMagic(void);

void FileDisableMd5(Flow *f, uint8_t);
void FileForceMd5Enable(void);
int FileForceMd5(void);

void FileDisableSha1(Flow *f, uint8_t);
void FileForceSha1Enable(void);
int FileForceSha1(void);

void FileDisableSha256(Flow *f, uint8_t);
void FileForceSha256Enable(void);
int FileForceSha256(void);

void FileForceHashParseCfg(ConfNode *);

void FileForceTrackingEnable(void);

void FileStoreAllFiles(FileContainer *);
void FileStoreAllFilesForTx(FileContainer *, uint64_t);
void FileStoreFileById(FileContainer *fc, uint32_t);

void FileTruncateAllOpenFiles(FileContainer *);

uint64_t FileDataSize(const File *file);
uint64_t FileTrackedSize(const File *file);

uint16_t FileFlowToFlags(const Flow *flow, uint8_t direction);

#endif /* __UTIL_FILE_H__ */
