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

#include "conf.h"

#include "util-streaming-buffer.h"

/* Hack: Pulling rust.h to get the SCSha256 causes all sorts of problems with
 *   header include orders, which is something we'll have to resolve as we provide
 *   more functionality via Rust. But this lets me continue with replacing nss
 *   without fighting the headers at this time. */
typedef struct SCSha256 SCSha256;
#define SC_SHA256_LEN 32

typedef struct SCSha1 SCSha1;
#define SC_SHA1_LEN 20

typedef struct SCMd5 SCMd5;
#define SC_MD5_LEN 16

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
#define FILE_HAS_GAPS   BIT_U16(15)

// to be used instead of PATH_MAX which depends on the OS
#define SC_FILENAME_MAX 4096

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
    FileState state;
    StreamingBuffer *sb;
    uint64_t txid;                  /**< tx this file is part of */
    uint32_t file_track_id;         /**< id used by protocol parser */
    uint32_t file_store_id;         /**< id used in store file name file.<id> */
    int fd;                         /**< file descriptor for filestore, not
                                        open if equal to -1 */
    uint8_t *name;
#ifdef HAVE_MAGIC
    char *magic;
#endif
    struct File_ *next;
    SCMd5 *md5_ctx;
    uint8_t md5[SC_MD5_LEN];
    SCSha1 *sha1_ctx;
    uint8_t sha1[SC_SHA1_LEN];
    SCSha256 *sha256_ctx;
    uint8_t sha256[SC_SHA256_LEN];
    uint64_t content_inspected;     /**< used in pruning if FILE_USE_DETECT
                                     *   flag is set */
    uint64_t content_stored;
    uint64_t size;
    uint32_t inspect_window;
    uint32_t inspect_min_size;
    uint64_t start;
    uint64_t end;

    uint32_t *sid; /* signature id of a rule that triggered the filestore event */
    uint32_t sid_cnt;
    uint32_t sid_max;
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
int FileOpenFileWithId(FileContainer *, const StreamingBufferConfig *,
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
int FileCloseFilePtr(File *ff, const uint8_t *data,
        uint32_t data_len, uint16_t flags);

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

void FileSetInspectSizes(File *file, const uint32_t win, const uint32_t min);

/**
 *  \brief Sets the offset range for a file.
 *
 *  \param ffc the container
 *  \param start start offset
 *  \param end end offset
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FileSetRange(FileContainer *, uint64_t start, uint64_t end);

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

void FileForceMagicEnable(void);
int FileForceMagic(void);

void FileForceMd5Enable(void);
int FileForceMd5(void);

void FileForceSha1Enable(void);
int FileForceSha1(void);

void FileForceSha256Enable(void);
int FileForceSha256(void);

void FileUpdateFlowFileFlags(Flow *f, uint16_t set_file_flags, uint8_t direction);

void FileForceHashParseCfg(ConfNode *);

void FileForceTrackingEnable(void);

void FileStoreAllFiles(FileContainer *);
void FileStoreAllFilesForTx(FileContainer *, uint64_t);
void FileStoreFileById(FileContainer *fc, uint32_t);

void FileTruncateAllOpenFiles(FileContainer *);

uint64_t FileDataSize(const File *file);
uint64_t FileTrackedSize(const File *file);

uint16_t FileFlowFlagsToFlags(const uint16_t flow_file_flags, uint8_t direction);
uint16_t FileFlowToFlags(const Flow *flow, uint8_t direction);

void FilePrintFlags(const File *file);

#endif /* __UTIL_FILE_H__ */
