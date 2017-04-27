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
 * \author Victor Julien <victor@inliniac.net>
 *
 * File based pcap packet acquisition support
 */

#include "pcap-directory-helper.h"
#include "runmode-unix-socket.h"
#include "util-mem.h"

static void CopyTime(struct timespec *from, struct timespec *to);
static int CompareTimes(struct timespec *left, struct timespec *right);
static TmEcode PcapRunStatus(PcapFileDirectoryVars *);
static TmEcode PcapDirectoryFailure(PcapFileDirectoryVars *ptv);
static TmEcode PcapDirectoryDone(PcapFileDirectoryVars *ptv);
static int PcapDirectoryGetModifiedTime(char const * file, struct timespec * out);
static TmEcode PcapDirectoryInsertFile(PcapFileDirectoryVars *pv,
                                       PendingFile *file_to_add,
                                       struct timespec *file_to_add_modified_time);
static TmEcode PcapDirectoryPopulateBuffer(PcapFileDirectoryVars *ptv,
                                           struct timespec * newer_than,
                                           struct timespec * older_than);
static TmEcode PcapDirectoryDispatchForTimeRange(PcapFileDirectoryVars *pv,
                                                 struct timespec *newer_than,
                                                 struct timespec *older_than);

void CopyTime(struct timespec *from, struct timespec *to) {
    to->tv_sec = from->tv_sec;
    to->tv_nsec = from->tv_nsec;
}

int CompareTimes(struct timespec *left, struct timespec *right) {
    if (left->tv_sec < right->tv_sec) {
        return -1;
    } else if (left->tv_sec > right->tv_sec) {
        return 1;
    } else {
        if (left->tv_nsec < right->tv_nsec) {
            return -1;
        } else if (left->tv_nsec > right->tv_nsec) {
            return 1;
        } else {
            return 0;
        }
    }
}

/**
 * Pcap Folder Utilities
 */
TmEcode PcapRunStatus(PcapFileDirectoryVars *ptv)
{
    if (RunModeUnixSocketIsActive()) {
        TmEcode done = UnixSocketPcapFile(TM_ECODE_OK, &ptv->shared->last_processed);
        if ( (suricata_ctl_flags & SURICATA_STOP) || done != TM_ECODE_OK) {
            SCReturnInt(TM_ECODE_DONE);
        }
    } else {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_DONE);
        }
    }
    SCReturnInt(TM_ECODE_OK);
}

void CleanupPendingFile(PendingFile *pending) {
    if (pending != NULL) {
        if (pending->filename != NULL) {
            SCFree(pending->filename);
        }
        SCFree(pending);
    }
}

void CleanupPcapFileDirectoryVars(PcapFileDirectoryVars *ptv)
{
    if (ptv != NULL) {
        if (ptv->current_file != NULL) {
            CleanupPcapFileFileVars(ptv->current_file);
            ptv->current_file = NULL;
        }
        if (ptv->directory != NULL) {
            closedir(ptv->directory);
            ptv->directory = NULL;
        }
        if (ptv->filename != NULL) {
            SCFree(ptv->filename);
        }
        ptv->shared = NULL;
        PendingFile *current_file = NULL;
        while (!TAILQ_EMPTY(&ptv->directory_content)) {
            current_file = TAILQ_FIRST(&ptv->directory_content);
            TAILQ_REMOVE(&ptv->directory_content, current_file, next);
            CleanupPendingFile(current_file);
        }
        SCFree(ptv);
    }
}

TmEcode PcapDirectoryFailure(PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_FAILED;

    if (unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (unlikely(ptv->shared == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory shared vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, &ptv->shared->last_processed);
    }

    SCReturnInt(status);
}

TmEcode PcapDirectoryDone(PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_DONE;

    if (unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (unlikely(ptv->shared == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory shared vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, &ptv->shared->last_processed);
    }

    SCReturnInt(status);
}

TmEcode PcapDetermineDirectoryOrFile(char *filename, DIR **directory)
{
    DIR *temp_dir = NULL;
    TmEcode return_code = TM_ECODE_FAILED;

    temp_dir = opendir(filename);

    if (temp_dir == NULL) {//if null, our filename may just be a normal file
        switch (errno) {
            case EACCES:
                SCLogError(SC_ERR_FOPEN, "%s: Permission denied", filename);
                break;

            case EBADF:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Not a valid file descriptor opened for reading",
                           filename);
                break;

            case EMFILE:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Per process open file descriptor limit reached",
                           filename);
                break;

            case ENFILE:
                SCLogError(SC_ERR_FOPEN,
                           "%s: System wide open file descriptor limit reached",
                           filename);
                break;

            case ENOENT:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Does not exist, or name is an empty string",
                           filename);
                break;
            case ENOMEM:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Insufficient memory to complete the operation",
                           filename);
                break;

            case ENOTDIR: //no error checking the directory, just is a plain file
                SCLogInfo("%s: Plain file, not a directory", filename);
                return_code = TM_ECODE_OK;
                break;

            default:
                SCLogError(SC_ERR_FOPEN, "%s: %" PRId32, filename, errno);
        }
    } else {
        //no error, filename references a directory
        *directory = temp_dir;
        return_code = TM_ECODE_OK;
    }

    return return_code;
}

int PcapDirectoryGetModifiedTime(char const *file, struct timespec *out)
{
    struct stat buf;
    int ret;

    if (file == NULL)
        return -1;

    if ((ret = stat(file, &buf)) != 0)
        return ret;

#ifdef OS_DARWIN
    *out = buf.st_mtimespec;
#else
    *out = buf.st_mtim;
#endif

    return ret;
}

TmEcode PcapDirectoryInsertFile(PcapFileDirectoryVars *pv,
                                PendingFile *file_to_add,
                                struct timespec *file_to_add_modified_time
) {
    PendingFile *file_to_compare = NULL;
    PendingFile *next_file_to_compare = NULL;

    if (unlikely(pv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory vars passed");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (unlikely(file_to_add == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "File passed was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (unlikely(file_to_add->filename == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "File was passed with null filename");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogDebug("Inserting %s into directory buffer", file_to_add->filename);

    if (TAILQ_EMPTY(&pv->directory_content)) {
        TAILQ_INSERT_TAIL(&pv->directory_content, file_to_add, next);
    } else {
        file_to_compare = TAILQ_FIRST(&pv->directory_content);
        while(file_to_compare != NULL) {
            struct timespec modified_time;
            if (PcapDirectoryGetModifiedTime(file_to_compare->filename,
                                             &modified_time) == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            if (CompareTimes(file_to_add_modified_time, &modified_time) < 0) {
                TAILQ_INSERT_BEFORE(file_to_compare, file_to_add, next);
                file_to_compare = NULL;
            } else {
                next_file_to_compare = TAILQ_NEXT(file_to_compare, next);
                if (next_file_to_compare == NULL) {
                    TAILQ_INSERT_AFTER(&pv->directory_content, file_to_compare,
                                       file_to_add, next);
                }
                file_to_compare = next_file_to_compare;
            }
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode PcapDirectoryPopulateBuffer(PcapFileDirectoryVars *pv,
                                    struct timespec *newer_than,
                                    struct timespec *older_than
) {
    if (unlikely(pv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory vars passed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (unlikely(pv->filename == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory filename was passed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    struct dirent * dir = NULL;
    PendingFile *file_to_add = NULL;

    while ((dir = readdir(pv->directory)) != NULL) {
        if (dir->d_type != DT_REG) {
            continue;
        }

        char pathbuff[PATH_MAX] = {0};

        int written = 0;

        written = snprintf(pathbuff, PATH_MAX, "%s/%s", pv->filename, dir->d_name);

        if (written <= 0 || written >= PATH_MAX) {
            SCLogError(SC_ERR_SPRINTF, "Could not write path");
            SCReturnInt(TM_ECODE_FAILED);
        } else {
            struct timespec temp_time;

            if (PcapDirectoryGetModifiedTime(pathbuff, &temp_time) == 0) {
                SCLogDebug("File %s time (%lu > %lu < %lu)", pathbuff,
                           newer_than->tv_sec, temp_time.tv_sec, older_than->tv_sec);

                // Skip files outside of our time range
                if (CompareTimes(&temp_time, newer_than) < 0) {
                    SCLogDebug("Skipping old file %s", pathbuff);
                    continue;
                }
                else if (CompareTimes(&temp_time, older_than) >= 0) {
                    SCLogDebug("Skipping new file %s", pathbuff);
                    continue;
                }
            } else {
                SCLogDebug("Unable to get modified time on %s, skipping", pathbuff);
                continue;
            }

            file_to_add = SCCalloc(1, sizeof(PendingFile));
            if (unlikely(file_to_add == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate pending file");

                SCReturnInt(TM_ECODE_FAILED);
            }

            file_to_add->filename = SCStrdup(pathbuff);
            if (unlikely(file_to_add->filename == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to copy filename");

                SCReturnInt(TM_ECODE_FAILED);
            }

            SCLogDebug("Found \"%s\"", file_to_add->filename);

            if (PcapDirectoryInsertFile(pv, file_to_add, &temp_time) == TM_ECODE_FAILED) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to add file");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
    }

    SCReturnInt(TM_ECODE_OK);
}


TmEcode PcapDirectoryDispatchForTimeRange(PcapFileDirectoryVars *pv,
                                          struct timespec *newer_than,
                                          struct timespec *older_than)
{
    if (PcapDirectoryPopulateBuffer(pv, newer_than, older_than) == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to populate directory buffer");
        SCReturnInt(TM_ECODE_FAILED);
    }

    TmEcode status = TM_ECODE_OK;

    if (TAILQ_EMPTY(&pv->directory_content)) {
        SCLogInfo("Directory %s has no files to process", pv->filename);
        clock_gettime(CLOCK_REALTIME, older_than);
        older_than->tv_sec = older_than->tv_sec - pv->delay;
        rewinddir(pv->directory);
        status = TM_ECODE_OK;
    } else {
        PendingFile *current_file = NULL;

        while (status == TM_ECODE_OK && !TAILQ_EMPTY(&pv->directory_content)) {
            current_file = TAILQ_FIRST(&pv->directory_content);
            TAILQ_REMOVE(&pv->directory_content, current_file, next);

            if (unlikely(current_file == NULL)) {
                SCLogWarning(SC_ERR_PCAP_DISPATCH, "Current file was null");
            } else if (unlikely(current_file->filename == NULL)) {
                SCLogWarning(SC_ERR_PCAP_DISPATCH, "Current file filename was null");
            } else {
                SCLogDebug("Processing file %s", current_file->filename);

                PcapFileFileVars *pftv = SCMalloc(sizeof(PcapFileFileVars));
                if (unlikely(pftv == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate PcapFileFileVars");
                    SCReturnInt(TM_ECODE_FAILED);
                }
                memset(pftv, 0, sizeof(PcapFileFileVars));

                pftv->filename = SCStrdup(current_file->filename);
                if (unlikely(pftv->filename == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate filename");
                    SCReturnInt(TM_ECODE_FAILED);
                }
                pftv->shared = pv->shared;

                if (InitPcapFile(pftv) == TM_ECODE_FAILED) {
                    SCLogWarning(SC_ERR_PCAP_DISPATCH,
                                 "Failed to init pcap file %s, skipping",
                                 current_file->filename);
                    CleanupPendingFile(current_file);
                    CleanupPcapFileFileVars(pftv);
                    status = TM_ECODE_OK;
                } else {
                    pv->current_file = pftv;

                    status = PcapFileDispatch(pftv);

                    CleanupPcapFileFileVars(pftv);

                    if (status == TM_ECODE_FAILED) {
                        CleanupPendingFile(current_file);
                        SCReturnInt(status);
                    }

                    struct timespec temp_time;
                    memset(&temp_time, 0, sizeof(struct timespec));

                    if (PcapDirectoryGetModifiedTime(current_file->filename,
                                                     &temp_time) != 0) {
                        CopyTime(&temp_time, newer_than);
                    }
                    SCLogDebug("Processed file %s, processed up to %ld",
                               current_file->filename, temp_time.tv_sec);
                    CopyTime(&temp_time, &pv->shared->last_processed);

                    CleanupPendingFile(current_file);
                    pv->current_file = NULL;

                    status = PcapRunStatus(pv);
                }
            }
        }

        *newer_than = *older_than;
    }
    clock_gettime(CLOCK_REALTIME, older_than);
    older_than->tv_sec = older_than->tv_sec - pv->delay;

    SCReturnInt(status);
}

TmEcode PcapDirectoryDispatch(PcapFileDirectoryVars *ptv)
{
    SCEnter();

    struct timespec newer_than;
    memset(&newer_than, 0, sizeof(struct timespec));
    struct timespec older_than;
    memset(&older_than, 0, sizeof(struct timespec));
    older_than.tv_sec = LONG_MAX;
    uint32_t poll_seconds = (uint32_t)localtime(&ptv->poll_interval)->tm_sec;

    if (ptv->should_loop) {
        clock_gettime(CLOCK_REALTIME, &older_than);
        older_than.tv_sec = older_than.tv_sec - ptv->delay;
    }
    TmEcode status = TM_ECODE_OK;

    while (status == TM_ECODE_OK) {
        //loop while directory is ok
        SCLogInfo("Processing pcaps directory %s, files must be newer than %ld and older than %ld",
                  ptv->filename, newer_than.tv_sec, older_than.tv_sec);
        status = PcapDirectoryDispatchForTimeRange(ptv, &newer_than, &older_than);
        if (ptv->should_loop && status == TM_ECODE_OK) {
            sleep(poll_seconds);
            //update our status based on suricata control flags or unix command socket
            status = PcapRunStatus(ptv);
            if (status == TM_ECODE_OK) {
                SCLogDebug("Checking if directory %s still exists", ptv->filename);
                //check directory
                if (PcapDetermineDirectoryOrFile(ptv->filename,
                                                &(ptv->directory)) == TM_ECODE_FAILED) {
                    SCLogInfo("Directory %s no longer exists, stopping",
                              ptv->filename);
                    status = TM_ECODE_DONE;
                }
            }
        } else if (status == TM_ECODE_OK) { //not looping, mark done
            SCLogDebug("Not looping, stopping directory mode");
            status = TM_ECODE_DONE;
        }
    }

    StatsSyncCountersIfSignalled(ptv->shared->tv);

    if (status == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_PCAP_DISPATCH, "Directory %s run mode failed", ptv->filename);
        status = PcapDirectoryFailure(ptv);
    } else {
        SCLogInfo("Directory run mode complete");
        status = PcapDirectoryDone(ptv);
    }

    SCReturnInt(status);
}

/* eof */
