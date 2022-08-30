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
 * \author Danny Browning <danny.browning@protectwise.com>
 */

#include "suricata-common.h"
#include "source-pcap-file-helper.h"
#include "queue.h"

#ifndef __SOURCE_PCAP_FILE_DIRECTORY_HELPER_H__
#define __SOURCE_PCAP_FILE_DIRECTORY_HELPER_H__

typedef struct PendingFile_
{
    char *filename;
    struct timespec modified_time;
    TAILQ_ENTRY(PendingFile_) next;
} PendingFile;
/**
 * Data specific to a directory of pcap files
 */
typedef struct PcapFileDirectoryVars_
{
    char *filename;
    DIR *directory;
    PcapFileFileVars *current_file;
    bool should_loop;
    bool should_recurse;
    uint8_t cur_dir_depth;
    time_t delay;
    time_t poll_interval;

    TAILQ_HEAD(PendingFiles, PendingFile_) directory_content;

    PcapFileSharedVars *shared;
} PcapFileDirectoryVars;

/**
 * Cleanup resources associated with a PendingFile object
 * @param pending Object to be cleaned up
 */
void CleanupPendingFile(PendingFile *pending);

/**
 * Cleanup resources associated with a PcapFileDirectoryVars object
 * @param ptv Object to be cleaned up
 */
void CleanupPcapFileDirectoryVars(PcapFileDirectoryVars *ptv);

/**
 * Determine if a given string represents a file or directory. If a directory,
 * populate the directory object.
 * @param filename String to check
 * @param directory Directory point to populate if directory
 * @return TM_ECODE_OK if string or directory
 */
TmEcode PcapDetermineDirectoryOrFile(char *filename, DIR **directory);

/**
 * Dispatch a directory for processing, where information for processing the
 * directory is contained in a PcapFileDirectoryVars object
 * @param ptv PcapFileDirectoryVars object containing information for processing
 * the directory
 * @return
 */
TmEcode PcapDirectoryDispatch(PcapFileDirectoryVars *ptv);

#endif /* __SOURCE_PCAP_FILE_DIRECTORY_HELPER_H__ */
