/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author William Metcalf <William.Metcalf@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Pcap packet logging module.
 */

#ifndef __LOG_PCAP_H__
#define __LOG_PCAP_H__

#ifdef HAVE_LIBLZ4
#include <lz4frame.h>
#endif /* HAVE_LIBLZ4 */

#include "pcap.h"

typedef struct PcapFileName_ {
    char *filename;
    char *dirname;

    /* Like a struct timeval, but with fixed size. This is only used when
     * seeding the ring buffer on start. */
    struct {
        uint64_t secs;
        uint32_t usecs;
    };

    TAILQ_ENTRY(PcapFileName_) next; /**< Pointer to next Pcap File for tailq. */
} PcapFileName;

typedef struct PcapLogProfileData_ {
    uint64_t total;
    uint64_t cnt;
} PcapLogProfileData;

#define MAX_TOKS 9
#define MAX_FILENAMELEN 513

enum PcapLogCompressionFormat {
    PCAP_LOG_COMPRESSION_FORMAT_NONE,
    PCAP_LOG_COMPRESSION_FORMAT_LZ4,
};

typedef struct PcapLogCompressionData_ {
    enum PcapLogCompressionFormat format;
    uint8_t *buffer;
    uint64_t buffer_size;
#ifdef HAVE_LIBLZ4
    LZ4F_compressionContext_t lz4f_context;
    LZ4F_preferences_t lz4f_prefs;
#endif /* HAVE_LIBLZ4 */
    FILE *file;
    uint8_t *pcap_buf;
    uint64_t pcap_buf_size;
    FILE *pcap_buf_wrapper;
    uint64_t bytes_in_block;
} PcapLogCompressionData;

/**
 * PcapLog thread vars
 *
 * Used for storing file options.
 */
typedef struct PcapLogData_ {
    int use_stream_depth;       /**< use stream depth i.e. ignore packets that reach limit */
    int honor_pass_rules;       /**< don't log if pass rules have matched */
    int is_private;             /**< TRUE if ctx is thread local */
    SCMutex plog_lock;
    uint64_t pkt_cnt;		/**< total number of packets */
    struct pcap_pkthdr *h;      /**< pcap header struct */
    char *filename;             /**< current filename */
    int mode;                   /**< normal or sguil */
    int prev_day;               /**< last day, for finding out when */
    uint64_t size_current;      /**< file current size */
    uint64_t size_limit;        /**< file size limit */
    pcap_t *pcap_dead_handle;   /**< pcap_dumper_t needs a handle */
    pcap_dumper_t *pcap_dumper; /**< actually writes the packets */
    uint64_t profile_data_size; /**< track in bytes how many bytes we wrote */
    uint32_t file_cnt;          /**< count of pcap files we currently have */
    uint32_t max_files;         /**< maximum files to use in ring buffer mode */

    PcapLogProfileData profile_lock;
    PcapLogProfileData profile_write;
    PcapLogProfileData profile_unlock;
    PcapLogProfileData profile_handles; // open handles
    PcapLogProfileData profile_close;
    PcapLogProfileData profile_open;
    PcapLogProfileData profile_rotate;

    TAILQ_HEAD(, PcapFileName_) pcap_file_list;

    uint32_t thread_number;     /**< thread number, first thread is 1, second 2, etc */
    int use_ringbuffer;         /**< ring buffer mode enabled or disabled */
    int timestamp_format;       /**< timestamp format sec or usec */
    char *prefix;               /**< filename prefix */
    const char *suffix;         /**< filename suffix */
    char dir[PATH_MAX];         /**< pcap log directory */
    int reported;
    int threads;                /**< number of threads (only set in the global) */
    char *filename_parts[MAX_TOKS];
    int filename_part_cnt;
    int alert_capture_cnt;      /**< count for number of alerts captured */
    int alert_dir_cnt;          /**< count of the number of alert capture directories created */
    char *alert_dirname;            /**< name of alert directory */
    char *alert_capture_dirname;      /**< current capture directory name */

    PcapLogCompressionData compression;
} PcapLogData;

typedef struct PcapLogThreadData_ {
    PcapLogData *pcap_log;
} PcapLogThreadData;

void PcapLogRegister(void);
void PcapLogProfileSetup(void);
#endif /* __LOG_PCAP_H__ */
