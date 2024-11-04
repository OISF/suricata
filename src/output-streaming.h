/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * Streaming Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_STREAMING_H
#define SURICATA_OUTPUT_STREAMING_H

#define OUTPUT_STREAMING_FLAG_OPEN          0x01
#define OUTPUT_STREAMING_FLAG_CLOSE         0x02
#define OUTPUT_STREAMING_FLAG_TOSERVER      0x04
#define OUTPUT_STREAMING_FLAG_TOCLIENT      0x08
#define OUTPUT_STREAMING_FLAG_TRANSACTION   0x10

enum SCOutputStreamingType {
    STREAMING_TCP_DATA,
    STREAMING_HTTP_BODIES,
};

/** streaming logger function pointer type */
typedef int (*SCStreamingLogger)(ThreadVars *, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags);

/** \brief Register a streaming logger.
 *
 * \param logger_id An ID to uniquely identify this logger.
 *
 * \param name An informational name for this logger.
 *
 * \param LogFunc Pointer to logging function.
 *
 * \param initdata Initialization data that will be passed the
 *     ThreadInit.
 *
 * \param stream_type Type of stream to log, see
 *     SCOutputStreamingType.
 *
 * \param ThreadInit Pointer to thread initialization function.
 *
 * \param ThreadDeinit Pointer to thread de-initialization function.
 */
int SCOutputRegisterStreamingLogger(LoggerId logger_id, const char *name, SCStreamingLogger LogFunc,
        void *initdata, enum SCOutputStreamingType stream_type, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);

/** Internal function: private API. */
void OutputStreamingLoggerRegister (void);

/** Internal function: private API. */
void OutputStreamingShutdown(void);

#endif /* SURICATA_OUTPUT_STREAMING_H */
