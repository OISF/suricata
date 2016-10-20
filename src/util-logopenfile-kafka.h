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
 * \author Paulo Pacheco <fooinha@gmail.com>
 */

#ifndef __UTIL_LOGOPENFILE_KAFKA_H__
#define __UTIL_LOGOPENFILE_KAFKA_H__

#ifdef HAVE_LIBRDKAFKA

#include "conf.h"            /* ConfNode   */

#include "librdkafka/rdkafka.h"

typedef struct KafkaSetup_ {
    rd_kafka_topic_t *topic;
    rd_kafka_conf_t *conf;
    char *brokers;
    int partition;
    intmax_t loglevel;
    time_t tried;
} KafkaSetup;


int SCConfLogOpenKafka(ConfNode *, void *);
int LogFileWriteKafka(void *, const char *, size_t);
void SCLogFileCloseKafka(void *lf_ctx);

#endif /* HAVE_LIBRDKAFKA */
#endif /* __UTIL_LOGOPENFILE_KAFKA_H__ */
