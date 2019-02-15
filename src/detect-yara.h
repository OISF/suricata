/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Ingve Skåra <isk@ingve.org>
 */

#ifndef __DETECT_YARA_H__
#define __DETECT_YARA_H__

#ifdef HAVE_LIBYARA
typedef struct DetectYaraData_ {
    int negated;
    char *filename;
    int thread_ctx_id;
    YR_RULES *rules;
} DetectYaraData;

#endif /* HAVE_LIBYARA */
void DetectYaraRegister(void);

#endif /* __DETECT_YARA_H__ */

