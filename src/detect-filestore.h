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
 */

#ifndef __DETECT_FILESTORE_H__
#define __DETECT_FILESTORE_H__

#define FILESTORE_DIR_DEFAULT   0   /* rule dir */
#define FILESTORE_DIR_TOSERVER  1
#define FILESTORE_DIR_TOCLIENT  2
#define FILESTORE_DIR_BOTH      3

#define FILESTORE_SCOPE_DEFAULT 0   /* per file */
#define FILESTORE_SCOPE_TX      1   /* per transaction */
#define FILESTORE_SCOPE_SSN     2   /* per flow/ssn */

typedef struct DetectFilestoreData_ {
    int16_t direction;
    int16_t scope;
} DetectFilestoreData;

/* prototypes */
void DetectFilestoreRegister (void);

#endif /* __DETECT_FILESTORE_H__ */
