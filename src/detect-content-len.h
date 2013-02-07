/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_CONTENT_LEN__H__
#define	__DETECT_CONTENT_LEN__H__

#define DETECT_CONTENT_LEN_LT  0
#define DETECT_CONTENT_LEN_GT  1
#define DETECT_CONTENT_LEN_EQ  3
#define DETECT_CONTENT_LEN_LE  4
#define DETECT_CONTENT_LEN_GE  5
#define DETECT_CONTENT_LEN_NE  6

typedef struct DetectContentLenData_ {
    uint32_t len;
    uint8_t op;
} DetectContentLenData;

int DetectContentLenMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *,
                          uint8_t, void *, Signature *, SigMatch *);
void DetectContentLenRegister(void);

#endif	/* __DETECT_CONTENT_LEN__H__ */
