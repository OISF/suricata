/* Copyright (C) 2015-2017 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#ifndef SURICATA_DETECT_KRB5_ERRCODE_H
#define SURICATA_DETECT_KRB5_ERRCODE_H

typedef struct DetectKrb5ErrCodeData_ {
    int32_t err_code;
} DetectKrb5ErrCodeData;

void DetectKrb5ErrCodeRegister(void);

#endif /* SURICATA_DETECT_KRB5_ERRCODE_H */
