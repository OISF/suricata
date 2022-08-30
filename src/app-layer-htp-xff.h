/* Copyright (C) 2014-2022 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 */

#ifndef __APP_LAYER_HTP_XFF_H__
#define __APP_LAYER_HTP_XFF_H__

/** XFF is disabled */
#define XFF_DISABLED 1
/** XFF extra data mode */
#define XFF_EXTRADATA 2
/** XFF overwrite mode */
#define XFF_OVERWRITE 4
/** XFF is to be used in a reverse proxy deployment */
#define XFF_REVERSE 8
/** XFF is to be used in a forward proxy deployment */
#define XFF_FORWARD 16
/** Single XFF IP maximum length (default value based on IPv6 address length) */
#define XFF_MAXLEN 46

typedef struct HttpXFFCfg_ {
    uint8_t flags; /**< XFF operation mode and deployment */
    const char *header; /**< XFF header name */
} HttpXFFCfg;

void HttpXFFGetCfg(ConfNode *conf, HttpXFFCfg *result);

int HttpXFFGetIPFromTx(const Flow *f, uint64_t tx_id, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen);

int HttpXFFGetIP(const Flow *f, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen);

void HTPXFFParserRegisterTests(void);

#endif /* __APP_LAYER_HTP_XFF_H__ */
