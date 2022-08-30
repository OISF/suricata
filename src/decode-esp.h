/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 */

#ifndef __DECODE_ESP_H__
#define __DECODE_ESP_H__

/** \brief size of the ESP header */
#define ESP_HEADER_LEN 8

#define ESP_GET_RAW_SPI(esph)      SCNtohl((esph)->spi)
#define ESP_GET_RAW_SEQUENCE(esph) SCNtohl((esph)->sequence)

/** \brief Get the spi field off a packet */
#define ESP_GET_SPI(p) ESP_GET_RAW_SPI(p->esph)

/** \brief Get the sequence field off a packet */
#define ESP_GET_SEQUENCE(p) ESP_GET_RAW_SEQUENCE(p->esph)

/** \brief ESP Header */
typedef struct ESPHdr_ {
    uint32_t spi;      /** < ESP Security Parameters Index */
    uint32_t sequence; /** < ESP sequence number */
} __attribute__((__packed__)) ESPHdr;

#define CLEAR_ESP_PACKET(p)                                                                        \
    {                                                                                              \
        (p)->esph = NULL;                                                                          \
    }                                                                                              \
    while (0)

void DecodeESPRegisterTests(void);

#endif /* __DECODE_ESP_H__ */
