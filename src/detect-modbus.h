/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author David DIALLO <diallo@et.esiea.fr>
 */

#ifndef __DETECT_MODBUS_H__
#define __DETECT_MODBUS_H__

#include "app-layer-modbus.h"

typedef enum {
    DETECT_MODBUS_EQ = 0,   /** < EQual operator */
    DETECT_MODBUS_LT,       /** < "Less Than" operator */
    DETECT_MODBUS_GT,       /** < "Greater Than" operator */
    DETECT_MODBUS_RA,       /** < RAnge operator */
} DetectModbusMode;

typedef struct DetectModbusValue_ {
    uint16_t            min;    /** < Modbus minimum [range] or equal value to match */
    uint16_t            max;    /** < Modbus maximum value [range] to match */
    DetectModbusMode    mode;   /** < Modbus operator used in the address/data signature */
} DetectModbusValue;

typedef struct DetectModbus_ {
    uint8_t             category;       /** < Modbus function code category to match */
    uint8_t             function;       /** < Modbus function code to match */
    uint16_t            *subfunction;   /** < Modbus subfunction to match */
    uint8_t             type;           /** < Modbus access type to match */
    DetectModbusValue   *address;       /** < Modbus address to match */
    DetectModbusValue   *data;          /** < Modbus data to match */
} DetectModbus;

/* prototypes */
void DetectModbusRegister(void);

#endif /* __DETECT_MODBUS_H__ */
