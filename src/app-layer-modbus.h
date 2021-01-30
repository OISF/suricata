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

#ifndef __APP_LAYER_MODBUS_H__
#define __APP_LAYER_MODBUS_H__

/* Modbus Function Code Categories. */
#define MODBUS_CAT_NONE                 0x0
#define MODBUS_CAT_PUBLIC_ASSIGNED      (1<<0)
#define MODBUS_CAT_PUBLIC_UNASSIGNED    (1<<1)
#define MODBUS_CAT_USER_DEFINED         (1<<2)
#define MODBUS_CAT_RESERVED             (1<<3)
#define MODBUS_CAT_ALL                  0xFF

/* Modbus Read/Write function and Access Types. */
#define MODBUS_TYP_NONE                 0x0
#define MODBUS_TYP_ACCESS_MASK          0x03
#define MODBUS_TYP_READ                 (1<<0)
#define MODBUS_TYP_WRITE                (1<<1)
#define MODBUS_TYP_ACCESS_FUNCTION_MASK 0x3C
#define MODBUS_TYP_BIT_ACCESS_MASK      0x0C
#define MODBUS_TYP_DISCRETES            (1<<2)
#define MODBUS_TYP_COILS                (1<<3)
#define MODBUS_TYP_WORD_ACCESS_MASK     0x30
#define MODBUS_TYP_INPUT                (1<<4)
#define MODBUS_TYP_HOLDING              (1<<5)
#define MODBUS_TYP_SINGLE               (1<<6)
#define MODBUS_TYP_MULTIPLE             (1<<7)
#define MODBUS_TYP_WRITE_SINGLE         (MODBUS_TYP_WRITE | MODBUS_TYP_SINGLE)
#define MODBUS_TYP_WRITE_MULTIPLE       (MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)
#define MODBUS_TYP_READ_WRITE_MULTIPLE  (MODBUS_TYP_READ | MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)

#endif /* __APP_LAYER_MODBUS_H__ */
