/**
 * Copyright(c) 2009 Open Information Security Foundation.
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */
#ifndef __ACTION_ORDER_H__
#define __ACTION_ORDER_H__
#include "suricata-common.h"
void ActionInitConfig();
uint8_t ActionOrderVal(uint8_t);
void UtilActionRegisterTests(void);

#endif /* __ACTION_ORDER_H__ */
