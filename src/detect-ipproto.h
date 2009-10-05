/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DETECT_IPPROTO_H__
#define __DETECT_IPPROTO_H__

/** IPProto Operators */
#define DETECT_IPPROTO_OP_EQ     '=' /**< "equals" operator (default) */
#define DETECT_IPPROTO_OP_NOT    '!' /**< "not" operator */
#define DETECT_IPPROTO_OP_LT     '<' /**< "less than" operator */
#define DETECT_IPPROTO_OP_GT     '>' /**< "greater than" operator */

/** ip_proto data */
typedef struct DetectIPProtoData_ {
    uint8_t op;                       /**< Operator used to compare */
    uint8_t proto;                    /**< Protocol used to compare */
} DetectIPProtoData;

/* prototypes */

/**
 * \brief Registration function for ip_proto keyword.
 */
void DetectIPProtoRegister (void);

#endif /* __DETECT_IPPROTO_H__ */

