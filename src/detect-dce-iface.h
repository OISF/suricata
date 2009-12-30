/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __DETECT_DCE_IFACE_H__
#define __DETECT_DCE_IFACE_H__

typedef enum DetectDceIfaceOperators_ {
    DETECT_DCE_IFACE_OP_LT = 1,
    DETECT_DCE_IFACE_OP_GT,
    DETECT_DCE_IFACE_OP_EQ,
    DETECT_DCE_IFACE_OP_NE,
} DetectDceIfaceOperators;

typedef struct DetectDceIfaceData_ {
    uint8_t uuid[16];
    uint8_t op;
    uint16_t version;
    uint8_t any_frag;
} DetectDceIfaceData;

void DetectDceIfaceRegister(void);
void DetectDceIfaceRegisterTests(void);

#endif /* __DETECT_DCE_IFACE_H__ */
