#ifndef __DETECT_ACK_H__
#define __DETECT_ACK_H__

/**
 * \brief ack data
 */
typedef struct DetectAckData_ {
    uint32_t ack;                    /**< ack to match */
} DetectAckData;

/**
 * \brief Registration function for ack: keyword
 */
void DetectAckRegister(void);

#endif /* __DETECT_ACK_H__ */

