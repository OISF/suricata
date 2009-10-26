#ifndef __DETECT_SEQ_H__
#define __DETECT_SEQ_H__

/**
 * \brief seq data
 */
typedef struct DetectSeqData_ {
    uint32_t seq;                    /**< seq to match */
} DetectSeqData;

/**
 * \brief Registration function for ack: keyword
 */
void DetectSeqRegister(void);

#endif /* __DETECT_SEQ_H__ */

