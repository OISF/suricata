/*
 * File:   detect-stream_size.h
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on September 7, 2009, 7:54 AM
 */

#ifndef _DETECT_STREAM_SIZE_H
#define	_DETECT_STREAM_SIZE_H

#define DETECTSSIZE_LT 0
#define DETECTSSIZE_LEQ 1
#define DETECTSSIZE_EQ 2
#define DETECTSSIZE_NEQ 3
#define DETECTSSIZE_GT 4
#define DETECTSSIZE_GEQ 5

#define STREAM_SIZE_SERVER 0x01
#define STREAM_SIZE_CLIENT 0x02
#define STREAM_SIZE_BOTH   0x04
#define STREAM_SIZE_EITHER 0x08

typedef struct DetectStreamSizeData_ {
    uint8_t flags;
    uint8_t mode;
    uint32_t ssize;
}DetectStreamSizeData;

void DetectStreamSizeRegister(void);

#endif	/* _DETECT_STREAM_SIZE_H */

