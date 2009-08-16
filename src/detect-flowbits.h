#ifndef __DETECT_FLOWBITS_H__
#define __DETECT_FLOWBITS_H__

#define DETECT_FLOWBITS_CMD_ISSET    0
#define DETECT_FLOWBITS_CMD_ISNOTSET 1
#define DETECT_FLOWBITS_CMD_SET      2 
#define DETECT_FLOWBITS_CMD_UNSET    3
#define DETECT_FLOWBITS_CMD_TOGGLE   4
#define DETECT_FLOWBITS_CMD_NOALERT  5

typedef struct DetectFlowbitsData_ {
    uint16_t idx;
    uint8_t cmd;
} DetectFlowbitsData;

/* prototypes */
void DetectFlowbitsRegister (void);

#endif /* __DETECT_FLOWBITS_H__ */

