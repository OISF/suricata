/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DETECT_BYTETEST_H__
#define __DETECT_BYTETEST_H__

/** Bytetest Operators */
#define DETECT_BYTETEST_OP_LT     '<' /**< "less than" operator */
#define DETECT_BYTETEST_OP_GT     '>' /**< "greater than" operator */
#define DETECT_BYTETEST_OP_EQ     '=' /**< "equals" operator */
#define DETECT_BYTETEST_OP_AND    '&' /**< "bitwise and" operator */
#define DETECT_BYTETEST_OP_OR     '^' /**< "bitwise or" operator */

/** Bytetest Base */
#define DETECT_BYTETEST_BASE_UNSET  0 /**< Unset type value string (automatic)*/
#define DETECT_BYTETEST_BASE_OCT    8 /**< "oct" type value string */
#define DETECT_BYTETEST_BASE_DEC   10 /**< "dec" type value string */
#define DETECT_BYTETEST_BASE_HEX   16 /**< "hex" type value string */

/** Bytetest Flags */
#define DETECT_BYTETEST_NEGOP    0x01 /**< "!" negated operator */
#define DETECT_BYTETEST_LITTLE   0x02 /**< "little" endian value (default "big") */
#define DETECT_BYTETEST_STRING   0x04 /**< "string" value */
#define DETECT_BYTETEST_RELATIVE 0x08 /**< "relative" offset */

typedef struct DetectBytetestData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t op;                       /**< Operator used to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint8_t flags;                    /**< Flags (big|little|relative|string) */
    int32_t offset;                   /**< Offset in payload */
    uint64_t value;                   /**< Value to compare against */
} DetectBytetestData;

/* prototypes */

/**
 * Registration function for byte_test.
 *
 * \todo add support for no_stream and stream_only
 */
void DetectBytetestRegister (void);

/**
 * This function is used to add the parsed byte_test data
 * into the current signature.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectBytetestSetup(DetectEngineCtx *, Signature *, char *);

/**
 * \brief this function will free memory associated with DetectBytetestData
 *
 * \param data pointer to DetectBytetestData
 */
void DetectBytetestFree(void *ptr);

/**
 * This function is used to parse byte_test options passed via
 *
 * byte_test: bytes, [!]op, value, offset [,flags [, ...]]
 *
 * flags: "big", "little", "relative", "string", "oct", "dec", "hex"
 *
 * \param optstr Pointer to the user provided byte_test options
 *
 * \retval data pointer to DetectBytetestData on success
 * \retval NULL on failure
 */
DetectBytetestData *DetectBytetestParse(char *optstr);

/**
 * This function is used to match byte_test
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectBytetestData
 *
 * \retval -1 error
 * \retval  0 no match
 * \retval  1 match
 *
 * \todo The return seems backwards.  We should return a non-zero error code.  One of the error codes is "no match".  As-is if someone accidentally does: if (DetectBytetestMatch(...)) { match }, then they catch an error as a match.
 */
int DetectBytetestMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);
int DetectBytetestDoMatch(DetectEngineThreadCtx *, Signature *, SigMatch *, uint8_t *, uint32_t);

#endif /* __DETECT_BYTETEST_H__ */

