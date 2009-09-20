/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DETECT_BYTEJUMP_H__
#define __DETECT_BYTEJUMP_H__

/** Bytejump Base */
#define DETECT_BYTEJUMP_BASE_UNSET  0 /**< Unset type value string (automatic)*/
#define DETECT_BYTEJUMP_BASE_OCT    8 /**< "oct" type value string */
#define DETECT_BYTEJUMP_BASE_DEC   10 /**< "dec" type value string */
#define DETECT_BYTEJUMP_BASE_HEX   16 /**< "hex" type value string */

/** Bytejump Flags */
#define DETECT_BYTEJUMP_BEGIN    0x01 /**< "from_beginning" jump */
#define DETECT_BYTEJUMP_LITTLE   0x02 /**< "little" endian value (default "big") */
#define DETECT_BYTEJUMP_STRING   0x04 /**< "string" value */
#define DETECT_BYTEJUMP_RELATIVE 0x08 /**< "relative" offset */
#define DETECT_BYTEJUMP_ALIGN    0x10 /**< "align" offset */

typedef struct DetectBytejumpData_ {
    uint8_t nbytes;                   /**< Number of bytes to compare */
    uint8_t base;                     /**< String value base (oct|dec|hex) */
    uint8_t flags;                    /**< Flags (big|little|relative|string) */
    uint32_t multiplier;              /**< Multiplier for nbytes (multiplier n)*/
    int32_t offset;                   /**< Offset in payload to extract value */
    int32_t post_offset;              /**< Offset to adjust post-jump */
} DetectBytejumpData;

/* prototypes */

/**
 * Registration function for byte_jump.
 *
 * \todo add support for no_stream and stream_only
 */
void DetectBytejumpRegister (void);

/**
 * This function is used to add the parsed byte_jump data
 * into the current signature.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectBytejumpSetup(DetectEngineCtx *de_ctx, Signature *s,
                        SigMatch *m, char *optstr);

/**
 * \brief this function will free memory associated with DetectBytejumpData
 *
 * \param data pointer to DetectBytejumpData
 */
void DetectBytejumpFree(void *ptr);

/**
 * This function is used to parse byte_jump options passed via
 *
 * byte_jump: bytes, offset [,flags [, ...]]
 *
 * flags: "big", "little", "relative", "string", "oct", "dec", "hex"
 *        "align", "from beginning", "multiplier N", "post_offset N"
 *
 * \param optstr Pointer to the user provided byte_jump options
 *
 * \retval data pointer to DetectBytejumpData on success
 * \retval NULL on failure
 */
DetectBytejumpData *DetectBytejumpParse(char *optstr);

/**
 * This function is used to match byte_jump
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectBytejumpData
 *
 * \retval -1 error
 * \retval  0 no match
 * \retval  1 match
 *
 * \todo The return seems backwards.  We should return a non-zero error code.
 *       One of the error codes is "no match".  As-is if someone accidentally
 *       does: if (DetectBytejumpMatch(...)) { match }, then they catch an
 *       error as a match.
 */
int DetectBytejumpMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m);

#endif /* __DETECT_BYTEJUMP_H__ */

