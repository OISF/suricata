/**Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef _DETECT_HTTP_COOKIE_H
#define	_DETECT_HTTP_COOKIE_H

typedef struct DetectHttpCookieData_ {
    uint8_t *data;
    uint8_t data_len;
    uint32_t id;
    uint8_t negated;

    uint16_t depth;
    uint16_t offset;
    uint32_t isdataat;
    int32_t distance;
    int32_t within;
    uint16_t flags;

    /** The group this chunk belongs to, relative to the signature
     * It start from 1, and the last SigMatch of the list should be
     * also the total number of DetectContent "Real" Patterns loaded
     * from the Signature */
    uint8_t chunk_group_id;
    /** The id number for this chunk in the current group of chunks
     * Starts from 0, and a chunk with chunk_id == 0 should be the
     * of the current chunk group where real modifiers are set before
     * propagation */
    uint8_t chunk_id;
    /** For modifier propagations (the new flags) */
    uint8_t chunk_flags;
} DetectHttpCookieData;

/* prototypes */
void DetectHttpCookieRegister (void);

#endif	/* _DETECT_HTTP_COOKIE_H */

