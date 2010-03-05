#ifndef __DETECT_HTTP_METHOD_H__
#define __DETECT_HTTP_METHOD_H__

typedef struct DetectHttpMethodData_ {
    uint8_t *content;     /**< Raw HTTP method content to match */
    size_t   content_len; /**< Raw HTTP method content length */
    int      method;      /**< Numeric HTTP method to match */
} DetectHttpMethodData;

/* prototypes */
void DetectHttpMethodRegister(void);
int DetectHttpMethodDoMatch(DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm, Flow *f, uint8_t flags, void *state);

#endif /* __DETECT_HTTP_METHOD_H__ */

