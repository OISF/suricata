#include "suricata-common.h"
#include "app-layer-detect.h"

/** \brief alloc a app layer detection ctx
 *  \retval alde_ctx ptr or NULL in case of error
 */
AlDetectEngineCtx *AlDetectEngineCtxAlloc(void) {
    AlDetectEngineCtx *alde_ctx = malloc(sizeof(AlDetectEngineCtx));
    if (alde_ctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed: %s", strerror(errno));
        return NULL;
    }
    memset(alde_ctx, 0x00, sizeof(AlDetectEngineCtx));

    return alde_ctx;
}

/** \brief free a app layer detection ctx
 *  \param alde_ctx ptr to app layer detection ctx
 */
void AlDetectEngineCtxAllocFree(AlDetectEngineCtx *alde_ctx) {
    free(alde_ctx);
}

