#ifndef __UTIL_VAR_NAME_H__
#define __UTIL_VAR_NAME_H__

int VariableNameInitHash(DetectEngineCtx *de_ctx);
u_int16_t VariableNameGetIdx(DetectEngineCtx *, char *, u_int8_t, u_int8_t);

#endif

