#ifndef __UTIL_VAR_NAME_H__
#define __UTIL_VAR_NAME_H__

int VariableNameInitHash(DetectEngineCtx *de_ctx);
void VariableNameFreeHash(DetectEngineCtx *de_ctx);

uint16_t VariableNameGetIdx(DetectEngineCtx *, char *, uint8_t);

#endif

