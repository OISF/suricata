/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Breno Silva Pinto <breno.silva@gmail.com>
 */

#ifndef __UTIL_THRESHOLD_CONFIG_H__
#define __UTIL_THRESHOLD_CONFIG_H__

void SCThresholdConfDeInitContext(DetectEngineCtx *, FILE *);
inline void SCThresholdConfParseFile(DetectEngineCtx *, FILE *);
inline int SCThresholdConfInitContext(DetectEngineCtx *, FILE *);

void SCThresholdConfRegisterTests();

#endif /* __UTIL_THRESHOLD_CONFIG_H__ */
