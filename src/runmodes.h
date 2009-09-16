#ifndef __RUNMODES_H__
#define __RUNMODES_H__

int RunModeIdsPcap(DetectEngineCtx *, char *);
int RunModeIdsPcap2(DetectEngineCtx *, char *);
int RunModeIdsPcap3(DetectEngineCtx *, char *);

int RunModeIpsNFQ(DetectEngineCtx *);

int RunModeFilePcap(DetectEngineCtx *, char *);
int RunModeFilePcap2(DetectEngineCtx *, char *);

#endif /* __RUNMODES_H__ */

