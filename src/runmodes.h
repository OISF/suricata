#ifndef __RUNMODES_H__
#define __RUNMODES_H__

void RunModeInitializeOutputs(void);

int RunModeIdsPcap(DetectEngineCtx *, char *);
int RunModeIdsPcap2(DetectEngineCtx *, char *);
int RunModeIdsPcap3(DetectEngineCtx *, char *);
int RunModeIdsPcapAuto(DetectEngineCtx *, char *);

int RunModeIpsNFQ(DetectEngineCtx *, char *);
int RunModeIpsNFQAuto(DetectEngineCtx *, char *);

int RunModeFilePcap(DetectEngineCtx *, char *);
int RunModeFilePcap2(DetectEngineCtx *, char *);
int RunModeFilePcapAuto(DetectEngineCtx *, char *);

int RunModeIdsPfring(DetectEngineCtx *, char *);
int RunModeIdsPfring2(DetectEngineCtx *, char *);
int RunModeIdsPfring3(DetectEngineCtx *, char *);
int RunModeIdsPfring4(DetectEngineCtx *, char *);
int RunModeIdsPfringAuto(DetectEngineCtx *, char *);

int RunModeIpsIPFW(DetectEngineCtx *);
int RunModeIpsIPFWAuto(DetectEngineCtx *);

void RunModeShutDown(void);

#endif /* __RUNMODES_H__ */

