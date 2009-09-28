#ifndef __RUNMODES_H__
#define __RUNMODES_H__

int RunModeIdsPcap(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);
int RunModeIdsPcap2(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);
int RunModeIdsPcap3(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);

int RunModeIpsNFQ(DetectEngineCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);

int RunModeFilePcap(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);
int RunModeFilePcap2(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);

int RunModeIdsPfring(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);
int RunModeIdsPfring2(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);
int RunModeIdsPfring3(DetectEngineCtx *, char *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *, LogFileCtx *);

#endif /* __RUNMODES_H__ */

