#ifndef __RUNMODE_DPDKINTEL_H__
#define __RUNMODE_DPDKINTEL_H__

#include <inttypes.h>


int32_t RunModeDpdkIntelWorkers(void);
void RunModeDpdkIntelRegister(void);
const char *RunModeDpdkIntelGetDefaultMode(void);
void ParseDpdkConfig(void);

#endif /* __RUNMODE_DPDKINTEL_H__ */
