#ifndef __UTIL_CPU_H__
#define __UTIL_CPU_H__

/* Processors configured: */
uint16_t UtilCpuGetNumProcessorsConfigured();
/* Processors online: */
uint16_t UtilCpuGetNumProcessorsOnline();

/* Only on Solaris */
uint16_t UtilCpuGetNumProcessorsMax();

void UtilCpuPrintSummary();

#endif /* __UTIL_CPU_H__ */
