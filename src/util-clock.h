#ifndef __UTIL_CLOCK_H__
#define __UTIL_CLOCK_H__

#include <time.h>

/* Feel free to add more macros */

#define CLOCK_INIT          clock_t clo1, clo2; clo1 = clo2 = 0;
#define CLOCK_START         clo1 = clock()

#define CLOCK_END           clo2 = clock()

#define CLOCK_PRINT_SEC     printf("Seconds spent: %.4fs\n", ((clo2 - clo1)/(double)CLOCKS_PER_SEC))

#define GET_CLOCK_END_SECS  ((clo1 - clo2)/(double)CLOCKS_PER_SEC)

#endif /*__UTIL_CLOCK_H__ */
