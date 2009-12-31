/** \file
  * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
  */

#include "suricata-common.h"
#include "detect.h"
#include "threads.h"
#include "util-debug.h"

/**
 * \brief create a seed number to pass to rand() , rand_r(), and similars
 * \retval seed for rand()
 */
unsigned int RandomTimePreseed(void) {
    /* preseed rand() */
    time_t now = time ( 0 );
    unsigned char *p = (unsigned char *)&now;
    unsigned seed = 0;
    size_t ind;

    for ( ind = 0; ind < sizeof now; ind++ )
      seed = seed * ( UCHAR_MAX + 2U ) + p[ind];

    return seed;
}

