/* 
========================================
  scc_random.h 
    : 
----------------------------------------
  softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_RANDOM_H__
#define __SCC_RANDOM_H__

#include "scc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_GetRandom(U8* output, U32 outputbytes);

#ifdef __cplusplus
}
#endif

#endif
