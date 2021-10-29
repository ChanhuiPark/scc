/* 
========================================
  scc_util.h 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_UTIL_H__
#define __SCC_UTIL_H__

#include "scc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_Uint32ToByte(U8 *buf, U32 a);

U32 
SC_ByteToUint32(U8 *buf);

int 
SC_Codec(U8 *output, U8 *input, int inputLength);

void 
SC_Memzero( void *v, U8 c, int n );

#ifdef __cplusplus
}
#endif

#endif