/* 
========================================
  scc_entropy.h 
    : accumulate entropy
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_ENTROPY_H__
#define __SCC_ENTROPY_H__

#include "scc_protocol.h"

/* constants */
#define	SC_ENTROPY_MAX_DATA_LENGTH			396	// U8
#define SC_ENTROPY_PERIOD 100000

/* structure */
typedef struct {
	U8		data[SC_ENTROPY_MAX_DATA_LENGTH];
	U32		dataLength;
	U32		pos;
} SC_ENTROPY_CTX;

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_Entropy_Accumulate(SC_ENTROPY_CTX *entropy);

void
SC_Entropy_GetBasicPieces (U8 *out, U32 *outputLength);

#ifdef __cplusplus
}
#endif

#endif
