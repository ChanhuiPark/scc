/* 
========================================
  scc_sha512.h 
    : sha512 algorithm
	: KS X ISO/IEC 10118-3:2006
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_SHA512_H__
#define __SCC_SHA512_H__

#include <stddef.h>
#include "scc_protocol.h"

/* structure */
typedef struct
{
    U64 total[2];          /*!< number of bytes processed  */
    U64 state[8];          /*!< intermediate digest state  */
    U8 buffer[128];		   /*!< data block being processed */
}
SC_SHA512_CONTEXT;


#ifdef __cplusplus
extern "C" {
#endif


void 
SC_SHA512_New(SC_SHA512_CONTEXT *ctx);

void 
SC_SHA512_Free(SC_SHA512_CONTEXT *ctx);

void 
SC_SHA512_Clone(SC_SHA512_CONTEXT *dst, const SC_SHA512_CONTEXT *src);

int 
SC_SHA512_Init(SC_SHA512_CONTEXT *ctx);

int 
SC_SHA512_Update(SC_SHA512_CONTEXT *ctx, const U8 *input, U32 inputLength);

int 
SC_SHA512_Final(SC_SHA512_CONTEXT *ctx, U8 output[64]);

int 
SC_SHA512_Digest(U8 *output, U32 *outputLength, const U8 *input, U32 inputLength);


#ifdef __cplusplus
}
#endif

#endif
