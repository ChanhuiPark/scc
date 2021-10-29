/* 
========================================
  scc_sha256.h 
    : sha256 algorithm
	: KS X ISO/IEC 10118-3:2006
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_SHA256_H__
#define __SCC_SHA256_H__

#include <stddef.h>
#include "scc_protocol.h"

/* structure */
typedef struct
{
    U32 total[2];          /*!< number of bytes processed  */
    U32 state[8];          /*!< intermediate digest state  */
    U8  buffer[64];		   /*!< data block being processed */
}
SC_SHA256_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif

void 
SC_SHA256_New(SC_SHA256_CONTEXT *ctx);

void 
SC_SHA256_Free(SC_SHA256_CONTEXT *ctx);

void 
SC_SHA256_Clone(SC_SHA256_CONTEXT *dst, const SC_SHA256_CONTEXT *src);

int 
SC_SHA256_Init(SC_SHA256_CONTEXT *ctx);

int 
SC_SHA256_Update(SC_SHA256_CONTEXT *ctx, const U8 *input, U32 inputLength);

int 
SC_SHA256_Final(SC_SHA256_CONTEXT *ctx, U8 output[32]);

int 
SC_SHA256_Digest(U8 *output, U32 *outputLength, const U8 *input, U32 inputLength);


#ifdef __cplusplus
}
#endif

#endif