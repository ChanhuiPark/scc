/* 
========================================
  scc_hmac_sha.h 
    : hmac sha2 algorithm
	: FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_HMAC_SHA_H__
#define __SCC_HMAC_SHA_H__

#include "scc_sha256.h"
#include "scc_sha512.h"
#include "scc_protocol.h"

/* structure */
typedef struct
{
	SC_SHA256_CONTEXT ctxInside;
	SC_SHA256_CONTEXT ctxOutside;

	U8 blockIpad[SCC_SHA256_BLOCK_SIZE];
	U8 blockOpad[SCC_SHA256_BLOCK_SIZE];

} SC_HMAC_SHA256_CTX;

typedef struct 
{
	SC_SHA512_CONTEXT ctxInside;
	SC_SHA512_CONTEXT ctxOutside;

	U8 blockIpad[SCC_SHA512_BLOCK_SIZE];
	U8 blockOpad[SCC_SHA512_BLOCK_SIZE];

} SC_HMAC_SHA512_CTX;

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_HMAC_SHA256_Init(SC_HMAC_SHA256_CTX *ctx, const U8 *key, const U32 keySize);

int 
SC_HMAC_SHA256_Update(SC_HMAC_SHA256_CTX *ctx, const U8 *message, const U32 messageLength);

int 
SC_HMAC_SHA256_Final(SC_HMAC_SHA256_CTX *ctx, U8 *mac, U32 *macLength);

int 
SC_HMAC_SHA256(U8 *mac, U32 *macLength,
				 const U8 *key, const U32 keySize,
                 const U8 *message, const U32 messageLength);

int 
SC_HMAC_SHA512_Init(SC_HMAC_SHA512_CTX *ctx, const U8 *key, const U32 keySize);

int 
SC_HMAC_SHA512_Update(SC_HMAC_SHA512_CTX *ctx, const U8 *message, const U32 messageLength);

int 
SC_HMAC_SHA512_Final(SC_HMAC_SHA512_CTX *ctx, U8 *mac, U32 *macLength);

int 
SC_HMAC_SHA512(U8 *mac, U32 *macLength,
				 const U8 *key, const U32 keySize,
                 const U8 *message, const U32 messageLength);

#ifdef __cplusplus
}
#endif

#endif 

