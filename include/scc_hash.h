/* 
========================================
  scc_hash.h 
    : hash function
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_HASH_H__
#define __SCC_HASH_H__

#include "scc_protocol.h"
#include "scc_sha256.h"
#include "scc_sha512.h"


typedef struct {
	int hashID;
	//SC_HASH_INFO info;
	union {
		SC_SHA256_CONTEXT sha256;
		SC_SHA512_CONTEXT sha512;
	} ctx;
} SC_HASH_CTX;



#ifdef __cplusplus
extern "C" {
#endif

SC_HASH_CTX * 
SC_HASH_CTX_New(void);

void 
SC_HASH_CTX_Free(SC_HASH_CTX *hashCtx);

int 
SC_Hash_Init(SC_HASH_CTX *hashCtx, const int hashID);

int 
SC_Hash_Update(SC_HASH_CTX *hashCtx, const U8 *input, const U32 inputLength);

int 
SC_Hash_Final(SC_HASH_CTX *hashCtx, U8 *hash, U32 *hashLength);

int 
SC_Hash(U8 *hash, U32 *hashLength, U8 *input, U32 inputLength, const int hashID);


#ifdef __cplusplus
}
#endif


#endif
