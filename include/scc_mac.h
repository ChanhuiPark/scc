/* 
========================================
  scc_mac.h 
    : mac function
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_MAC_H__
#define __SCC_MAC_H__

#include "scc_protocol.h"
#include "scc_hmac_sha.h"
#include "scc_cipher.h"

typedef struct {
	int macID;
	union {
		SC_HMAC_SHA256_CTX hmacSha256;
		SC_HMAC_SHA512_CTX hmacSha512;
	} ctx;
} SC_MAC_CTX;


#ifdef __cplusplus
extern "C" {
#endif

SC_MAC_CTX * 
SC_MAC_CTX_New();

void 
SC_MAC_CTX_Free(SC_MAC_CTX *macCtx);

int
SC_MAC_Init(SC_MAC_CTX *macCtx, const SC_SKEY_SecretKey *key, const int macID);

int 
SC_MAC_Update(SC_MAC_CTX *macCtx, const U8 *input, const U32 inputLength);

int 
SC_MAC_Final(SC_MAC_CTX *macCtx, U8 *mac, U32 *macLength);

int 
SC_MAC(U8 *mac, U32 *macLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int macID);


#ifdef __cplusplus
}
#endif

#endif