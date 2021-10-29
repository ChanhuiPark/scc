/* 
========================================
  scc_kcdsa.h
    : Digital Signature Algorithm KCDSA
	: TTAS.KO-12.0001/R3:2014
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/
#ifndef __SCC_KCDSA_H__
#define __SCC_KCDSA_H__

#include "scc_protocol.h"
#include "scc_bignum.h"

/* constants */
#define SC_DOMAIN_PARAMS	1
#define SC_PRIVATE_KEY		2
#define SC_PUBLIC_KEY		3

typedef struct {
	SC_BIGINT 		KCDSA_p;		//	prime(1024 + 128i bits i=0..8)
	SC_BIGINT 		KCDSA_q;		//	subprime(128 + 32j bits j=0..4)
	SC_BIGINT 		KCDSA_g;		//	Base

	U32				Count;			//	Prime Type ID
	U32				SeedLen;		//	in BYTEs
	U8				*Seed;			//
} SC_KCDSA_Parameters;

#ifdef __cplusplus
extern "C" {
#endif


int 
SC_KCDSA_CreateKeyObject(SC_KCDSA_Parameters **KCDSA_Params);

int 
SC_KCDSA_DestroyKeyObject(SC_KCDSA_Parameters **KCDSA_Params);
	
int 
SC_KCDSA_Sign(SC_KCDSA_Parameters *KCDSA_Params, SC_BIGINT *KCDSA_x, U8 *MsgDigest, U32 MsgDigestLen, U8 *Signature, U32 *SignLen);

int 
SC_KCDSA_Verify(SC_KCDSA_Parameters *KCDSA_Params, SC_BIGINT *KCDSA_y, U8 *MsgDigest, U32 MsgDigestLen, U8 *Signature, U32 SignLen);


#ifdef __cplusplus
}
#endif

#endif
