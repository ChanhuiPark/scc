/* 
========================================
  scc_drbg.h 
    : random algorithm
	: TTAK.KO-12.0190:2012, Deterministic Random Bit Generator - Part 2 : 
	  Deterministic Random Bit Generator Based On Hash Function
    : ISO/IEC 18031:2011, Information technology Security techniques Random bit generation
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_DRBG_H__
#define __SCC_DRBG_H__

#include "scc_protocol.h"

/* constants */
#define	SC_HashDRBG_MATERIAL_MAX_SIZE				880		// BYTE(entropy165bytes + nonce8bytes + personalization_string55bytes)
#define SC_HashDRBG_BLOCK_SIZE						32
#define SC_HashDRBG_SEED_LEN						55
#define SC_HashDRBG_SEED_LEN_BIT					440
#define SC_HashDRBG_SEED_N							0x000001B8 //55byte
#define SC_HashDRBG_LEN_SEED						2      //sha256 
#define RESEED_MAX									100000
#define SC_HashDRBG_ONE								0x01
#define SC_MAX_BITS_REQUEST							1 << (19 - 1)

/* structure */
typedef struct{
	U32 reseedCounter;
	U8 V[SC_HashDRBG_SEED_LEN];
	U8 C[SC_HashDRBG_SEED_LEN];
	int vLen;
	int cLen;
}SC_HashDRBG_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_HashDRBG_Reseed(SC_HashDRBG_CONTEXT *ctx, const U8 *addInput, const U32 addInputLen);

int 
SC_HashDRBG_ReseedTestVector(SC_HashDRBG_CONTEXT *ctx, const U8 *addInput, const U32 addInputLen, const U8 *entropy, U32 entropyLen);

int 
SC_HashDRBG_Init( SC_HashDRBG_CONTEXT *ctx, U8 *personalStr, U32 personalStrLen, U8 *nonce, U32 nonceLen);

int 
SC_HashDRBG_Generate(SC_HashDRBG_CONTEXT *ctx, 
						 U8 *output, const U32 outputLen, 
						 const U8 *addInput, const int addInputLen, 
						 const int predictionResistant);

#ifdef __cplusplus
}
#endif

#endif
