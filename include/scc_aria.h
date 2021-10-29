/* 
========================================
  scc_aria.h 
    : aria algorithm
	: KS X 1213-1:2014, KS X 1213-2:2014
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_ARIA_H__
#define __SCC_ARIA_H__

#include "scc_protocol.h"

/* constants */
#define	SC_ARIA_DIR_ENCRYPT					0
#define	SC_ARIA_DIR_DECRYPT					1

#define	SC_ARIA_MAX_KEY_SIZE				32		// 256 bits, U8s Block
#define	SC_ARIA_MIN_KEY_SIZE				16		// 128 bits, U8s Block

#define	SC_ARIA_BLOCK_SIZE					16		// U8
#define	SC_ARIA_IV_SIZE						16		// U8

#define	SC_ARIA_MAX_BLOCK_SIZE			    16	
#define	SC_ARIA_MAX_IV_SIZE				    16	

/* structure */
typedef struct {
	int			modeID;
	int			paddingID;
	
	U8		iv[SC_ARIA_MAX_IV_SIZE];
	U32		ivLength;

	// user key
	U8		key[SC_ARIA_MAX_KEY_SIZE];
	U32		keyLength;
	
	//for make key
	U32		rounds;
	U32		roundKey[16*(16+1)];

	// working buffer
	U8		remain[SC_ARIA_MAX_BLOCK_SIZE];
	U32		remainLength;

	U8		last[SC_ARIA_MAX_BLOCK_SIZE];
	U32		lastLength;
} SC_ARIA_CONTEXT;


#ifdef __cplusplus
extern "C" {
#endif

int SC_ARIA_Encrypt(U8 *output, 
				U32 *outputLength, 
				const U8 *input, 
				const U32 inputLength,
				const U8 *key, 
				const U32 keyLength,
				const U8 *iv, 
				const U32 ivLength,
				const int modeID, 
				const int paddingID );

int
SC_ARIA_Decrypt(U8 *output, 
				U32 *outputLength, 
				const U8 *input, 
				const U32 inputLength,
				const U8 *key, 
				const U32 keyLength,
				const U8 *iv, 
				const U32 ivLength,
				const int modeID, 
				const int paddingID);

int
SC_ARIA_Encrypt_Init(SC_ARIA_CONTEXT *ctx,
					 const U8 *key, 
					 const U32 keyLength,
					 const U8 *iv, 
					 const U32 ivLength,
					 const U32 modeID,
					 const U32 paddingID);

int
SC_ARIA_Encrypt_Update(SC_ARIA_CONTEXT *ctx, 
					   U8 *output, 
					   U32 *outputLength,
					   const U8 *input, 
					   const U32 inputLength);

int
SC_ARIA_Encrypt_Final(SC_ARIA_CONTEXT *ctx, 
					  U8 *output, 
					  U32 *outputLength);

int 
SC_ARIA_Decrypt_Init(SC_ARIA_CONTEXT *ctx, 
					 const U8 *key, 
					 const U32 keyLength,
					 const U8 *iv, 
					 const U32 ivLength,
					 const U32 modeID,
					 const U32 paddingID);

int
SC_ARIA_Decrypt_Update(SC_ARIA_CONTEXT *ctx, 
					   U8 *output, 
					   U32 *outputLength,
					   const U8 *input, 
					   const U32 inputLength);

int
SC_ARIA_Decrypt_Final(SC_ARIA_CONTEXT *ctx,
					U32 *paddingLength);

int
SC_ARIA_Decrypt(U8 *output, 
				U32 *outputLength, 
				const U8 *input, 
				const U32 inputLength,
				const U8 *key, 
				const U32 keyLength,
				const U8 *iv, 
				const U32 ivLength,
				const int modeID, 
				const int paddingID);

#ifdef __cplusplus
}
#endif

#endif
