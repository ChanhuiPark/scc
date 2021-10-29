/* 
========================================
  scc_drbg.c
    : random algorithm
	: TTAK.KO-12.0190:2012, Deterministic Random Bit Generator - Part 2 : 
	  Deterministic Random Bit Generator Based On Hash Function
    : ISO/IEC 18031:2011, Information technology Security techniques Random bit generation
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/
#include <string.h>
#include <stdlib.h>
#include "scc_cmvp.h"
#include "scc_drbg.h"
#include "scc_sha256.h"
#include "scc_entropy.h"
#include "scc_error.h"
#include "scc_util.h"
#include "scc_malloc.h"

static 
int 
SC_Hash_Df(U8 *output, U32 *outputLen, U8 *seed, U32 seedLen)
{
    // 1. temp = the Null string.
    // 2. .
    // 3. counter = an 8-bit binary value representing the integer "1".
    // 4. For i = 1 to len do
    // Comment : In step 4.1, no_of_bits_to_return
    // is used as a 32-bit string.
    // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
    // input_string).
    // 4.2 counter = counter + 1.
    // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    // 6. Return SUCCESS and requested_bits.

    U8 *temp = NULL;
	U8 dig[SCC_SHA256_DIGEST_SIZE];
	U8 buf[5];
    int counter, tempLen;
	SC_SHA256_CONTEXT ctx;
	int i;
	int retCode;

	tempLen = 2*SCC_SHA256_DIGEST_SIZE;
	temp = (U8 *)sc_malloc(tempLen);
	if(temp == NULL){
		retCode = SCC_HASHDRBG_ERROR_MALLOC_FAILED;
		goto end;
	}
	
	counter = 1;
    for (i = 0; i <= 1; i++)
    {
		SC_Memzero(&ctx, 0, sizeof(SC_SHA256_CONTEXT));

		retCode = SC_SHA256_Init(&ctx);
		if(retCode != 0) goto end;
		
		buf[0] = (U8)counter;
		SC_Uint32ToByte (buf+1, SC_HashDRBG_SEED_LEN_BIT);

		retCode = SC_SHA256_Update(&ctx, buf, 5);
		if(retCode != 0) goto end;

		retCode = SC_SHA256_Update(&ctx, seed, seedLen);
		if(retCode != 0) goto end;

		retCode = SC_SHA256_Final(&ctx, dig);
		if(retCode != 0) goto end;
	
		memcpy(temp + (i*SCC_SHA256_DIGEST_SIZE), dig, SCC_SHA256_DIGEST_SIZE);

        counter++;
    }
	
	memcpy(output, temp, SC_HashDRBG_SEED_LEN);
	*outputLen = SC_HashDRBG_SEED_LEN;

	retCode = 0;
end:
	if(temp!=NULL)
		sc_free(temp);

	return retCode;
}

/**
* Reseed the DRBG.
*
* @param additionalInput additional input to be added to the DRBG in this step.
*/
int SC_HashDRBG_Reseed(SC_HashDRBG_CONTEXT *ctx, const U8 *addInput, const U32 addInputLen)
{
	// 1. seed_material = 0x01 || V || entropy_input || additional_input.
	//
	// 2. seed = Hash_df (seed_material, seedlen).
	//
	// 3. V = seed.
	//
	// 4. C = Hash_df ((0x00 || V), seedlen).
	//
	// 5. reseed_counter = 1.
	//
	// 6. Return V, C, and reseed_counter for the new_working_state.
	//
	// Comment: Precede with a byte of all zeros.
	U8 seedMaterial[SC_HashDRBG_MATERIAL_MAX_SIZE]={0x00,};
	U8 dfBuf[SC_HashDRBG_SEED_LEN]={0x00,}, dfBuf1[SC_HashDRBG_SEED_LEN+1]={0x00,};
	int pos, dfBufLen;
	SC_ENTROPY_CTX entropy;
	int retCode;
	
	SC_Memzero(&entropy, 0, sizeof(SC_ENTROPY_CTX));

	// for selftest
	if (SC_CMVP_GetStatus() == SCC_STATUS_SELFTEST) {
		extern U8 _entropy2[55];
		memcpy(entropy.data, _entropy2, 55);
		entropy.dataLength = 55;
		entropy.pos = 55;
	}
	else {
		retCode = SC_Entropy_Accumulate(&entropy);	
		if (retCode != 0) goto end;
	}

	pos =0;

	seedMaterial[pos++] = 0x01;

	//concate
	if((addInputLen) <= SC_HashDRBG_MATERIAL_MAX_SIZE){
		memcpy(seedMaterial + pos, ctx->V, ctx->vLen);
		pos += ctx->vLen;
		memcpy(seedMaterial + pos, entropy.data, entropy.dataLength);
		pos += entropy.dataLength;
		memcpy(seedMaterial + pos, addInput, addInputLen);
		pos += addInputLen;
	}else{
		retCode = SCC_HASHDRBG_ERROR_INVALID_INPUTLEN;
		goto end;
	}
	
	retCode = SC_Hash_Df (dfBuf, &dfBufLen, seedMaterial, pos);
	if (retCode != 0) goto end;

	memcpy(ctx->V , dfBuf, dfBufLen);
	
	dfBuf1[0] = 0x00;
	memcpy(dfBuf1+1, dfBuf, dfBufLen);
	retCode = SC_Hash_Df (ctx->C, &ctx->cLen, dfBuf1, dfBufLen+1);
	if (retCode != 0) goto end;

	ctx->reseedCounter = 1;

end:
	// 엔트로피 제로화
	SC_Memzero(&entropy, 0, sizeof(SC_ENTROPY_CTX));

	return retCode;
}

static 
int 
SC_HashDRBG_AddTo(U8 *dst, U32 dstlen, const U8 *add, U32 addlen)
{
	/* implied: dstlen > addlen */
	U8 *dstptr;
	const U8 *addptr;
	U32 remainder = 0;
	U32 len = addlen;

	dstptr = dst + (dstlen-1);
	addptr = add + (addlen-1);
	while (len) {
		remainder += *dstptr + *addptr;
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--; addptr--;
	}
	
	len = dstlen - addlen;
	while (len && remainder > 0) {
		remainder = *dstptr + 1;
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--;
	}

	return 0;
}


int SC_HashDRBG_Hashgen(U8 *output, const U32 lengthInBits, const U8 *input, const U32 inputLen)
{
	// 1. m = [requested_number_of_bits / outlen]
	// 2. data = V.
	// 3. W = the Null string.
	// 4. For i = 1 to m
	// 4.1 wi = Hash (data).
	// 4.2 W = W || wi.
	// 4.3 data = (data + 1) mod 2^seedlen
	// .
	// 5. returned_bits = Leftmost (requested_no_of_bits) bits of W.
	U8 *data = NULL;
	U8 *W = NULL;
	U8 dig[SCC_SHA256_DIGEST_SIZE];
	U8 oneNum[1];
	int m, digLen, dataLen, bytesToCopy, WLen;
	int i;
	int retCode;
	
	m = (lengthInBits / 8)  / SCC_SHA256_DIGEST_SIZE;
    data = (U8 *)sc_malloc(inputLen);
	dataLen = inputLen;

	memcpy (data, input, inputLen);
	
	WLen = lengthInBits / 8;
	W = (U8 *)sc_malloc(WLen);
	if (W == NULL) {
		retCode = SCC_HASHDRBG_ERROR_MALLOC_FAILED;
		goto end;
	}

	for (i = 0; i <= m; i++)
	{
		retCode = SC_SHA256_Digest(dig, &digLen, data, dataLen);
		if(retCode != 0) goto end;
		
		bytesToCopy = ((WLen - i * digLen) > digLen) ? digLen : (WLen - i * digLen);
		memcpy(output + (i * digLen),  dig, bytesToCopy);

		oneNum[0] = 0x01;
		retCode = SC_HashDRBG_AddTo(data, dataLen, oneNum, 1);
		if(retCode != 0) goto end;
	}

	retCode = 0;
end:
	if(data!=NULL)
		sc_free(data);
	if(W!=NULL)
		sc_free(W);
	return retCode;
}

int SC_HashDRBG_Init( SC_HashDRBG_CONTEXT *ctx, U8 *personalStr, U32 personalStrLen, U8 *nonce, U32 nonceLen)
{
	// 1. seed_material = entropy_input || nonce || personalization_string.
	// 2. seed = Hash_df (seed_material, seedlen).
	// 3. V = seed.
	// 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
	// of zeros.
	// 5. reseed_counter = 1.
	// 6. Return V, C, and reseed_counter as the initial_working_state
	U8 seedMaterial[SC_HashDRBG_MATERIAL_MAX_SIZE]={0x00,};
	U8 dfBuf[SC_HashDRBG_SEED_LEN]={0x00,}, dfBuf1[SC_HashDRBG_SEED_LEN+1]={0x00,};
	int pos, dfBufLen;
	SC_ENTROPY_CTX entropy;
	int retCode;

	if(ctx == NULL || nonce == NULL){
		retCode = SCC_HASHDRBG_ERROR_INVALID_INPUT;
		goto end;
	}

	//if(nonceLen == 0) {
		//retCode = SCC_HASHDRBG_ERROR_INVALID_INPUTLEN;
		//goto end;
	//}
	
	SC_Memzero(&entropy, 0, sizeof(SC_ENTROPY_CTX));

	// for selftest
	if (SC_CMVP_GetStatus() == SCC_STATUS_SELFTEST) {
		extern U8 _entropy1[55];
		memcpy(entropy.data, _entropy1, 55);
		entropy.dataLength = 55;
		entropy.pos = 55;
	}

	else {
 		retCode = SC_Entropy_Accumulate(&entropy);	
		if (retCode != 0) goto end;
	}

	pos =0;  

	//concate
	if((personalStrLen+nonceLen) <= SC_HashDRBG_MATERIAL_MAX_SIZE){
		memcpy(seedMaterial, entropy.data, entropy.dataLength);
		pos += entropy.dataLength;
		memcpy(seedMaterial + pos, nonce, nonceLen);
		pos += nonceLen;
		memcpy(seedMaterial + pos, personalStr, personalStrLen);
		pos += personalStrLen;
	}else{
		retCode = SCC_HASHDRBG_ERROR_INVALID_INPUTLEN;
		goto end;
	}

    retCode = SC_Hash_Df (dfBuf, &dfBufLen, seedMaterial, pos);
	if (retCode != 0) goto end;

	memcpy(ctx->V , dfBuf, dfBufLen);
	ctx->vLen = dfBufLen;

	dfBuf1[0] = 0x00;
	memcpy(dfBuf1+1, dfBuf, dfBufLen);
	retCode = SC_Hash_Df (ctx->C, &ctx->cLen, dfBuf1, dfBufLen+1);
	if (retCode != 0) goto end;

	ctx->reseedCounter = 1;

	retCode = 0;

end:
	// 엔트로피 제로화
	SC_Memzero(&entropy, 0, sizeof(SC_ENTROPY_CTX));

	return retCode;
}


int 
SC_HashDRBG_Generate(SC_HashDRBG_CONTEXT *ctx, U8 *output, const U32 outputLen, const U8 *addInput, const int addInputLen, const int predictionResistant)
{
	// 1. If reseed_counter > reseed_interval, then return an indication that a
	// reseed is required.
	// 2. If (additional_input != Null), then do
	// 2.1 w = Hash (0x02 || V || additional_input).
	// 2.2 V = (V + w) mod 2^seedlen
	// .
	// 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
	// 4. H = Hash (0x03 || V).
	// 5. V = (V + H + C + reseed_counter) mod 2^seedlen
	// .
	// 6. reseed_counter = reseed_counter + 1.
	// 7. Return SUCCESS, returned_bits, and the new values of V, C, and
	// reseed_counter for the new_working_state.
	
	U8 *newInput = NULL;
	U8 *subHash = NULL;
	U8 *rvOutput = NULL;
	U8 wHash[SCC_SHA256_DIGEST_SIZE];
	U8 hashOut[SCC_SHA256_DIGEST_SIZE];
	U8 counter[4];
	U32 newInputLen, wHashLen, hashOutLen;
	int retCode;
	int numberOfBits;

	if(ctx == NULL || output == NULL){
		retCode = SCC_HASHDRBG_ERROR_INVALID_INPUT;
		goto end;
	}

	//if (predictionResistant == 1)
	//{   
	//	SC_HashDRBG_Reseed(ctx, addInput, addInputLen);
	//	addInput = NULL;
	//}

	if (addInput != NULL)
	{
		newInputLen = 1 + ctx->vLen + addInputLen;
		newInput = (U8*)sc_malloc(newInputLen);
		if (newInput == NULL) {
			retCode = SCC_HASHDRBG_ERROR_MALLOC_FAILED;
			goto end;
		}
		newInput[0] = 0x02;
		memcpy(newInput + 1, ctx->V, ctx->vLen);

		memcpy(newInput + 1 + ctx->vLen, addInput, addInputLen);
		
		retCode = SC_SHA256_Digest(wHash, &wHashLen, newInput, newInputLen);
		if(retCode != 0) goto end;

		SC_HashDRBG_AddTo(ctx->V, ctx->vLen, wHash, wHashLen);
	}
	
	rvOutput = (U8 *)sc_malloc(outputLen);
	if (rvOutput == NULL) {
		retCode = SCC_HASHDRBG_ERROR_MALLOC_FAILED;
		goto end;
	}

	numberOfBits = outputLen*8;
	if (numberOfBits > SC_MAX_BITS_REQUEST)
	{
		retCode = SCC_HASHDRBG_ERROR_INVALID_LIMITREQ;
		goto end;
	}


 	retCode = SC_HashDRBG_Hashgen(rvOutput, numberOfBits, ctx->V, ctx->vLen);
	if(retCode != 0) goto end;

	subHash = (U8 *)sc_malloc(ctx->vLen + 1);
	if (subHash == NULL) {
		retCode = SCC_HASHDRBG_ERROR_MALLOC_FAILED;
		goto end;
	}
	memcpy(subHash + 1, ctx->V, ctx->vLen);
	subHash[0] = 0x03;
	
	retCode = SC_SHA256_Digest(hashOut, &hashOutLen, subHash, ctx->vLen + 1);
	if(retCode != 0) goto end;

	SC_HashDRBG_AddTo(ctx->V, ctx->vLen, hashOut, hashOutLen);
	SC_HashDRBG_AddTo(ctx->V, ctx->vLen, ctx->C, ctx->cLen);
	
	counter[0] = (U8)(ctx->reseedCounter >> 24);
	counter[1] = (U8)(ctx->reseedCounter >> 16);
	counter[2] = (U8)(ctx->reseedCounter >> 8);
	counter[3] = (U8) ctx->reseedCounter;

	SC_HashDRBG_AddTo(ctx->V, ctx->vLen, counter, 4);
	
	ctx->reseedCounter++;

	memcpy(output, rvOutput, outputLen);

	retCode = 0;
end:
	if(newInput!=NULL) {
		SC_Memzero(newInput, 0x00, newInputLen);
		newInputLen = 0;
		sc_free(newInput);
	}
	if(subHash!=NULL) {
		SC_Memzero(subHash, 0x00, ctx->vLen + 1);
		sc_free(subHash);
	}
	if(rvOutput!=NULL) {
		SC_Memzero(rvOutput, 0x00, outputLen);
		sc_free(rvOutput);
	}

	return retCode;
}