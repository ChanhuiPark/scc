/*
========================================
scc_aria.c
: aria algorithm
: KS X 1213-1:2014, KS X 1213-2:2014
----------------------------------------
Softcamp(c).
2015.10.
========================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scc_aria.h"
#include "scc_aria_tab.h"
#include "scc_error.h"
#include "scc_util.h"

/**
*
*	Diffusion Layer
*
*/
void
DL(const U8 *i, U8 *o)
{
	U8 T;

	T = i[3] ^ i[4] ^ i[9] ^ i[14];
	o[0] = i[6] ^ i[8] ^ i[13] ^ T;
	o[5] = i[1] ^ i[10] ^ i[15] ^ T;
	o[11] = i[2] ^ i[7] ^ i[12] ^ T;
	o[14] = i[0] ^ i[5] ^ i[11] ^ T;
	T = i[2] ^ i[5] ^ i[8] ^ i[15];
	o[1] = i[7] ^ i[9] ^ i[12] ^ T;
	o[4] = i[0] ^ i[11] ^ i[14] ^ T;
	o[10] = i[3] ^ i[6] ^ i[13] ^ T;
	o[15] = i[1] ^ i[4] ^ i[10] ^ T;
	T = i[1] ^ i[6] ^ i[11] ^ i[12];
	o[2] = i[4] ^ i[10] ^ i[15] ^ T;
	o[7] = i[3] ^ i[8] ^ i[13] ^ T;
	o[9] = i[0] ^ i[5] ^ i[14] ^ T;
	o[12] = i[2] ^ i[7] ^ i[9] ^ T;
	T = i[0] ^ i[7] ^ i[10] ^ i[13];
	o[3] = i[5] ^ i[11] ^ i[14] ^ T;
	o[6] = i[2] ^ i[9] ^ i[12] ^ T;
	o[8] = i[1] ^ i[4] ^ i[15] ^ T;
	o[13] = i[3] ^ i[6] ^ i[8] ^ T;
}

/**
*
*	Right-rotate 128 bit source string s by n bits and XOR it to target string t
*
*/
void
RotXOR(const U8 *s, int n, U8 *t)
{
	int i, q;

	q = n / 8; n %= 8;
	for (i = 0; i < 16; i++) {
		t[(q + i) % 16] ^= (s[i] >> n);
		if (n != 0) t[(q + i + 1) % 16] ^= (s[i] << (8 - n));
	}
}

/**
*
*
*
*/
int
SC_ARIA_MakeKey(SC_ARIA_CONTEXT *ariaKey,
	const U8 *key,
	const U32 keyLength,
	const int dir)
{
	U8	tempKey[SC_ARIA_MAX_KEY_SIZE];
	U8	t[16], w1[16], w2[16], w3[16];
	U8 *w0, *rk;
	int		i, j, R;

	if ((ariaKey == NULL) || (key == NULL))
		return SCC_ARIA_ERROR_INVALID_INPUT;

	if (keyLength < SC_ARIA_MIN_KEY_SIZE || keyLength > SC_ARIA_MAX_KEY_SIZE) {
		return SCC_ARIA_ERROR_KEY_LENGTH;
	}
	else if ((16 <= keyLength) && (keyLength < 24)) {
		ariaKey->rounds = R = 12;
		ariaKey->keyLength = 16;
		memcpy(tempKey, key, 16);
	}
	else if ((24 <= keyLength) && (keyLength < 32)) {
		ariaKey->rounds = R = 14;
		ariaKey->keyLength = 24;
		memcpy(tempKey, key, 24);
	}
	else {
		ariaKey->rounds = R = 16;
		ariaKey->keyLength = 32;
		memcpy(tempKey, key, 32);
	}

	rk = (U8 *)ariaKey->roundKey;
	w0 = (U8 *)tempKey;

	if (R == 12) {
		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_12[i] ^ w0[i]];
		DL(t, w1);

		for (i = 0; i < 16; i++) t[i] = S[(2 + i) % 4][KRK_12[i + 16] ^ w1[i]];
		DL(t, w2);
		for (i = 0; i < 16; i++) w2[i] ^= w0[i];

		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_12[i + 32] ^ w2[i]];
	}
	else if (R == 14) {
		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_14[i] ^ w0[i]];
		DL(t, w1);

		for (i = 0; i < 8; i++) w1[i] ^= w0[16 + i];

		for (i = 0; i < 16; i++) t[i] = S[(2 + i) % 4][KRK_14[i + 16] ^ w1[i]];
		DL(t, w2);
		for (i = 0; i < 16; i++) w2[i] ^= w0[i];

		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_14[i + 32] ^ w2[i]];
	}
	else {
		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_16[i] ^ w0[i]];
		DL(t, w1);

		for (i = 0; i < 16; i++) w1[i] ^= w0[16 + i];

		for (i = 0; i < 16; i++) t[i] = S[(2 + i) % 4][KRK_16[i + 16] ^ w1[i]];
		DL(t, w2);
		for (i = 0; i < 16; i++) w2[i] ^= w0[i];

		for (i = 0; i < 16; i++) t[i] = S[i % 4][KRK_16[i + 32] ^ w2[i]];
	}

	DL(t, w3);
	for (i = 0; i < 16; i++) w3[i] ^= w1[i];

	for (i = 0; i < 16 * (R + 1); i++) rk[i] = 0;

	RotXOR(w0, 0, rk); RotXOR(w1, 19, rk);
	RotXOR(w1, 0, rk + 16); RotXOR(w2, 19, rk + 16);
	RotXOR(w2, 0, rk + 32); RotXOR(w3, 19, rk + 32);
	RotXOR(w3, 0, rk + 48); RotXOR(w0, 19, rk + 48);
	RotXOR(w0, 0, rk + 64); RotXOR(w1, 31, rk + 64);
	RotXOR(w1, 0, rk + 80); RotXOR(w2, 31, rk + 80);
	RotXOR(w2, 0, rk + 96); RotXOR(w3, 31, rk + 96);
	RotXOR(w3, 0, rk + 112); RotXOR(w0, 31, rk + 112);
	RotXOR(w0, 0, rk + 128); RotXOR(w1, 67, rk + 128);
	RotXOR(w1, 0, rk + 144); RotXOR(w2, 67, rk + 144);
	RotXOR(w2, 0, rk + 160); RotXOR(w3, 67, rk + 160);
	RotXOR(w3, 0, rk + 176); RotXOR(w0, 67, rk + 176);
	RotXOR(w0, 0, rk + 192); RotXOR(w1, 97, rk + 192);

	if (R > 12) {
		RotXOR(w1, 0, rk + 208); RotXOR(w2, 97, rk + 208);
		RotXOR(w2, 0, rk + 224); RotXOR(w3, 97, rk + 224);

		if (R > 14) {
			RotXOR(w3, 0, rk + 240); RotXOR(w0, 97, rk + 240);
			RotXOR(w0, 0, rk + 256); RotXOR(w1, 109, rk + 256);
		}
	}

	if (dir == SC_ARIA_DIR_DECRYPT) {
		for (j = 0; j < 16; j++) {
			t[j] = rk[j];
			rk[j] = rk[16 * R + j];
			rk[16 * R + j] = t[j];
		}
		for (i = 1; i <= R / 2; i++) {
			DL(rk + i * 16, t);
			DL(rk + (R - i) * 16, rk + i * 16);
			for (j = 0; j < 16; j++) rk[(R - i) * 16 + j] = t[j];
		}
	}

	// 임시키 제로화
	SC_Memzero(tempKey, 0x00, sizeof(tempKey));
	SC_Memzero(t, 0x00, sizeof(t));

	return 0;
}

/**
*
*
*
*/
static
int
SC_ARIA_Main(U8 output[16],
	const U8 input[16],
	const SC_ARIA_CONTEXT *ariaKey)
{
	int i, j;
	int retCode = 0;
	U8 t[16];

	int R = 0;
	U8 *roundKey = NULL;

	if ((ariaKey == NULL) || (output == NULL) || (input == NULL)) {
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	R = ariaKey->rounds;
	roundKey = (U8 *)ariaKey->roundKey;

	for (j = 0; j < 16; j++) output[j] = input[j];
	for (i = 0; i < R / 2; i++)
	{
		for (j = 0; j < 16; j++) t[j] = S[j % 4][roundKey[j] ^ output[j]];
		DL(t, output); roundKey += 16;
		for (j = 0; j < 16; j++) t[j] = S[(2 + j) % 4][roundKey[j] ^ output[j]];
		DL(t, output); roundKey += 16;
	}
	DL(output, t);
	for (j = 0; j < 16; j++) output[j] = roundKey[j] ^ t[j];

	retCode = 0;

end:
	return retCode;
}

/**
*
*
*
*/
static
int
SC_ARIA_Padding(U8 *data,
	const U32 dataLength,
	const int padding,
	const U32 blockSize)
{
	U32	paddingLength, i;

	paddingLength = blockSize - (dataLength % blockSize);

	switch (padding) {
	case SCC_CIPHER_PADDING_NO:
		paddingLength = 0;
		break;

	case SCC_CIPHER_PADDING_ZERO:
		for (i = 0; i<paddingLength; i++)
			data[dataLength + i] = 0x00;
		break;

	case SCC_CIPHER_PADDING_HASH:
		data[dataLength] = 0x80;
		for (i = 1; i<paddingLength; i++)
			data[dataLength + i] = 0x00;
		break;

	case SCC_CIPHER_PADDING_PKCS:
		for (i = 0; i<paddingLength; i++)
			data[dataLength + i] = paddingLength;
		break;
	}

	return (dataLength + paddingLength);
}

/**
*
*	RETURN
*		paddingLength
*		WK_CIPHER_ERROR_INVALID_PADDING
*
*/
static
int
SC_ARIA_GetPaddingLength(U8 *input,
	const U32 inputLength,
	const int padding,
	const U32 blockSize)
{
	U32	paddingLength, i;

	paddingLength = 0;

	switch (padding) {
	case SCC_CIPHER_PADDING_NO:
		break;

	case SCC_CIPHER_PADDING_HASH:
		i = 0;
		while ((i < blockSize - 1) && (input[(inputLength - 1) - i] == 0x00))
			i++;

		if (input[(inputLength - 1) - i] != 0x80)
			return SCC_ARIA_ERROR_INVALID_PADDING;

		paddingLength = i + 1;
		break;

	case SCC_CIPHER_PADDING_PKCS:
		paddingLength = input[inputLength - 1];

		if ((paddingLength < 1) || (blockSize < paddingLength))
			return SCC_ARIA_ERROR_INVALID_PADDING;

		for (i = 1; i<paddingLength; i++)
			if (input[(inputLength - 1) - i] != paddingLength)
				return SCC_ARIA_ERROR_INVALID_PADDING;
		break;
	}

	return paddingLength;
}

/**
*
*	NOTE: The input and output can point to the same location.
*
*/
static
int
SC_ARIA_CBC(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength,
	const int dir)
{
	U8		iv[SC_ARIA_MAX_IV_SIZE], nextiv[SC_ARIA_MAX_IV_SIZE];
	U32		blockSize, i, j;
	int	retCode = 0;

	blockSize = SC_ARIA_BLOCK_SIZE;

	SC_Memzero(iv, 0, sizeof(iv));
	memcpy(iv, ctx->iv, ctx->ivLength);

	if (dir == SC_ARIA_DIR_ENCRYPT) {
		//	C_0 = IV.
		//	For 1<=i<=t, C_{i} = E(C_{i-1} xor P_{i}).
		//
		for (i = 0; i < inputLength; i += blockSize) {
			for (j = 0; j < blockSize; j++)
				iv[j] ^= input[j];

			retCode = SC_ARIA_Main(output, iv, ctx);
			if (retCode != 0) goto end;

			memcpy(iv, output, blockSize);

			input += blockSize;
			output += blockSize;
		}
	}
	else {
		//	C_0 = IV.
		//	For 1<=i<=t, P_{i} = C_{i-1} xor D(C_{i}).
		//
		for (i = 0; i < inputLength; i += blockSize) {
			memcpy(nextiv, input, blockSize);

			retCode = SC_ARIA_Main(output, input, ctx);
			if (retCode != 0) goto end;

			for (j = 0; j < blockSize; j++)
				output[j] ^= iv[j];

			memcpy(iv, nextiv, blockSize);

			input += blockSize;
			output += blockSize;
		}
	}

	memcpy(ctx->iv, iv, blockSize);

	*outputLength = inputLength;

	retCode = 0;

end:
	return retCode;
}

/**
*
*
*
*/
static
int
SC_ARIA_CTR(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength,
	const int dir)
{
	U8		iv[SC_ARIA_MAX_IV_SIZE];
	U32		blockSize, length = 16, i, j;
	int	retCode;

	blockSize = SC_ARIA_BLOCK_SIZE;

	SC_Memzero(iv, 0, sizeof(iv));
	memcpy(iv, ctx->iv, ctx->ivLength);

	for (i = 0; i < inputLength; i += blockSize) {
		U32		carry = 1;

		retCode = SC_ARIA_Main(output, iv, ctx);
		if (retCode != 0) goto end;

		for (j = 0; j < blockSize; j++)
			output[j] ^= input[j];

		for (j = ctx->ivLength - 1; ; j--) {
			U8 T = iv[j] + carry;
			carry = !T;
			iv[j] = T;

			if (carry == 0 || j == 0)  break;
		}

		memcpy(ctx->iv, iv, ctx->ivLength);

		input += blockSize;
		output += length;
	}

	*outputLength = inputLength;

	retCode = 0;

end:
	return retCode;
}

/**
*
*
*
*/
static
int
SC_ARIA_Mode(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength,
	const int dir)
{
	int	retCode = 0;

	switch (ctx->modeID) {
	case SCC_CIPHER_MODE_CTR:
		retCode = SC_ARIA_CTR(ctx, output, outputLength, input, inputLength, dir);
		break;

	case SCC_CIPHER_MODE_CBC:
		retCode = SC_ARIA_CBC(ctx, output, outputLength, input, inputLength, dir);
		break;
	}

	return retCode;
}

/**
*
*
*/
int
SC_ARIA_Encrypt_Init(SC_ARIA_CONTEXT *ctx,
	const U8 *key,
	const U32 keyLength,
	const U8 *iv,
	const U32 ivLength,
	const U32 modeID,
	const U32 paddingID)
{
	int	retCode = 0;

	if ((ctx == NULL) || (key == NULL) || (iv == NULL))
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	if (ivLength != SC_ARIA_IV_SIZE)
	{
		retCode = SCC_ARIA_ERROR_IV_LENGTH;
		goto end;
	}

	SC_Memzero(ctx, 0, sizeof(SC_ARIA_CONTEXT));

	// STEP 1 : set mode and padding.
	ctx->modeID = modeID;
	ctx->paddingID = paddingID;

	// STEP 2 : set iv
	memcpy(ctx->iv, iv, ivLength);
	ctx->ivLength = ivLength;

	// STEP 3 : Generate subkey of aria.
	retCode = SC_ARIA_MakeKey(ctx, key, keyLength, SC_ARIA_DIR_ENCRYPT);
	if (retCode != 0) goto end;

	retCode = 0;

end:
	if (retCode < 0 && ctx != NULL)
		SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));

	return retCode;
}

/**
*
*
*/
int
SC_ARIA_Encrypt_Update(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength)
{
	U8		temp[SC_ARIA_MAX_BLOCK_SIZE];
	U32		blockSize;
	U32		inPos, outPos, inLen, length;
	int		retCode = 0;

	if ((ctx == NULL) || (output == NULL) || (outputLength == NULL) || (input == NULL))
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	if (inputLength < 0)
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}


	blockSize = SC_ARIA_BLOCK_SIZE;

	// STEP 1 : block cipher
	inPos = outPos = 0;

	if (ctx->remainLength) {
		memcpy(temp, ctx->remain, ctx->remainLength);
		memcpy(temp + ctx->remainLength, input, (blockSize - ctx->remainLength));

		retCode = SC_ARIA_Mode(ctx, output, &length, temp, blockSize, SC_ARIA_DIR_ENCRYPT);
		if (retCode != 0) goto end;

		inPos += (blockSize - ctx->remainLength);
		outPos += blockSize;
	}

	// STEP 1.2 :
	//
	inLen = ((inputLength - inPos) / blockSize) * blockSize;

	retCode = SC_ARIA_Mode(ctx, output + outPos, &length, input + inPos, inLen, SC_ARIA_DIR_ENCRYPT);
	if (retCode != 0) goto end;

	inPos += inLen;
	outPos += inLen;

	// STEP 1.3 :
	//

	ctx->remainLength = 0;
	if (inPos < inputLength) {
		ctx->remainLength = inputLength - inPos;
		memcpy(ctx->remain, input + inPos, ctx->remainLength);
	}

	*outputLength = outPos;
	retCode = 0;

end:
	if (retCode < 0) {
		// 출력값 제로화
		if (ctx != NULL)
			SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));
		SC_Memzero(output, 0x00, inputLength + SC_ARIA_BLOCK_SIZE);
	}
	return retCode;
}

/**
*
*/
int
SC_ARIA_Encrypt_Final(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength)
{
	U8		temp[SC_ARIA_MAX_BLOCK_SIZE];
	U32		blockSize = SC_ARIA_BLOCK_SIZE;
	int		retCode = 0;


	if ((ctx == NULL) || (output == NULL) || (outputLength == NULL)) {
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	// STEP 2 : block cipher
	//
	if (ctx->paddingID == SCC_CIPHER_PADDING_NO) {
		if (ctx->remainLength)
			return SCC_ARIA_ERROR_ENCRYPT_FAILED;

		else {
			*outputLength = 0;
			return 0;
		}
	}

	memcpy(temp, ctx->remain, ctx->remainLength);
	retCode = SC_ARIA_Padding(temp, ctx->remainLength, ctx->paddingID, blockSize);
	if (retCode < 0)
		goto end;

	ctx->remainLength = 0;

	retCode = SC_ARIA_Encrypt_Update(ctx, output, outputLength, temp, blockSize);
	if (retCode != 0) goto end;

	retCode = 0;

end:
	if (retCode < 0) {
		// 키제로화
		SC_Memzero(output, 0x00, blockSize);
	}

	if (ctx != NULL)
		SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));

	return retCode;
}

/**
*
*
*/
int
SC_ARIA_Encrypt(U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength,
	const U8 *key,
	const U32 keyLength,
	const U8 *iv,
	const U32 ivLength,
	const int modeID,
	const int paddingID)
{
	SC_ARIA_CONTEXT ariaCTX;
	U32		length;
	int		retCode = 0;

	retCode = SC_ARIA_Encrypt_Init(&ariaCTX, key, keyLength, iv, ivLength, modeID, paddingID);
	if (retCode != 0) goto end;

	retCode = SC_ARIA_Encrypt_Update(&ariaCTX, output, outputLength, input, inputLength);
	if (retCode != 0) goto end;

	retCode = SC_ARIA_Encrypt_Final(&ariaCTX, output + *outputLength, &length);
	if (retCode != 0) goto end;

	*outputLength += length;

	retCode = 0;

end:
	if (retCode < 0) {
		// 키제로화
		SC_Memzero(output, 0x00, inputLength + SC_ARIA_BLOCK_SIZE);
	}

	return retCode;
}

/**
*
*
*/
int
SC_ARIA_Decrypt_Init(SC_ARIA_CONTEXT *ctx,
	const U8 *key,
	const U32 keyLength,
	const U8 *iv,
	const U32 ivLength,
	const U32 modeID,
	const U32 paddingID)
{
	int	retCode = 0;

	if ((ctx == NULL) || (key == NULL) || (iv == NULL))
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	if (ivLength != SC_ARIA_IV_SIZE) {
		retCode = SCC_ARIA_ERROR_IV_LENGTH;
		goto end;
	}

	SC_Memzero(ctx, 0, sizeof(SC_ARIA_CONTEXT));

	// STEP 1 : set mode and padding.
	ctx->modeID = modeID;
	ctx->paddingID = paddingID;

	// STEP 2 : set iv
	memcpy(ctx->iv, iv, ivLength);
	ctx->ivLength = ivLength;

	// STEP 3 : Generate subkey of aria.
	if (ctx->modeID == SCC_CIPHER_MODE_CTR) {
		retCode = SC_ARIA_MakeKey(ctx, key, keyLength, SC_ARIA_DIR_ENCRYPT);
	}
	else {
		retCode = SC_ARIA_MakeKey(ctx, key, keyLength, SC_ARIA_DIR_DECRYPT);
	}
	if (retCode != 0) goto end;

	retCode = 0;

end:
	if (retCode < 0 && ctx != NULL)
	{
		SC_Memzero(ctx, 0, sizeof(SC_ARIA_CONTEXT));
	}
	return retCode;
}

/**
*
*
*/

int
SC_ARIA_Decrypt_Update(SC_ARIA_CONTEXT *ctx,
	U8 *output,
	U32 *outputLength,
	const U8 *input,
	const U32 inputLength)
{
	U8		temp[SC_ARIA_MAX_BLOCK_SIZE];
	U32		blockSize;
	U32		inPos, outPos, inLen, length;
	int		retCode = 0;

	if ((ctx == NULL) || (output == NULL) || (input == NULL))
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	if (inputLength < 0)
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	blockSize = SC_ARIA_BLOCK_SIZE;

	// STEP 1.1 : if data is remained in last operation, then do with new data.
	//
	
	inPos = outPos = 0;
	
	if (ctx->remainLength) {
		memcpy(temp, ctx->remain, ctx->remainLength);

		memcpy(temp + ctx->remainLength, input, (blockSize - ctx->remainLength));

		retCode = SC_ARIA_Mode(ctx, output, &length, temp, blockSize,
			SC_ARIA_DIR_DECRYPT);
		if (retCode != 0) goto end;

		inPos += (blockSize - ctx->remainLength);
		outPos += blockSize;
	}
	
	// STEP 1.2 : 
	//
	inLen = ((inputLength - inPos) / blockSize) * blockSize;


	retCode = SC_ARIA_Mode(ctx, output + outPos, &length, input + inPos, inLen,
		SC_ARIA_DIR_DECRYPT);
	if (retCode != 0) goto end;

	inPos += inLen;
	outPos += inLen;

	// STEP 1.3 : if input is remained, then save remain data to buffer.
	//			else (not remained), then copy last plaintext to buffer for
	//			verifing padding length in final.
	//

	ctx->remainLength = 0;
	if (inPos < inputLength) {
		ctx->remainLength = inputLength - inPos;
		memcpy(ctx->remain, input + inPos, ctx->remainLength);
	}
	else {
		ctx->lastLength = blockSize;
		memcpy(ctx->last, output + outPos - blockSize, blockSize);
	}

	*outputLength = outPos;

	retCode = 0;

end:
	if (retCode < 0) {
		// 키제로화
		if (ctx != NULL)
			SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));
		SC_Memzero(output, 0x00, inputLength + SC_ARIA_BLOCK_SIZE);
	}
	return retCode;
}

/**
*
*
*/
int
SC_ARIA_Decrypt_Final(SC_ARIA_CONTEXT *ctx,
	U32 *paddingLength)
{
	int			length;
	int			retCode = 0;

	if ((ctx == NULL) || (paddingLength == NULL))
		return SCC_ARIA_ERROR_INVALID_INPUT;

	*paddingLength = 0;

	// STEP 1 : block cipher
	//
	if (ctx->remainLength) {
		retCode = SCC_ARIA_ERROR_DECRYPT_FAILED;
		goto end;
	}

	if (ctx->paddingID == SCC_CIPHER_PADDING_NO) {
		retCode = 0;
		goto end;
	}

	length = SC_ARIA_GetPaddingLength(ctx->last, ctx->lastLength,
		ctx->paddingID, SC_ARIA_BLOCK_SIZE);
	if (length < 0) {
		retCode = SCC_ARIA_ERROR_INVALID_PADDING;
		goto end;
	}

	*paddingLength = length;

	retCode = 0;

end:
	if (retCode < 0) {
		// 키제로화
		SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));
	}

	if (ctx != NULL)
		SC_Memzero(ctx, 0x00, sizeof(SC_ARIA_CONTEXT));

	return retCode;
}

/**
*
*
*/
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
	const int paddingID)
{
	SC_ARIA_CONTEXT ariaCTX;
	U32		length;
	int		retCode = 0;

	if ((output == NULL) || (outputLength == NULL) || (input == NULL) ||
		(key == NULL) || (iv == NULL))
	{
		retCode = SCC_ARIA_ERROR_INVALID_INPUT;
		goto end;
	}

	retCode = SC_ARIA_Decrypt_Init(&ariaCTX, key, keyLength, iv, ivLength, modeID, paddingID);
	if (retCode != 0) goto end;

	retCode = SC_ARIA_Decrypt_Update(&ariaCTX, output, outputLength, input, inputLength);
	if (retCode != 0) goto end;

	retCode = SC_ARIA_Decrypt_Final(&ariaCTX, &length);
	if (retCode != 0) goto end;

	*outputLength -= length;

	retCode = 0;

end:
	if (retCode < 0) {
		SC_Memzero(output, 0x00, inputLength + SC_ARIA_BLOCK_SIZE);
	}

	return retCode;
}
