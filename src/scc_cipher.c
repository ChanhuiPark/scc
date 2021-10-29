/* 
========================================
  scc_cipher.c 
    : cipher function

----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdio.h>
#include <string.h>

#include "scc_cipher.h"
#include "scc_error.h"
#include "scc_malloc.h"
#include "scc_aria.h"
#include "scc_random.h"
#include "scc_cmvp.h"
#include "scc_util.h"

int
SC_Cipher_CheckModeID(int id)
{
	switch(id) {
	case SCC_CIPHER_MODE_CBC:
	case SCC_CIPHER_MODE_CTR:
		return 0;
	default:
		return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}
}

int
SC_Cipher_CheckPaddingID(int id)
{
	switch(id) {
	case SCC_CIPHER_PADDING_NO:
	case SCC_CIPHER_PADDING_ZERO:
	case SCC_CIPHER_PADDING_HASH:
	case SCC_CIPHER_PADDING_PKCS:
		return 0;
	default:
		return SCC_CIPHER_ERROR_UNKNOWN_PADDING;
	}
}

SC_SKEY_SecretKey *
SC_SKEY_SecretKey_New(void)
{
	SC_SKEY_SecretKey *key;

	key = (SC_SKEY_SecretKey *)sc_calloc(sizeof(SC_SKEY_SecretKey), 1);

	return key;
}

void
SC_SKEY_SecretKey_Free(SC_SKEY_SecretKey *key)
{
	if(key != NULL) {
		SC_Memzero(key, 0x00, sizeof(SC_SKEY_SecretKey));
		sc_free(key);
	}

	return;
}

/*
*
* !new : 동적할당 함수
*
*/

SC_CIPHER_CTX *
SC_CIPHER_CTX_New(void)
{
	SC_CIPHER_CTX *ctx;

	ctx = (SC_CIPHER_CTX *)sc_calloc(sizeof(SC_CIPHER_CTX), 1);

	return ctx;
}

void 
SC_CIPHER_CTX_Free(SC_CIPHER_CTX *ctx)
{
	if(ctx != NULL) {
		SC_Memzero(ctx, 0x00, sizeof(SC_CIPHER_CTX));
		sc_free(ctx);
	}

	return;
}

int 
SC_SKEY_GenerateKey(SC_SKEY_SecretKey *key, const int keyID, const U32 keyLength)
{
	int retCode = 0;

	if(key == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}
	if(keyLength == 0 || keyLength > SCC_CIPHER_MAX_KEY_SIZE) {
		return SCC_CIPHER_ERROR_KEY_LENGTH;
	}

	switch (keyID)
	{
	case SCC_KEY_ID_ARIA:
		// 난수발생기 함수 호출
		retCode = SC_GetRandom(key->key, keyLength);
		if(retCode < 0) goto end;

		key->cipherID = SCC_CIPHER_ID_ARIA;
		key->keyLength = keyLength;

		break;

	default:
		return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;

}

int 
SC_Cipher_Encrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	if(ctx == NULL || key == NULL || param == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	retCode = SC_Cipher_CheckModeID(param->modeID);
	if (retCode < 0)
		goto end;
	
	retCode = SC_Cipher_CheckPaddingID(param->paddingID);
	if (retCode < 0)
		goto end;

	switch(cipherID){
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Encrypt_Init(&ctx->cipherKey.aria, key->key, key->keyLength, param->modeParam.iv, param->modeParam.ivLength, param->modeID, param->paddingID);
			if(retCode < 0)
				goto end;
			ctx->cipherID = cipherID;
			break;
			
		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;

	}

end:
	return retCode;

}

int 
SC_Cipher_Encrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(ctx == NULL || input == NULL || inputLength == 0) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(ctx->cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Encrypt_Update(&ctx->cipherKey.aria, output, outputLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Cipher_Encrypt_Final(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength)
{
	int retCode = 0;

	if(ctx == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(ctx->cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Encrypt_Final(&ctx->cipherKey.aria, output, outputLength);
			if(retCode < 0) goto end;
			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Cipher_Encrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	if (param != NULL) {
		if (key == NULL ) {
			return SCC_COMMON_ERROR_INVALID_INPUT;
		}
	}
	else {
		if (key == NULL || param == NULL || input == NULL || inputLength == 0) {
			return SCC_COMMON_ERROR_INVALID_INPUT;
		}
	}

	retCode = SC_Cipher_CheckModeID(param->modeID);
	if (retCode < 0)
		goto end;
	
	retCode = SC_Cipher_CheckPaddingID(param->paddingID);
	if (retCode < 0)
		goto end;
	
	switch(cipherID) {
		case SCC_CIPHER_ID_ARIA: 
			retCode = SC_ARIA_Encrypt(output, outputLength, input, inputLength, key->key, key->keyLength, param->modeParam.iv, param->modeParam.ivLength, param->modeID, param->paddingID);

			if(retCode < 0) goto end;
					break;
		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}
end:
	return retCode;
}

int 
SC_Cipher_Decrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	if(ctx == NULL || key == NULL || param == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	retCode = SC_Cipher_CheckModeID(param->modeID);
	if (retCode < 0)
		goto end;
	
	retCode = SC_Cipher_CheckPaddingID(param->paddingID);
	if (retCode < 0)
		goto end;

	switch(cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Decrypt_Init(&ctx->cipherKey.aria, key->key, key->keyLength, param->modeParam.iv, param->modeParam.ivLength, param->modeID, param->paddingID);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Cipher_Decrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(ctx == NULL || input == NULL || inputLength == 0) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(ctx->cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Decrypt_Update(&ctx->cipherKey.aria, output, outputLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Cipher_Decrypt_Final(SC_CIPHER_CTX *ctx, U32 *paddingLength)
{
	int retCode = 0;

	if(ctx == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(ctx->cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Decrypt_Final(&ctx->cipherKey.aria, paddingLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int
SC_Cipher_Decrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	if (param != NULL) {
		if (key == NULL ) {
			return SCC_COMMON_ERROR_INVALID_INPUT;
		}
	}
	else {
		if(key == NULL || param == NULL || input == NULL || inputLength == 0) {
			return SCC_COMMON_ERROR_INVALID_INPUT;
		}
	}

	retCode = SC_Cipher_CheckModeID(param->modeID);
	if (retCode < 0)
		goto end;
	
	retCode = SC_Cipher_CheckPaddingID(param->paddingID);
	if (retCode < 0)
		goto end;

	switch(cipherID) {
		case SCC_CIPHER_ID_ARIA:
			retCode = SC_ARIA_Decrypt(output, outputLength, input, inputLength, key->key, key->keyLength, param->modeParam.iv, param->modeParam.ivLength, param->modeID, param->paddingID);
			if(retCode < 0) goto end;
			break;
		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;

}

