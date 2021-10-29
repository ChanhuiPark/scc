#include <string.h>

#include "scc_hash.h"
#include "scc_sha256.h"
#include "scc_sha512.h"
#include "scc_error.h"
#include "scc_protocol.h"
#include "scc_malloc.h"
#include "scc_cmvp.h"
#include "scc_util.h"

SC_HASH_CTX * 
SC_HASH_CTX_New(void)
{
	SC_HASH_CTX *ctx;

	ctx = (SC_HASH_CTX *)sc_calloc(sizeof(SC_HASH_CTX), 1);

	return ctx;
}

void 
SC_HASH_CTX_Free(SC_HASH_CTX *hashCtx)
{
	if(hashCtx != NULL) {
				
		SC_Memzero(hashCtx, 0x00, sizeof(SC_HASH_CTX));
		sc_free(hashCtx);
	}

	return;
}

int 
SC_Hash_Init(SC_HASH_CTX *hashCtx, const int hashID)
{
	int retCode = 0;

	if(hashCtx == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(hashID) {
		case SCC_HASH_ID_SHA256:
			hashCtx->hashID = hashID;
			SC_SHA256_New(&hashCtx->ctx.sha256);

			retCode = SC_SHA256_Init(&hashCtx->ctx.sha256);
			if(retCode < 0) goto end;

			break;

		case SCC_HASH_ID_SHA512:
			hashCtx->hashID = hashID;
			SC_SHA512_New(&hashCtx->ctx.sha512);

			retCode = SC_SHA512_Init(&hashCtx->ctx.sha512);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Hash_Update(SC_HASH_CTX *hashCtx, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(hashCtx == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	// 입력길이 제한
	if (inputLength > MAXINPUTSIZE)
		return SCC_COMMON_ERROR_INVALID_INPUT;

	switch(hashCtx->hashID) {
		case SCC_HASH_ID_SHA256:
			retCode = SC_SHA256_Update(&hashCtx->ctx.sha256, input, inputLength);
			if(retCode < 0) goto end;

			break;

		case SCC_HASH_ID_SHA512:
			retCode = SC_SHA512_Update(&hashCtx->ctx.sha512, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Hash_Final(SC_HASH_CTX *hashCtx, U8 *hash, U32 *hashLength)
{
	int retCode = 0;

	if(hashCtx == NULL || hash == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(hashCtx->hashID) {
		case SCC_HASH_ID_SHA256:
			retCode = SC_SHA256_Final(&hashCtx->ctx.sha256, hash);
			if(retCode < 0) goto end;

			*hashLength = 32;

			break;

		case SCC_HASH_ID_SHA512:
			retCode = SC_SHA512_Final(&hashCtx->ctx.sha512, hash);
			if(retCode < 0) goto end;

			*hashLength = 64;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_Hash(U8 *hash, U32 *hashLength, U8 *input, U32 inputLength, const int hashID)
{
	int retCode = 0;
	
	if(hash == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	// 입력길이 제한
	if (inputLength > MAXINPUTSIZE)
		return SCC_COMMON_ERROR_INVALID_INPUT;

	switch(hashID) {
		case SCC_HASH_ID_SHA256:
			retCode = SC_SHA256_Digest(hash, hashLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		case SCC_HASH_ID_SHA512:
			retCode = SC_SHA512_Digest(hash, hashLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}
