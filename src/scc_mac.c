#include <string.h>

#include "scc_mac.h"
#include "scc_malloc.h"
#include "scc_error.h"
#include "scc_cmvp.h"
#include "scc_util.h"

SC_MAC_CTX * 
SC_MAC_CTX_New()
{
	SC_MAC_CTX *ctx;

	ctx = (SC_MAC_CTX *)sc_calloc(sizeof(SC_MAC_CTX), 1);

	return ctx;
}

void 
SC_MAC_CTX_Free(SC_MAC_CTX *macCtx)
{
	if(macCtx != NULL) {
		SC_Memzero(macCtx, 0x00, sizeof(SC_MAC_CTX));
		sc_free(macCtx);
	}

	return;
}

int
SC_MAC_Init(SC_MAC_CTX *macCtx, const SC_SKEY_SecretKey *key, const int macID)
{
	int retCode = 0;

	if(macCtx == NULL || key == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(macID) {
		case SCC_MAC_ID_HMAC_SHA256:
			retCode = SC_HMAC_SHA256_Init(&macCtx->ctx.hmacSha256, key->key, key->keyLength);
			if(retCode < 0) goto end;
			
			macCtx->macID = macID;

			break;

		case SCC_MAC_ID_HMAC_SHA512:
			retCode = SC_HMAC_SHA512_Init(&macCtx->ctx.hmacSha512, key->key, key->keyLength);
			if(retCode < 0) goto end;

			macCtx->macID = macID;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_MAC_Update(SC_MAC_CTX *macCtx, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(macCtx == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(macCtx->macID) {
		case SCC_MAC_ID_HMAC_SHA256:
			retCode = SC_HMAC_SHA256_Update(&macCtx->ctx.hmacSha256, input, inputLength);
			if(retCode < 0) goto end;

			break;

		case SCC_MAC_ID_HMAC_SHA512:
			retCode = SC_HMAC_SHA512_Update(&macCtx->ctx.hmacSha512, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_MAC_Final(SC_MAC_CTX *macCtx, U8 *mac, U32 *macLength)
{
	int retCode = 0;

	if(macCtx == NULL || mac == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(macCtx->macID) {
		case SCC_MAC_ID_HMAC_SHA256:
			retCode = SC_HMAC_SHA256_Final(&macCtx->ctx.hmacSha256, mac, macLength);
			if(retCode < 0) goto end;

			break;

		case SCC_MAC_ID_HMAC_SHA512:
			retCode = SC_HMAC_SHA512_Final(&macCtx->ctx.hmacSha512, mac, macLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

int 
SC_MAC(U8 *mac, U32 *macLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int macID)
{
	int retCode = 0;

	if(mac == NULL || input == NULL || key == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(macID) {
		case SCC_MAC_ID_HMAC_SHA256:
			retCode = SC_HMAC_SHA256(mac, macLength, key->key, key->keyLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		case SCC_MAC_ID_HMAC_SHA512:
			retCode = SC_HMAC_SHA512(mac, macLength, key->key, key->keyLength, input, inputLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_CIPHER_ERROR_UNKNOWN_ID;
	}

end:
	return retCode;
}

