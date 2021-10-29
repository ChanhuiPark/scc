/* 
========================================
  scc_hmac_sha2.c
    : hmac sha2 algorithm
	: FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <string.h>
#include "scc_hmac_sha.h"
#include "scc_error.h"
#include "scc_util.h"

/* HMAC-SHA-256 functions */
int SC_HMAC_SHA256_Init(SC_HMAC_SHA256_CTX *ctx, const U8 *key,
                      const U32 keySize)
{
    U32 fill;
    U32 num;

    const U8 *keyUsed;
    U8 keyTemp[SCC_SHA256_DIGEST_SIZE];
	U32 keyTempLength;
    int i;
	int retCode;
	
	if (ctx == NULL || key == NULL){
		retCode = SCC_HMACSHA256_ERROR_INVALID_INPUT;
		goto end;
	}

	if (keySize < SCC_SHA256_DIGEST_SIZE){
		retCode = SCC_HMACSHA256_ERROR_INVALID_INPUTLEN;
		goto end;
	}

    if (keySize == SCC_SHA256_BLOCK_SIZE) {
        keyUsed = key;
        num = SCC_SHA256_BLOCK_SIZE;
    } else {
        if (keySize > SCC_SHA256_BLOCK_SIZE){
            num = SCC_SHA256_DIGEST_SIZE;
			retCode = SC_SHA256_Digest(keyTemp, &keyTempLength, key, keySize);
			if(retCode != 0) goto end;
			keyUsed = keyTemp;
		} else { 
            keyUsed = key;
            num = keySize;
        }
        fill = SCC_SHA256_BLOCK_SIZE - num;

        SC_Memzero(ctx->blockIpad + num, 0x36, fill);
        SC_Memzero(ctx->blockOpad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->blockIpad[i] = keyUsed[i] ^ 0x36;
        ctx->blockOpad[i] = keyUsed[i] ^ 0x5c;
    }

    retCode = SC_SHA256_Init(&ctx->ctxInside);
	if (retCode != 0) goto end;

    retCode = SC_SHA256_Update(&ctx->ctxInside, ctx->blockIpad, SCC_SHA256_BLOCK_SIZE);
	if (retCode != 0) goto end;

    retCode = SC_SHA256_Init(&ctx->ctxOutside);
	if (retCode != 0) goto end;

    retCode = SC_SHA256_Update(&ctx->ctxOutside, ctx->blockOpad, SCC_SHA256_BLOCK_SIZE);
	if (retCode != 0) goto end;

	retCode = 0;

end:
	// 키 제로화
	if(retCode < 0)
		SC_Memzero(ctx, 0x00, sizeof(SC_HMAC_SHA256_CTX));

	return retCode;

}

int SC_HMAC_SHA256_Update(SC_HMAC_SHA256_CTX *ctx, const U8 *message,
                       const U32 messageLength)
{
	int retCode;

	if (ctx == NULL || message == NULL){
		retCode = SCC_HMACSHA256_ERROR_INVALID_INPUT;
		goto end;
	}

	if (messageLength < 0 || messageLength > MAXINPUTSIZE){
		retCode = SCC_HMACSHA256_ERROR_INVALID_INPUTLEN;
		goto end;
	}

    retCode = SC_SHA256_Update(&ctx->ctxInside, message, messageLength);
	if (retCode != 0) goto end;
	
	retCode = 0;

end:
	// 키 제로화
	if(retCode < 0)
		SC_Memzero(ctx, 0x00, sizeof(SC_HMAC_SHA256_CTX));

	return retCode;

}

int SC_HMAC_SHA256_Final(SC_HMAC_SHA256_CTX *ctx, U8 *mac,
                       U32 *macLength)
{
    U8 digest_inside[SCC_SHA256_DIGEST_SIZE];
    U8 macTemp[SCC_SHA256_DIGEST_SIZE];
	int retCode;

	if (ctx == NULL || mac == NULL || macLength == NULL){
		retCode = SCC_HMACSHA256_ERROR_INVALID_INPUT;
		goto end;
	}

    retCode = SC_SHA256_Final(&ctx->ctxInside, digest_inside);
	if (retCode != 0) goto end;

    retCode = SC_SHA256_Update(&ctx->ctxOutside, digest_inside, SCC_SHA256_DIGEST_SIZE);
	if (retCode != 0) goto end;

    retCode = SC_SHA256_Final(&ctx->ctxOutside, macTemp);
	if (retCode != 0) goto end;

    memcpy(mac, macTemp, SCC_SHA256_DIGEST_SIZE);
	*macLength = SCC_SHA256_DIGEST_SIZE;

	retCode = 0;
end:
	SC_Memzero(ctx, 0x00, sizeof(SC_HMAC_SHA256_CTX));

	return retCode;
}

int SC_HMAC_SHA256(U8 *mac, U32 *macLength,
				   const U8 *key, const U32 keySize,
				   const U8 *message, const U32 messageLength)
{
    SC_HMAC_SHA256_CTX ctx;
	int retCode;

    retCode = SC_HMAC_SHA256_Init(&ctx, key, keySize);
	if (retCode != 0) goto end;

    retCode = SC_HMAC_SHA256_Update(&ctx, message, messageLength);
	if (retCode != 0) goto end;

    retCode = SC_HMAC_SHA256_Final(&ctx, mac, macLength);
	if (retCode != 0) goto end;
	
	retCode = 0;
end:
	SC_Memzero(&ctx, 0x00, sizeof(SC_HMAC_SHA256_CTX));
	return retCode;
}

/* HMAC-SHA-512 functions */

int SC_HMAC_SHA512_Init(SC_HMAC_SHA512_CTX *ctx, const U8 *key,
                      const U32 keySize)
{
    U32 fill;
    U32 num;

    const U8 *keyUsed;
    U8 keyTemp[SCC_SHA512_DIGEST_SIZE];
	U32 keyTempLength;
    int i;
	int retCode;

	if (ctx == NULL || key == NULL){
		retCode = SCC_HMACSHA512_ERROR_INVALID_INPUT;
		goto end;
	}

	if (keySize < SCC_SHA512_DIGEST_SIZE){
		retCode = SCC_HMACSHA512_ERROR_INVALID_INPUTLEN;
		goto end;
	}

    if (keySize == SCC_SHA512_BLOCK_SIZE) {
        keyUsed = key;
        num = SCC_SHA512_BLOCK_SIZE;
    } else {
        if (keySize > SCC_SHA512_BLOCK_SIZE){
            num = SCC_SHA512_DIGEST_SIZE;
            SC_SHA512_Digest(keyTemp, &keyTempLength, key, keySize);

            keyUsed = keyTemp;
		} else { 
            keyUsed = key;
            num = keySize;
        }

        fill = SCC_SHA512_BLOCK_SIZE - num;

        SC_Memzero(ctx->blockIpad + num, 0x36, fill);
        SC_Memzero(ctx->blockOpad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->blockIpad[i] = keyUsed[i] ^ 0x36;
        ctx->blockOpad[i] = keyUsed[i] ^ 0x5c;
    }

    retCode = SC_SHA512_Init(&ctx->ctxInside);
	if (retCode != 0) goto end;

    retCode = SC_SHA512_Update(&ctx->ctxInside, ctx->blockIpad, SCC_SHA512_BLOCK_SIZE);
	if (retCode != 0) goto end;

    retCode = SC_SHA512_Init(&ctx->ctxOutside);
	if (retCode != 0) goto end;
    retCode = SC_SHA512_Update(&ctx->ctxOutside, ctx->blockOpad, SCC_SHA512_BLOCK_SIZE);
	if (retCode != 0) goto end;

	retCode = 0;
end:
	// 키 제로화
	if(retCode < 0)
		SC_Memzero(ctx, 0x00, sizeof(SC_HMAC_SHA512_CTX));

	return retCode;
}

int SC_HMAC_SHA512_Update(SC_HMAC_SHA512_CTX *ctx, const U8 *message,
                        const U32 messageLength)
{
	int retCode;

	if (ctx == NULL || message == NULL){
		retCode = SCC_HMACSHA512_ERROR_INVALID_INPUT;
		goto end;
	}

	if (messageLength < 0 || messageLength > MAXINPUTSIZE){
		retCode = SCC_HMACSHA512_ERROR_INVALID_INPUTLEN;
		goto end;
	}

    retCode = SC_SHA512_Update(&ctx->ctxInside, message, messageLength);
	if (retCode != 0) goto end;

	retCode = 0;
end:
	return retCode;
}

int SC_HMAC_SHA512_Final(SC_HMAC_SHA512_CTX *ctx, U8 *mac,
                       U32 *macLength)
{
    U8 digest_inside[SCC_SHA512_DIGEST_SIZE];
    U8 macTemp[SCC_SHA512_DIGEST_SIZE];
	int retCode;

	if (ctx == NULL || mac == NULL || macLength == NULL){
		retCode = SCC_HMACSHA512_ERROR_INVALID_INPUT;
		goto end;
	}

    retCode = SC_SHA512_Final(&ctx->ctxInside, digest_inside);
	if (retCode != 0) goto end;

    retCode = SC_SHA512_Update(&ctx->ctxOutside, digest_inside, SCC_SHA512_DIGEST_SIZE);
	if (retCode != 0) goto end;

    retCode = SC_SHA512_Final(&ctx->ctxOutside, macTemp);
	if (retCode != 0) goto end;

    memcpy(mac, macTemp, SCC_SHA512_DIGEST_SIZE);
	*macLength = SCC_SHA512_DIGEST_SIZE;

	retCode = 0;

end:
	// 키 제로화
	if(retCode < 0)
		SC_Memzero(ctx, 0x00, sizeof(SC_HMAC_SHA512_CTX));

	return retCode;
}

int SC_HMAC_SHA512(U8 *mac, U32 *macLength,
				   const U8 *key, const U32 keySize,
          const U8 *message, const U32 messageLength)
{
    SC_HMAC_SHA512_CTX ctx;
	int retCode; 

    retCode = SC_HMAC_SHA512_Init(&ctx, key, keySize);
	if (retCode != 0) goto end;

    retCode = SC_HMAC_SHA512_Update(&ctx, message, messageLength);
	if (retCode != 0) goto end;

    retCode = SC_HMAC_SHA512_Final(&ctx, mac, macLength);
	if (retCode != 0) goto end;

	retCode = 0;
end:
	SC_Memzero(&ctx, 0x00, sizeof(SC_HMAC_SHA512_CTX));
	return retCode;

}
