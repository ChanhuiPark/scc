/* 
========================================
  scc_main.c 
    : crypto main 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "scc_main.h"
#include "scc_protocol.h"
#include "scc_error.h"
#include "scc_aria.h"
#include "scc_sha256.h"
#include "scc_sha512.h"
#include "scc_cmvp.h"
#include "scc_hmac_sha.h"
#include "scc_selftest.h"
#include "scc_cipher.h"
#include "scc_hash.h"
#include "scc_malloc.h"
#include "scc_drbg.h"
#include "scc_pkey.h"
#include "scc_random.h"

// for test
#include <crtdbg.h>
#include <malloc.h>

#define	SC_CRYPTO_VERSION					"1.0.0.0"


/**
 *
 *
 *
 */
// 난수발생기 함수 : 핵심보안매개변수에 해당하는 작동상태에 대한 출력이 없음
int
SCC_RAND(U8 *output, const U32 outputLength)
{
	int	retCode = 0;
	int i = 0;
	int remain = 0;
	U8 buffer[SC_HashDRBG_SEED_LEN] = {0x00,};
	int pos = 0;

	// check state
	retCode = SC_CMVP_Status_CheckState();
	if (retCode != 0) return retCode;

	if(outputLength == 0) {
		retCode = SCC_COMMON_ERROR_INVALID_INPUT;
		return retCode;
	}
	
	retCode = SC_GetRandom(output, outputLength);
	//retCode = SC_GetRandomTestVector(output, outputLength);
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_CRITICAL_ERROR);

	return retCode;
}

int 
SCC_RAND_Final(void)
{
	int retCode = 0;

	// 난수 컨텍스트 제로화
	SC_CMVP_RAND_Final();

	return retCode;
}

int 
SCC_CM_Initialize(void)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_init();

	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_CRITICAL_ERROR);

	return retCode;
}

int 
SCC_CM_Finalize(void)
{
	int retCode = 0;

	// 난수 컨텍스트 제로화
	SC_CMVP_RAND_Final();
	retCode = SC_CMVP_MoveStatus(SCC_STATUS_FINALIZED);

	return retCode;
}

char *
SCC_CM_GetVersion(void)
{
	return SC_CRYPTO_VERSION;
}

char *
SCC_CM_GetErrorString(const int errorCode)
{
	return SC_GetErrorString(errorCode);
}

int
SCC_CM_GetState(void)
{	
	return SC_CMVP_GetStatus();
}

int 
SCC_CM_ChangeState(const int stateID)
{

	int	retCode = 0;

	switch (g_cmvp_status_id) {
	// 현재 상태가 검증대상동작모드 및 심각한 오류일때만 허용
	case SCC_STATUS_KCMVP :
	case SCC_STATUS_CRITICAL_ERROR :
		switch (stateID) {
		case SCC_STATUS_FINALIZED :
			g_cmvp_status_id = stateID;
			break;
		case SCC_STATUS_LOADED :
		case SCC_STATUS_SELFTEST :
		case SCC_STATUS_SELFTESTCASE :
		case SCC_STATUS_CRITICAL_ERROR :
		case SCC_STATUS_ERROR :	
		case SCC_STATUS_KCMVP :
			retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
			goto end;
		
		default :
			retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
			goto end;
		}
		break;

	// 현재 상태가 모듈 종료일때
	default : 
		retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
		goto end;
		break;

	}

	retCode = 0;

end:
	return retCode;
}

int 
SCC_CM_SelfTest(void)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) 
		return retCode;

	retCode = SC_CMVP_SelfTest();
	if (retCode != 0) {
		// 자기서험 실패할 경우 심각한 오류상태 진입
		SC_CMVP_MoveStatus(SCC_STATUS_CRITICAL_ERROR);
		return retCode;
	}
	
	// 자가시험 성공하면 승인모드 상태로 변경
	SC_CMVP_MoveStatus(SCC_STATUS_KCMVP);

	return 0;
}


SC_SKEY_SecretKey *
SCC_SKEY_SecretKey_New(void)
{
	return SC_SKEY_SecretKey_New();
}

void
SCC_SKEY_SecretKey_Free(SC_SKEY_SecretKey *key)
{
	SC_SKEY_SecretKey_Free(key);

	return;
}

int 
SCC_SKEY_GenerateKey(SC_SKEY_SecretKey *key, const int keyID, const U32 keyLength)
{
	int retCode = 0;
		
	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) 
		return retCode;

	return 	SC_SKEY_GenerateKey(key, keyID, keyLength);
}

SC_CIPHER_CTX *
SCC_CIPHER_CTX_New(void)
{
	return SC_CIPHER_CTX_New();
}

void 
SCC_CIPHER_CTX_Free(SC_CIPHER_CTX *ctx)
{
	SC_CIPHER_CTX_Free(ctx);
}

int 
SCC_CIPHER_Encrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Encrypt_Init(ctx, key, cipherID, param);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Encrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(ctx->cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Encrypt_Update(ctx, output, outputLength, input, inputLength);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Encrypt_Final(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(ctx->cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Encrypt_Final(ctx, output, outputLength);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Encrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Encrypt(output, outputLength, input, inputLength, key, cipherID, param);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Decrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Decrypt_Init(ctx, key, cipherID, param);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Decrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(ctx->cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Decrypt_Update(ctx, output, outputLength, input, inputLength);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_CIPHER_Decrypt_Final(SC_CIPHER_CTX *ctx, U32 *paddingLength)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(ctx->cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Decrypt_Final(ctx, paddingLength);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int
SCC_CIPHER_Decrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckCipherID(cipherID);
	if(retCode < 0) goto end;

	retCode = SC_Cipher_Decrypt(output, outputLength, input, inputLength, key, cipherID, param);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

SC_HASH_CTX * 
SCC_HASH_CTX_New(void)
{
	return SC_HASH_CTX_New();
}

void 
SCC_HASH_CTX_Free(SC_HASH_CTX *hashCtx)
{
	SC_HASH_CTX_Free(hashCtx);

	return;
}

int 
SCC_HASH_Init(SC_HASH_CTX *hashCtx, const int hashID)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckHashID(hashID);
	if(retCode < 0) goto end;

	retCode = SC_Hash_Init(hashCtx, hashID);
	if (retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_HASH_Update(SC_HASH_CTX *hashCtx, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(hashCtx == NULL) {
		retCode = SCC_CMVP_HASH_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = SC_CMVP_Status_CheckHashID(hashCtx->hashID);
	if(retCode < 0) goto end;

	retCode = SC_Hash_Update(hashCtx, input, inputLength);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_HASH_Final(SC_HASH_CTX *hashCtx, U8 *hash, U32 *hashLength)
{
	int retCode = 0;

	if(hashCtx == NULL) {
		retCode = SCC_CMVP_HASH_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = SC_CMVP_Status_CheckHashID(hashCtx->hashID);
	if(retCode < 0) goto end;

	retCode = SC_Hash_Final(hashCtx, hash, hashLength);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_HASH(U8 *hash, U32 *hashLength, U8 *input, U32 inputLength, const int hashID)
{
	int retCode = 100;

	retCode = SC_CMVP_Status_CheckHashID(hashID);
	if(retCode < 0) goto end;

	retCode = SC_Hash(hash, hashLength, input, inputLength, hashID);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

SC_MAC_CTX * 
SCC_MAC_CTX_New(void)
{
	return SC_MAC_CTX_New();
}

void 
SCC_MAC_CTX_Free(SC_MAC_CTX *macCtx)
{
	SC_MAC_CTX_Free(macCtx);

	return;
}

int
SCC_MAC_Init(SC_MAC_CTX *macCtx, const SC_SKEY_SecretKey *key, const int macID)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckMacID(macID);
	if(retCode < 0) goto end;

	retCode = SC_MAC_Init(macCtx, key, macID);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_MAC_Update(SC_MAC_CTX *macCtx, const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	if(macCtx == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	retCode = SC_CMVP_Status_CheckMacID(macCtx->macID);
	if(retCode < 0) goto end;

	retCode = SC_MAC_Update(macCtx, input, inputLength);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_MAC_Final(SC_MAC_CTX *macCtx, U8 *mac, U32 *macLength)
{
	int retCode = 0;

	if(macCtx == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	retCode = SC_CMVP_Status_CheckMacID(macCtx->macID);
	if(retCode < 0) goto end;

	retCode = SC_MAC_Final(macCtx, mac, macLength);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_MAC(U8 *mac, U32 *macLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int macID)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckMacID(macID);
	if(retCode < 0) goto end;

	retCode = SC_MAC(mac, macLength, input, inputLength, key, macID);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

SC_PKEY_Parameters *
SCC_PKEY_Parameters_New(void)
{
	return SC_PKEY_Parameters_New();
}

void 
SCC_PKEY_Parameters_Free(SC_PKEY_Parameters *params)
{
	SC_PKEY_Parameters_Free(params);

	return;
}

SC_PKEY_PrivateKey * 
SCC_PKEY_PrivateKey_New(void)
{
	return SC_PKEY_PrivateKey_New();
}

void 
SCC_PKEY_PrivateKey_Free(SC_PKEY_PrivateKey *privateKey)
{
	SC_PKEY_PrivateKey_Free(privateKey);

	return;
}

SC_PKEY_PublicKey *
SCC_PKEY_PublicKey_New(void)
{
	return SC_PKEY_PublicKey_New();
}

void 
SCC_PKEY_PublicKey_Free(SC_PKEY_PublicKey *publicKey)
{
	SC_PKEY_PublicKey_Free(publicKey);

	return;
}

int 
SCC_PKEY_Parameters_ToBinary(U8 *output, U32 *outputLength,
							 const SC_PKEY_Parameters *params)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Parameters_ToBinary(output, outputLength, params);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_Parameters_FromBinary(SC_PKEY_Parameters *params,
							   const int pkeyID,
							   const U8 *input, const U32 inputLength)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Parameters_FromBinary(params, pkeyID, input, inputLength);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}


int 
SCC_PKEY_PrivateKey_ToBinary(U8 *output, U32 *outputLength,
							 const SC_PKEY_PrivateKey *privKey,
							 const SC_PKEY_Parameters *params)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_PrivateKey_ToBinary(output, outputLength, privKey, params);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_PrivateKey_FromBinary(SC_PKEY_PrivateKey *privKey,
							   const int pkeyID,
							   const U8 *input, const U32 inputLength,
							   const SC_PKEY_Parameters *params)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_PrivateKey_FromBinary(privKey, pkeyID, input, inputLength, params);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_PublicKey_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_PublicKey *pubKey,
							const SC_PKEY_Parameters *params)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_PublicKey_ToBinary(output, outputLength, pubKey, params);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_PublicKey_FromBinary(SC_PKEY_PublicKey *pubKey,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength,
							  const SC_PKEY_Parameters *params)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_PublicKey_FromBinary(pubKey, pkeyID, input, inputLength, params);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_Encrypt(U8 *cipher, U32 *cipherLength, 
				 const U8 *plain, const U32 plainLength, 
				 const int pencID, 
				 const SC_PKEY_PublicKey * pubKey, 
				 const SC_PKEY_Parameters *params, 
				 const SC_PKEY_PEncParam *encParam)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckPencID(pencID);
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Encrypt(cipher, cipherLength, plain, plainLength, pencID, pubKey, params, encParam);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_Decrypt(U8 *plain, U32 *plainLength, 
				 const U8 *cipher, const U32 cipherLength, 
				 const int pencID, 
				 const SC_PKEY_PrivateKey * privKey, 
				 const SC_PKEY_Parameters *params, 
				 const SC_PKEY_PEncParam *encParam)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckPencID(pencID);
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Decrypt(plain, plainLength, cipher, cipherLength, pencID, privKey, params, encParam);
	if(retCode < 0) goto end;
	
end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_Sign(U8 *signature, U32 *signatureLength,
			  const int msgID,
			  const U8 *message, const U32 messageLength,
			  const int signID,
			  const SC_PKEY_PrivateKey *privKey,
			  const SC_PKEY_Parameters *params,
			  const SC_PKEY_SignParam * signParam)
{
	int retCode = 0;

	retCode = SC_CMVP_Status_CheckSignID(signID);
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Sign(signature, signatureLength, msgID, message, messageLength, signID, privKey, params, signParam);
	if(retCode < 0) goto end;

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

int 
SCC_PKEY_Verify(U8 *signature, U32 signatureLength, 
				const int msgID, 
				const U8 *message, const U32 messageLength, 
				const int signID, 
				const SC_PKEY_PublicKey *pubKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_SignParam * signParam)
{
	int retCode = 0;
	
	retCode = SC_CMVP_Status_CheckState();
	if(retCode < 0) goto end;

	retCode = SC_PKEY_Verify(signature, signatureLength, msgID, message, messageLength, signID, pubKey, params, signParam);

end:
	if (retCode < 0)
		SC_CMVP_MoveStatus(SCC_STATUS_ERROR);

	return retCode;
}

