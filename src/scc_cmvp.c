/* 
========================================
  scc_cmvp.c 
    : crypto status 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#else
#include <pthread.h>
#endif

#include "scc_entropy.h"
#include "scc_drbg.h"
#include "scc_random.h"
#include "scc_sha256.h"
#include "scc_cmvp.h"
#include "scc_error.h"
#include "scc_selftest.h"
#include "scc_pkey.h"
#include "scc_rsa.h"
#include "scc_util.h"


int	g_cmvp_status_id = SCC_STATUS_LOADED;
static SC_HashDRBG_CONTEXT	g_cmvp_rand_ctx;
static int	g_cmvp_rand_init = 0;
static U32	g_cmvp_rand_compare_init = 0;
static U8	g_cmvp_rand_compare[SC_HashDRBG_SEED_LEN];
static U32	g_cmvp_rand_compare_len;



/**
 *
 *
 *
 */
int
SC_CMVP_MoveStatus(const int stateID)
{
	int	retCode = 0;

	switch (g_cmvp_status_id) {
	// 현재 상태가 적재됨일때
	case SCC_STATUS_LOADED :
		switch (stateID) {
		case SCC_STATUS_LOADED :
		case SCC_STATUS_SELFTEST :
			g_cmvp_status_id = stateID;
			break;
		case SCC_STATUS_KCMVP :
		case SCC_STATUS_SELFTESTCASE :
		case SCC_STATUS_FINALIZED :
		case SCC_STATUS_ERROR :
		case SCC_STATUS_CRITICAL_ERROR :
			retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
			goto end;
		default :
			retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
			goto end;
		}
		break;

	// 현재 상태가 동작 전 자가시험, 조건부 자가시험, 주기적 자가시험 일때
	case SCC_STATUS_SELFTEST :
	case SCC_STATUS_SELFTESTCASE :
		switch (stateID) {
		case SCC_STATUS_SELFTEST :
		case SCC_STATUS_KCMVP :
		case SCC_STATUS_CRITICAL_ERROR :
			g_cmvp_status_id = stateID;
			break;
		case SCC_STATUS_LOADED :
		case SCC_STATUS_FINALIZED :
		case SCC_STATUS_ERROR :
			retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
			goto end;
		default :
			retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
			goto end;
		}
		break;

	// 현재 상태가 검증대상 동작모드 일때
	case SCC_STATUS_KCMVP :
		switch (stateID) {
		case SCC_STATUS_KCMVP :
		case SCC_STATUS_SELFTEST :
		case SCC_STATUS_SELFTESTCASE :
		case SCC_STATUS_FINALIZED :
		case SCC_STATUS_CRITICAL_ERROR :
			g_cmvp_status_id = stateID;
			break;
		case SCC_STATUS_LOADED :
			retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
			goto end;
		// 현재 상태가 검증대상동작모드에서 단순오류가 발생하면 검즈앧상동작모드로 복구시킨다
		case SCC_STATUS_ERROR :	
			g_cmvp_status_id = SCC_STATUS_KCMVP;
			break;
		default :
			retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
			goto end;
		}
		break;

	
	// 현재 상태가 단순오류일때 - 없음
	
	// 현재 상태가 심각한 오류일때
	case SCC_STATUS_CRITICAL_ERROR :
		switch (stateID) {
		case SCC_STATUS_CRITICAL_ERROR :
		case SCC_STATUS_FINALIZED :
			g_cmvp_status_id = stateID;
			break;
		case SCC_STATUS_LOADED :
		case SCC_STATUS_KCMVP :
		case SCC_STATUS_ERROR :
		case SCC_STATUS_SELFTEST :
		case SCC_STATUS_SELFTESTCASE :
			retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
			goto end;
		default :
			retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
			goto end;
		}
		goto end;

	// 현재 상태가 모듈 종료일때
	case SCC_STATUS_FINALIZED :
		retCode = SCC_CMVP_ERROR_STATE_IN_FINALIZED;
		goto end;
		break;

	}

	retCode = 0;

end:
	return retCode;
}


/**
 *
 *
 *
 */
int
SC_CMVP_Status_init(void)
{
	int	retCode = 0;

	switch (g_cmvp_status_id) {
	case SCC_STATUS_LOADED :
		retCode = SC_CMVP_SelfTest();
		if (retCode != 0) {
			// 자가시험 실패할 경우 심각한 오류상태 진입
			SC_CMVP_MoveStatus(SCC_STATUS_CRITICAL_ERROR);
			retCode = SCC_CMVP_ERROR_SELFTEST_FAILED;
			goto end;
		}
		retCode = SC_CMVP_MoveStatus(SCC_STATUS_KCMVP);
		break;

	case SCC_STATUS_KCMVP :
		// crypto is already initialized
		break;

	case SCC_STATUS_SELFTEST :
	case SCC_STATUS_SELFTESTCASE :
		retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
		goto end;

	case SCC_STATUS_ERROR :
	case SCC_STATUS_CRITICAL_ERROR :
		retCode = SCC_CMVP_ERROR_STATE_IN_ERROR;
		goto end;

	case SCC_STATUS_FINALIZED :
		retCode = SCC_CMVP_ERROR_STATE_IN_FINALIZED;
		goto end;

	default :
		retCode = SCC_CMVP_ERROR_UNKNOWN_STATEID;
		goto end;
	}
	
end:
	return retCode;

}

int
SC_CMVP_Status_Final(void)
{
	int retCode = 0;

	retCode = SC_CMVP_MoveStatus(SCC_STATUS_FINALIZED);
	return retCode;
	
}

/**
 *
 *
 *
 */
int
SC_CMVP_GetStatus(void)
{
	return g_cmvp_status_id;
}



/**
 *
 *
 *
 */
static int
SC_Status_CheckCipherID(const int cipherID)
{
	int	retCode;

	switch (cipherID) {
	case SCC_CIPHER_ID_ARIA :
		break;
	default :
		retCode = SCC_CMVP_CIPHER_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

static
int
SC_Status_CheckHashID(const int hashID)
{
	int	retCode;

	switch (hashID) {
	case SCC_HASH_ID_SHA256 :
	case SCC_HASH_ID_SHA512 :
		break;
	default :
		retCode = SCC_CMVP_HASH_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

static
int
SC_Status_CheckMacID(const int macID)
{
	int	retCode;

	switch (macID) {
	case SCC_MAC_ID_SHA256 :
	case SCC_MAC_ID_SHA512 :
		break;
	default :
		retCode = SCC_CMVP_MAC_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

static
int
SC_Status_CheckPkeyID(const int pkeyID)
{
	int	retCode;

	switch (pkeyID) {
	case SC_PKEY_ID_RSA :
	case SC_PKEY_ID_KCDSA :
		break;
	default :
		retCode = SCC_CMVP_PKEY_ERROR_UNKNOWN_ID;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

static
int
SC_Status_CheckPencID(const int pencID)
{
	int	retCode;
	
	switch (pencID) {
	case SC_PKEY_PENCID_RSA_OAEP :
		break;
	default :
		retCode = SCC_CMVP_PENC_ERROR_UNKNOWN_ID;
		goto end;
	}
	
	retCode = 0;

end:
	return retCode;
}

static
int
SC_Status_CheckSignID(const int signID)
{
	int	retCode;
	
	switch (signID) {
	case SC_PKEY_SIGNID_KCDSA_SHA256:
		break;
	default :
		retCode = SCC_CMVP_SIGN_ERROR_UNKNOWN_ID;
		goto end;
	}
	
	retCode = 0;

end:
	return retCode;
}

static int
SC_Status_CheckAlgID(const int algID,
					int (*CB_KCMVP_CheckAlgID)(const int algID))
{
	int	retCode;

	switch (g_cmvp_status_id) {
	case SCC_STATUS_KCMVP :
		// 검증대상동작모드상태인지 체크
		if (CB_KCMVP_CheckAlgID != NULL) {
			retCode = (CB_KCMVP_CheckAlgID)(algID);
			if (retCode != 0) goto end;
		}
		break;

	default:
		// 그 밖의 상태는 허용되지 않음
		retCode = SCC_CMVP_ERROR_STATE_NOT_ALLOWED;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

int
SC_CMVP_Status_CheckState(void)
{
	return SC_Status_CheckAlgID(0, NULL);
}

int
SC_CMVP_Status_CheckCipherID(const int cipherID)
{
	return SC_Status_CheckAlgID(cipherID, SC_Status_CheckCipherID);
}

int
SC_CMVP_Status_CheckHashID(const int hashID)
{
	return SC_Status_CheckAlgID(hashID, SC_Status_CheckHashID);
}

int
SC_CMVP_Status_CheckMacID(const int hashID)
{
	return SC_Status_CheckAlgID(hashID, SC_Status_CheckMacID);
}

int 
SC_CMVP_Status_CheckPkeyID(const int pkeyID)
{
	return SC_Status_CheckAlgID(pkeyID, SC_Status_CheckPkeyID);
}

int 
SC_CMVP_Status_CheckSignID(const int signID)
{
	return SC_Status_CheckAlgID(signID, SC_Status_CheckSignID);
}

int 
SC_CMVP_Status_CheckPencID(const int pencID)
{
	return SC_Status_CheckAlgID(pencID, SC_Status_CheckPencID);
}

int
SC_CMVP_Cipher_CheckParams(const int modeID,
						   const int paddingID)
{
	int	retCode;

	switch (modeID) {
	case SCC_CIPHER_MODE_CBC :
	case SCC_CIPHER_MODE_CTR :
		break;
	default :
		retCode = SCC_CMVP_ERROR_CHECKPARAM_UNKNOWN_MODE;
		goto end;
	}

	switch (paddingID) {
	case SCC_CIPHER_PADDING_NO :
	case SCC_CIPHER_PADDING_HASH :
	case SCC_CIPHER_PADDING_ZERO :
	case SCC_CIPHER_PADDING_PKCS :
		break;
	default :
		retCode = SCC_CMVP_ERROR_CHECKPARAM_UNKNOWN_PADDING;
		goto end;
	}

	retCode = 0;

end:
	return retCode;
}

static void 
SC_CMVP_GetNonce16(U8 *out)
{
	static int count = 1;
	U8 temp[128*8], md[32];
	int templength = 0, mdlength = 0;

	SC_Entropy_GetBasicPieces(temp, &templength);

	temp[templength++] = (U8)(count%256);

	SC_SHA256_Digest(md, &mdlength, temp, templength);
	memcpy(out, md, 16);

	return;
}









int
SC_CMVP_RAND_Init(void)
{
	U8		nonce[16]={0x00,}, *personal=NULL;
	int	retCode, nonceLen=0, personalLen=0;

	if (g_cmvp_rand_init == 1) return 0;
	
	g_cmvp_rand_init = 1;
	
	SC_CMVP_GetNonce16(nonce);
	nonceLen = 16;

	SC_HashDRBG_Init(&g_cmvp_rand_ctx, personal, personalLen, nonce, nonceLen);
	
	retCode = 0;

	return retCode;
}

void 
SC_CMVP_RAND_Final(void)
{
	// 추출된 엔트로피로부터 생성된 난수 컨텍스트 제로화
	SC_Memzero (&g_cmvp_rand_ctx, 0x00, sizeof(SC_HashDRBG_CONTEXT));
	g_cmvp_rand_init = 0;
	g_cmvp_rand_compare_init = 0;
	SC_Memzero(g_cmvp_rand_compare, 0x00, sizeof(g_cmvp_rand_compare));

	return;
}



int
SC_CMVP_RAND_GetRandom(U8 *output, 
					   const U32 outputLength)
{
	U8		buffer[SC_HashDRBG_SEED_LEN+1];
	int		retCode;
	U32		len = 0;

	if (!g_cmvp_rand_init)
		SC_CMVP_RAND_Init();
		
	if (!g_cmvp_rand_compare_init) {
		// generate random block
		retCode = SC_HashDRBG_Generate(&g_cmvp_rand_ctx, buffer, 20, NULL, 0, 0); 
		if (retCode != 0)
			goto end;
	
		// 최초에는 비교할 난수값을 20바이트 생성
		memcpy(g_cmvp_rand_compare, buffer, 20);
		g_cmvp_rand_compare_len = 20;
		g_cmvp_rand_compare_init = 1;
	}
	
	// generate random block
	SC_HashDRBG_Generate(&g_cmvp_rand_ctx, buffer, outputLength, NULL, 0, 0); 
		
	if(g_cmvp_status_id == SCC_STATUS_KCMVP) {
		retCode = SC_CMVP_MoveStatus(SCC_STATUS_SELFTESTCASE);
		if (retCode != 0) goto end;
	}

	// 조건부 자가시험 : 연속적 난수발생기 시험
	// 생성된 난수와 이전 난수를 비교하여 다르면 복사
	// 이전 난수 길이와 요청 난수 길이 중 짧은 길이를 비교
	
	len = (outputLength >= g_cmvp_rand_compare_len) ? g_cmvp_rand_compare_len : outputLength;
	if (memcmp(g_cmvp_rand_compare, buffer, len) != 0) {
		// 성공하면 요청난수값 저장
		memcpy(g_cmvp_rand_compare, buffer, outputLength);
		g_cmvp_rand_compare_len = outputLength;
	}
	else {
		SC_CMVP_MoveStatus(SCC_STATUS_CRITICAL_ERROR);
		retCode = SCC_MAIN_ERROR_SELFTESTCASE_FAILED;
		goto end;
	}
	
	if(g_cmvp_status_id == SCC_STATUS_SELFTESTCASE) {
		retCode = SC_CMVP_MoveStatus(SCC_STATUS_KCMVP);
		if (retCode != 0) goto end;
	}
	
	// 리씨드카운터 요청출력길이 만큼 증가시킨 후
	// 리씨드카운터가 100000 초과 되면 
	// 외부갱신 함수 호출
	if (g_cmvp_rand_ctx.reseedCounter > 100000) {
		SC_HashDRBG_Reseed(&g_cmvp_rand_ctx, NULL, 0);
	}
	
	memcpy(output, buffer, outputLength);
	retCode = 0;

end:
	
	return retCode;
}

