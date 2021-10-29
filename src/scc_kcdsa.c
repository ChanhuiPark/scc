/* 
========================================
  scc_kcdsa.c
    : Digital Signature Algorithm KCDSA
	: TTAS.KO-12.0001/R3:2014
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <time.h>

#include "scc_kcdsa.h"
#include "scc_bignum.h"
#include "scc_error.h"
#include "scc_sha256.h"
#include "scc_malloc.h"
#include "scc_cmvp.h"
#include "scc_util.h"

static int SC_KCDSA_PRNG(
					  U8		*pbSrc,
					  U32		dSrcByteLen,	//	in Bytes
					  U8		*pbDst,
					  U32		dDstBitLen)		//	in Bits
{
	U8		Count, DigestValue[SCC_SHA256_DIGEST_SIZE];
	U32		i;
	SC_SHA256_CONTEXT ctx;

	//
	i = ((dDstBitLen+7) & 0xFFFFFFF8) / 8;
	for( Count=0;  ; Count++) {
		SC_Memzero(&ctx, 0, sizeof(SC_SHA256_CONTEXT));

		SC_SHA256_Init(&ctx);
		SC_SHA256_Update(&ctx, pbSrc, dSrcByteLen);
		SC_SHA256_Update(&ctx, &Count, 1);
		SC_SHA256_Final(&ctx, DigestValue);

		if( i>=SCC_SHA256_DIGEST_SIZE ) {
			i -= SCC_SHA256_DIGEST_SIZE;
			memcpy(pbDst+i, DigestValue, SCC_SHA256_DIGEST_SIZE);
			if( i==0 )	break;
		}
		else {
			memcpy(pbDst, DigestValue+SCC_SHA256_DIGEST_SIZE-i, i);
			break;
		}
	}

	//
	i = dDstBitLen & 0x07;
	if( i )
		pbDst[0] &= (1<<i) - 1;

	//
	return SCC_SUCCESS;
}

int 
SC_KCDSA_CreateKeyObject(SC_KCDSA_Parameters **KCDSA_Params)
{
	SC_KCDSA_Parameters *params;

	if(KCDSA_Params == NULL) {
		return SCC_KCDSA_ERROR_INVALID_POINTER;
	}

	*KCDSA_Params = params = (SC_KCDSA_Parameters *) sc_malloc(sizeof(SC_KCDSA_Parameters));
	if(params == NULL) {
		goto err;
	}

	SC_Bigint_New(&params->KCDSA_p);
	SC_Bigint_New(&params->KCDSA_q);
	SC_Bigint_New(&params->KCDSA_g);
	
	params->Count = 0;
	params->SeedLen = 512/8;
	params->Seed = sc_malloc(512/8);
	if(params->Seed == NULL) {
		goto err;
	}
	SC_Memzero(params->Seed, 0x00, 512/8);

	return SCC_SUCCESS;

err:
	SC_KCDSA_DestroyKeyObject(KCDSA_Params);

	return SCC_KCDSA_ERROR_MALLOC_FAILED;

}

int 
SC_KCDSA_DestroyKeyObject(SC_KCDSA_Parameters **KCDSA_Params)
{
	SC_KCDSA_Parameters *params = NULL; 

	if(KCDSA_Params == NULL) {
		return SCC_KCDSA_ERROR_INVALID_POINTER;
	}
	if(*KCDSA_Params == NULL) {
		return SCC_SUCCESS;
	}

	params = *KCDSA_Params;

	SC_Bigint_Free( &params->KCDSA_p );
	SC_Bigint_Free( &params->KCDSA_q );
	SC_Bigint_Free( &params->KCDSA_g );
	
	if(params->Seed != NULL) {
		SC_Memzero(params->Seed, 0x00, 512/8);
		sc_free(params->Seed);
	}
	params->SeedLen = 0;

	SC_Memzero(params, 0x00, sizeof(SC_KCDSA_Parameters));
	sc_free(params);
	*KCDSA_Params = NULL;

	return SCC_SUCCESS;
}


int SC_KCDSA_Sign(
		SC_KCDSA_Parameters	*KCDSA_Params,
		SC_BIGINT *KCDSA_x,
		U8				*MsgDigest,		//	해쉬값 Hash(z||M) 입력
		U32				MsgDigestLen,
		U8				*Signature, 
		U32				*SignLen)
{
	//	Step 0. (선택 사항) P, Q, G와 Y가 올바른지 검증.
	//	Step 1. 난수값 K를 {1, ... , Q - 1}에서 랜덤하게 선택.
	//	Step 2. 증거값 W = G^K mod P를 계산한다.
	//	Step 3. 서명의 첫 부분 R = h(W)를 계산한다.
	//	Step 4. 메시지의 해쉬코드 H = h(Z||M)을 계산한다.
	//	Step 5. 중간값 E = (R XOR H) mod Q를 계산한다
	//	Step 6. 서명의 두 번째 값 S = X(K - E) mod Q를 계산한다.
	//	Step 7. 비트열 R과 , 정수 S의 쌍을 서명으로 출력한다. 즉 S = {R, S}.
	U8		bzTmp[2048/8];
	U32		i, j, qByteLen, DigestLen;
	int		retCode;
	SC_BIGINT	BN_K, BN_Tmp1, KCDSA_s;
	SC_SHA256_CONTEXT ctx;

	SC_Bigint_New( &BN_K ); SC_Bigint_New( &BN_Tmp1 ); SC_Bigint_New( &KCDSA_s );

	if(KCDSA_Params == NULL || KCDSA_x == NULL || MsgDigest == NULL || Signature == NULL){
		retCode = SCC_KCDSA_ERROR_INVALID_INPUT;
		goto end;
	}	

	if(MsgDigestLen == 0){
		retCode = SCC_KCDSA_ERROR_INVALID_INPUTLEN;
		goto end;
	}	
	
	if(KCDSA_x->n != 8) {
		retCode = SCC_KCDSA_ERROR_INVALID_KEY_LENGTH;
		goto end;
	}
	
	
	//	Step 0 : KCDSA_PrivKey의 p, q, g, seed, x에 대한 메모리 할당이 적절하다고 가정.
	DigestLen = SCC_SHA256_DIGEST_SIZE;
	qByteLen = SC_DIGITSIZE * KCDSA_Params->KCDSA_q.n;

	//
	*SignLen = DigestLen + qByteLen;

	//	step 0. (선택 사항) 도메인 변수 P, Q, G와 공개 검증키 Y가 올바른지 검증
	//	step 1. 난수값 K를 [1, Q-1]에서 랜덤하게 선택한다.
	retCode = SC_Bigint_Fill_Random(&BN_K, SC_DIGITSIZE*qByteLen);
	if( retCode!=SCC_SUCCESS )	goto end;
	
	if( SC_Bigint_Cmp_Bignum(&BN_K, &KCDSA_Params->KCDSA_q)>=0 ) {
		retCode = SC_Bigint_Sub_Bignum(&BN_K, &BN_K, &KCDSA_Params->KCDSA_q);
		if( retCode!=SCC_SUCCESS )	goto end;
	}

	// for KAT 
	if(g_cmvp_status_id == SCC_STATUS_SELFTEST) {
		SC_Bigint_Read_String(&BN_K, 16, "0d30f8f92313f7a5abe0b0deec219e40c4640c8939222aa0dd6a332955778025");
	}

	//	step 2. 증거값 W=G^K mod P를 계산한다.
	retCode = SC_Bigint_Exp_Mod(&BN_Tmp1, &KCDSA_Params->KCDSA_g, &BN_K, &KCDSA_Params->KCDSA_p, NULL);						
	if( retCode!=SCC_SUCCESS )	goto end;

	//	step 3. 서명의 첫 부분 R=h(W)를 계산한다.
	i = SC_DIGITSIZE * KCDSA_Params->KCDSA_p.n;
	retCode = SC_Bigint_Write_Binary(&BN_Tmp1, bzTmp, i);									
	if( retCode!=SCC_SUCCESS )	goto end;
	j = i;

	SC_Memzero(&ctx, 0, sizeof(SC_SHA256_CONTEXT));

	SC_SHA256_Init(&ctx);
	SC_SHA256_Update(&ctx, bzTmp, j);
	SC_SHA256_Final(&ctx, bzTmp);
	memcpy(Signature, bzTmp, SCC_SHA256_DIGEST_SIZE);	////	Step 7

	//	step 4. 메시지의 해쉬코드 H=h(Z||M)을 계산한다.

	//	step 5. 중간값 E=(R^H) mod Q를 계산한다.
	if( DigestLen<=MsgDigestLen ) {
		for( i=0; i<DigestLen; i++)	bzTmp[i] ^= MsgDigest[i];
		for(  ; i<MsgDigestLen; i++)			bzTmp[i]  = MsgDigest[i];
	}
	else {
		for( i=0; i<MsgDigestLen; i++)			bzTmp[i] ^= MsgDigest[i];
		i = DigestLen;
	}

	retCode = SC_Bigint_Read_Binary(&BN_Tmp1, bzTmp, i);									
	if( retCode!=SCC_SUCCESS )	goto end;
	
	retCode = SC_Bigint_Mod_Bignum(&BN_Tmp1, &BN_Tmp1, &KCDSA_Params->KCDSA_q);		
	if( retCode!=SCC_SUCCESS )	goto end;

	//	step 6. 서명의 두 번째 값 S = X(K-E) mod Q를 계산한다.
	retCode = SC_Big_SubMod(&BN_K, &BN_K, &BN_Tmp1, &KCDSA_Params->KCDSA_q);	
	if( retCode!=SCC_SUCCESS )	goto end;
	
	retCode = SC_Big_MulMod(&KCDSA_s, KCDSA_x, &BN_K, &KCDSA_Params->KCDSA_q);						
	if( retCode!=SCC_SUCCESS )	goto end;

	//	step 7. 정수쌍 R, S를 서명으로 출력한다. 즉 서명 = {R, S}.
	retCode = SC_Bigint_Write_Binary(&KCDSA_s, Signature+DigestLen, qByteLen);
	if( retCode!=SCC_SUCCESS )	goto end;

	//
	retCode = SCC_SUCCESS;
end:
	 SC_Bigint_Free( &BN_K );
	 SC_Bigint_Free( &BN_Tmp1 );
	 SC_Bigint_Free( &KCDSA_s );

	return retCode;
}

int 
SC_KCDSA_Verify(SC_KCDSA_Parameters *KCDSA_Params, SC_BIGINT *KCDSA_y, U8 *MsgDigest, U32 MsgDigestLen, U8 *Signature, U32 SignLen)
{
	//	Step 0.	(선택 사항) 서명자의 인증서를 확인,
	//			서명검증에 필요한 도메인 변수 P, Q, G와 공개 검증키 Y, Z를 추출.
	//	Step 1.	수신된 서명 S={R',S'}에 대해 0< R'<2^|h( )| , 0<S'<Q 임을 확인.
	//	Step 2.	Z = h(Y)를 계산, M'에 대한 해쉬코드 H' = h(Z||M')을 계산한다.
	//	Step 3.	중간값 E' = (R' XOR H') mod Q을 계산한다.
	//	Step 4. Y를 이용하여 증거값 W' =Y^S' G^E' mod P를 계산.
	//	Step 5.	h(W') = R'이 성립하는지 확인한다.
	U8		bzTmp[2048/8];
	U32		i, j, qByteLen, DigestLen;
	int		retCode;
	SC_BIGINT		BN_Tmp1, BN_Tmp2, BN_Tmp3, KCDSA_s;
	SC_SHA256_CONTEXT ctx;

	//	Step 0 : 입력 pointer가 NULL인지 확인
	if( KCDSA_Params==NULL || KCDSA_y == NULL || MsgDigest==NULL || Signature==NULL ){
		retCode = SCC_KCDSA_ERROR_INVALID_POINTER;
		goto end;
	}	

	SC_Bigint_New( &BN_Tmp1 ); SC_Bigint_New( &BN_Tmp2 ); SC_Bigint_New( &BN_Tmp3 ); SC_Bigint_New( &KCDSA_s );
	//	Step 0 : KCDSA_PubKey의 p, q, g, seed, y에 대한 메모리 할당이 적절하다고 가정.

	//	
	DigestLen = SCC_SHA256_DIGEST_SIZE;
	qByteLen = SC_DIGITSIZE * KCDSA_Params->KCDSA_q.n;

	//
	if( SignLen!=DigestLen+qByteLen ){
		retCode = SCC_KCDSA_ERROR_INVALID_SIGNATURE_LEN;
		goto end;
	}

	//
	memcpy(bzTmp, Signature, DigestLen);
	retCode = SC_Bigint_Read_Binary(&KCDSA_s, Signature+DigestLen, qByteLen);
	if( retCode!=SCC_SUCCESS )	goto end;

	//retCode = SCC_KCDSA_ERROR_VERIFY_FAIL;
	//if( BN_Cmp(KCDSA_s, KCDSA_PubKey->KCDSA_q)>=0 )			goto end;

	//	step 0. (선택 사항) 서명자의 인증서를 확인하고,
	//			서명검증에 필요한 도메인 변수 P, Q, G와 공개 검증키 Y를 추출
	//	step 1. 수신된 서명 {R', S'}에 대해 0<R'<2^|Q|, 0<S'<Q 임을 확인한다.
	//	step 2. 서명자의 공개키에 대한 해쉬코드 Z=h(Y)를 계산하고,
	//			검증할 메시지 M'에 대한 해쉬코드 H'=h(Z||M')을 계산한다.

	//	step 3. 중간값 E'=(R'^H') mod Q을 계산한다.
	if( DigestLen<=MsgDigestLen ) {
		for( i=0; i<DigestLen; i++)	
			bzTmp[i] ^= MsgDigest[i];
		for(  ; i<MsgDigestLen; i++)			
			bzTmp[i]  = MsgDigest[i];
	}
	else {
		for( i=0; i<MsgDigestLen; i++)			
			bzTmp[i] ^= MsgDigest[i];
		i = DigestLen;
	}

	retCode = SC_Bigint_Read_Binary(&BN_Tmp1, bzTmp, i);
	if( retCode!=SCC_SUCCESS )	goto end;

	retCode = SC_Bigint_Mod_Bignum(&BN_Tmp1, &BN_Tmp1, &KCDSA_Params->KCDSA_q);
	if( retCode!=SCC_SUCCESS )	goto end;

	//	step 4. Y를 이용하여 증거값 W'=Y^{S'} G^{E'} mod P를 계산한다.
	retCode = SC_Bigint_Exp_Mod(&BN_Tmp2, KCDSA_y, &KCDSA_s, &KCDSA_Params->KCDSA_p, NULL);	
	if( retCode!=SCC_SUCCESS )	goto end;

	retCode = SC_Bigint_Exp_Mod(&BN_Tmp3, &KCDSA_Params->KCDSA_g, &BN_Tmp1, &KCDSA_Params->KCDSA_p, NULL);
	if( retCode!=SCC_SUCCESS )	goto end;

	retCode = SC_Big_MulMod(&BN_Tmp1, &BN_Tmp2, &BN_Tmp3, &KCDSA_Params->KCDSA_p);							
	if( retCode!=SCC_SUCCESS )	goto end;

	//	step 5. h(W') = R'이 성립하는지 확인한다.
	i = SC_DIGITSIZE * KCDSA_Params->KCDSA_p.n;
	retCode = SC_Bigint_Write_Binary(&BN_Tmp1, bzTmp, i);
	if( retCode!=SCC_SUCCESS )	goto end;
	j = i;
	//i = 0;

	SC_Memzero(&ctx, 0, sizeof(SC_SHA256_CONTEXT));

	SC_SHA256_Init(&ctx);
	SC_SHA256_Update(&ctx, bzTmp, j);
	SC_SHA256_Final(&ctx, bzTmp);

	retCode = SCC_KCDSA_ERROR_VERIFY_FAIL;
	if( memcmp(bzTmp, Signature, SCC_SHA256_DIGEST_SIZE)!=0 )
		goto end;

	retCode = SCC_SUCCESS;
end:
	SC_Bigint_Free( &BN_Tmp1 );
	SC_Bigint_Free( &BN_Tmp2 );
	SC_Bigint_Free( &BN_Tmp3 );
	SC_Bigint_Free( &KCDSA_s );

	return retCode;
}

