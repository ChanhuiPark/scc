/* 
========================================
  scc_pkey.c 
    : public key cipher 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <string.h>

#include "scc_pkey.h"
#include "scc_malloc.h"
#include "scc_error.h"
#include "scc_rsa.h"
#include "scc_kcdsa.h"
#include "scc_hash.h"
#include "scc_asn1.h"
#include "scc_cmvp.h"
#include "scc_util.h"


SC_PKEY_CTX * 
SC_PKEY_CTX_New(void)
{
	SC_PKEY_CTX *ctx;

	ctx = (SC_PKEY_CTX *)sc_calloc(sizeof(SC_PKEY_CTX), 1);

	return ctx;
}

void 
SC_PKEY_CTX_Free(SC_PKEY_CTX *ctx)
{
	if(ctx != NULL) {
		switch(ctx->opID) {
			case SC_PKEY_OPID_SIGN:
			case SC_PKEY_OPID_VERIFY:
				//	
				break;
		}

		SC_Memzero(ctx, 0x00, sizeof(SC_PKEY_CTX));
		sc_free(ctx);
	}

	return;
}

SC_PKEY_Parameters *
SC_PKEY_Parameters_New(void)
{
	SC_PKEY_Parameters *params;

	params = (SC_PKEY_Parameters *)sc_calloc(sizeof(SC_PKEY_Parameters), 1);

	return params;
}

void 
SC_PKEY_Parameters_Free(SC_PKEY_Parameters *params)
{
	if(params != NULL) {
		switch(params->pkeyID) {
			case SC_PKEY_ID_RSA:
				// not use
				break;

			case SC_PKEY_ID_KCDSA:
				SC_KCDSA_DestroyKeyObject((SC_KCDSA_Parameters **)&params->params);
				break;
		}

		SC_Memzero(params, 0x00, sizeof(SC_PKEY_Parameters));
		sc_free(params);
	}

	return;
}

SC_PKEY_PrivateKey * 
SC_PKEY_PrivateKey_New(void)
{
	SC_PKEY_PrivateKey *privKey;

	privKey = (SC_PKEY_PrivateKey *)sc_calloc(sizeof(SC_PKEY_PrivateKey), 1);

	return privKey;
}

void 
SC_PKEY_PrivateKey_Free(SC_PKEY_PrivateKey *privateKey)
{
	if(privateKey != NULL) {
		switch(privateKey->pkeyID) {
			case SC_PKEY_ID_RSA:
				SC_RSA_PrivateKey_Free(privateKey->privKey);
				break;

			case SC_PKEY_ID_KCDSA:
				SC_Bigint_Free(privateKey->privKey);
				sc_free(privateKey->privKey);
				break;
		}

		SC_Memzero(privateKey, 0x00, sizeof(SC_PKEY_PrivateKey));
		sc_free(privateKey);
	}

	return;
}

SC_PKEY_PublicKey *
SC_PKEY_PublicKey_New(void)
{
	SC_PKEY_PublicKey *pubKey;

	pubKey = (SC_PKEY_PublicKey *)sc_calloc(sizeof(SC_PKEY_PublicKey), 1);

	return pubKey;
}

void 
SC_PKEY_PublicKey_Free(SC_PKEY_PublicKey *publicKey)
{
	if(publicKey != NULL) {
		switch(publicKey->pkeyID) {
			case SC_PKEY_ID_RSA:
				SC_RSA_PublicKey_Free(publicKey->pubKey);
				break;

			case SC_PKEY_ID_KCDSA:
				SC_Bigint_Free(publicKey->pubKey);
				sc_free(publicKey->pubKey);
				break;
		}

		SC_Memzero(publicKey, 0x00, sizeof(SC_PKEY_PublicKey));
		sc_free(publicKey);
	}

	return;
}

int 
_eSequence(U8 *src, int len)
{
	int shift = 0;
	int i = 0;

	if(len >= 256) {
		shift = 4;
	}else if(len >= 128) {
		shift = 3;
	}else {
		shift = 2;
	}

	for(i=len; i>0; i--) {
		src[i+shift-1] = src[i-1];
	}

	if(len >= 256) {
		src[0] = 0x30;
		src[1] = 0x82;
		src[2] = (U8)(len / 0x100);
		src[3] = (U8)(len % 0x100);
	}else if(len >= 128) {
		src[0] = 0x30;
		src[1] = 0x81;
		src[2] = (U8)len;
	}else {
		src[0] = 0x30;
		src[1] = (U8)len;
	}

	return shift;
}

int 
SC_PKEY_Parameters_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_Parameters *params)
{
	int retCode = 0;
	SC_BIGINT *big_buf;
	SC_KCDSA_Parameters *param_buf;
	int pos = 0;
	int length = 0;
	int len_size;

	if(output == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(params->pkeyID) {
		case SC_PKEY_ID_RSA:

			break;
		case SC_PKEY_ID_KCDSA:
			if(params->params == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}

			param_buf = (SC_KCDSA_Parameters *)params->params;

			// P
			big_buf = &param_buf->KCDSA_p;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;
			
			// Q
			big_buf = &param_buf->KCDSA_q;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// G
			big_buf = &param_buf->KCDSA_g;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			pos += _eSequence(output, pos);
			

			*outputLength = pos;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
	}

end:

	return retCode;
}

int 
SC_PKEY_Parameters_FromBinary(SC_PKEY_Parameters *params,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength)
{
	int retCode = 0;
	SC_KCDSA_Parameters *param_buf;
	int pos = 0;
	const U8 *buf = input;

	int len, len_size;

	if(params==NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	params->pkeyID = pkeyID;
	retCode = SC_KCDSA_CreateKeyObject((SC_KCDSA_Parameters **)&params->params);
	if(retCode < 0) goto end;

	//buf = input;

	ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_SEQUENCE);
	ASN1_LENGTH_DECODE(buf, pos, len, len_size);

	param_buf = (SC_KCDSA_Parameters *)params->params;
	
	ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
	ASN1_LENGTH_DECODE(buf, pos, len, len_size);
	SC_Bigint_Read_Binary(&param_buf->KCDSA_p, buf+pos, len);
	pos += len;

	ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
	ASN1_LENGTH_DECODE(buf, pos, len, len_size);
	SC_Bigint_Read_Binary(&param_buf->KCDSA_q, buf+pos, len);
	pos += len;

	ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
	ASN1_LENGTH_DECODE(buf, pos, len, len_size);
	SC_Bigint_Read_Binary(&param_buf->KCDSA_g, buf+pos, len);
	//pos += len;
	
	
end:

	return retCode;

}

int 
SC_PKEY_PublicKey_ToBinary(U8 *output, U32 *outputLength,
						   const SC_PKEY_PublicKey *pubKey,
						   const SC_PKEY_Parameters *params)
{
	int retCode = 0;
	SC_BIGINT *big_buf;
	SC_RSA_PublicKey *rsaKey;
	int pos = 0;
	int length = 0;
	int pkeyID = 0;
	int len_size;

	if(output == NULL || pubKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	if(params == NULL) {
		pkeyID = SC_PKEY_ID_RSA;
	}else {
		pkeyID = SC_PKEY_ID_KCDSA;
	}

	switch(pkeyID) {
		case SC_PKEY_ID_RSA:
			
			rsaKey = (SC_RSA_PublicKey *)pubKey->pubKey;
			if(rsaKey == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}

			// n
			big_buf = rsaKey->n;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// e
			big_buf = rsaKey->e;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			break;

		case SC_PKEY_ID_KCDSA:
			if(params->params == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}

			// Y
			big_buf = pubKey->pubKey;
			if(big_buf == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;
			
			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
	}

	pos += _eSequence(output, pos);
	*outputLength = pos;

end:

	return retCode;
}

int 
SC_PKEY_PublicKey_FromBinary(SC_PKEY_PublicKey *pubKey,
							 const int pkeyID,
							 const U8 *input, const U32 inputLength,
							 const SC_PKEY_Parameters *params)
{
	int retCode = 0;
	int pos = 0;
	SC_BIGINT *big_buf;
	SC_RSA_PublicKey *rsaKey;
	const U8 *buf = input;

	int len, len_size;

	if(pubKey == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(pkeyID) {
		case SC_PKEY_ID_RSA:
			pubKey->pkeyID = SC_PKEY_ID_RSA;
			rsaKey = pubKey->pubKey = SC_RSA_PublicKey_New();

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_SEQUENCE);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);

			// n
			big_buf = rsaKey->n;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			// e
			big_buf = rsaKey->e;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			//pos += len;

			break;

		case SC_PKEY_ID_KCDSA:
			pubKey->pkeyID = SC_PKEY_ID_KCDSA;
			pubKey->pubKey = (SC_BIGINT *)sc_malloc(sizeof(SC_BIGINT));
			if (pubKey->pubKey == NULL) {
				retCode = SCC_BIGNUM_ERROR_ALLOC_FAILED;
				goto end;
			}

			SC_Bigint_New(pubKey->pubKey);

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_SEQUENCE);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);

			big_buf = (SC_BIGINT *)pubKey->pubKey;

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			//pos += len;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;

	}

end:
	
	return retCode;
}

int 
SC_PKEY_PrivateKey_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_PrivateKey *privKey,
							const SC_PKEY_Parameters *params)
{
	int retCode = 0;
	SC_BIGINT *big_buf;
	int pos = 0;
	int length = 0;
	int pkeyID = 0;
	SC_RSA_PrivateKey *rsaKey;
	int len_size;

	if(output == NULL || privKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	if(params == NULL) {
		pkeyID = SC_PKEY_ID_RSA;
	}else {
		pkeyID = SC_PKEY_ID_KCDSA;
	}

	switch(pkeyID) {
		case SC_PKEY_ID_RSA:

			rsaKey = (SC_RSA_PrivateKey *)privKey->privKey;
			if(rsaKey == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}
			
			// n
			big_buf = rsaKey->n;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// e
			big_buf = rsaKey->e;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// d
			big_buf = rsaKey->d;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// p
			big_buf = rsaKey->p;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// q
			big_buf = rsaKey->q;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// dP
			big_buf = rsaKey->dP;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// dQ
			big_buf = rsaKey->dQ;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			// qInv
			big_buf = rsaKey->qInv;
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;
			
			break;

		case SC_PKEY_ID_KCDSA:
			if(params->params == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}

			// X
			big_buf = privKey->privKey;
			if(big_buf == NULL) {
				return SCC_COMMON_ERROR_INVALID_INPUT;
			}
			length = (big_buf->n) * 4;
			
			ASN1_TYPE_ENCODE(output, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_ENCODE(output, pos, len_size, length);
			retCode = SC_Bigint_Write_Binary(big_buf, output+pos, length);
			if(retCode < 0) goto end;
			pos += length;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
	}

	pos += _eSequence(output, pos);
	*outputLength = pos;

end:

	return retCode;
}

int 
SC_PKEY_PrivateKey_FromBinary(SC_PKEY_PrivateKey *privKey,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength,
							  const SC_PKEY_Parameters *params)
{
	int retCode = 0;
	int pos = 0;
	SC_BIGINT *big_buf;
	SC_RSA_PrivateKey *rsaKey;
	const U8 *buf = input;

	int len, len_size;

	if(privKey == NULL || input == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(pkeyID) {
		case SC_PKEY_ID_RSA:
			if (params)
				return SCC_COMMON_ERROR_INVALID_INPUT;

			privKey->pkeyID = SC_PKEY_ID_RSA;
			rsaKey = privKey->privKey = SC_RSA_PrivateKey_New();

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_SEQUENCE);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);

			// n
			big_buf = rsaKey->n;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			// e
			big_buf = rsaKey->e;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			// d
			big_buf = rsaKey->d;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			// p
			big_buf = rsaKey->p;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			// q
			big_buf = rsaKey->q;
			
			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			pos += len;

			if(pos < (int)inputLength) {
				// dP
				big_buf = rsaKey->dP;
			
				ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
				ASN1_LENGTH_DECODE(buf, pos, len, len_size);
				SC_Bigint_Read_Binary(big_buf, buf+pos, len);
				pos += len;

				// dQ
				big_buf = rsaKey->dQ;
			
				ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
				ASN1_LENGTH_DECODE(buf, pos, len, len_size);
				SC_Bigint_Read_Binary(big_buf, buf+pos, len);
				pos += len;

				// qInv
				big_buf = rsaKey->qInv;
			
				ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
				ASN1_LENGTH_DECODE(buf, pos, len, len_size);
				SC_Bigint_Read_Binary(big_buf, buf+pos, len);
				//pos += len;
			}

			break;

		case SC_PKEY_ID_KCDSA:
			if (!params)
				return SCC_COMMON_ERROR_INVALID_INPUT;

			privKey->pkeyID = SC_PKEY_ID_KCDSA;
			privKey->privKey = (SC_BIGINT *)sc_malloc(sizeof(SC_BIGINT));
			if (privKey->privKey == NULL) {
				retCode = SCC_BIGNUM_ERROR_ALLOC_FAILED;
				goto end;
			}
			SC_Bigint_New(privKey->privKey);

			big_buf = (SC_BIGINT *)privKey->privKey;

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_SEQUENCE);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);

			ASN1_TYPE_CHECK(buf, pos, SC_ASN1_TAG_INTEGER);
			ASN1_LENGTH_DECODE(buf, pos, len, len_size);
			SC_Bigint_Read_Binary(big_buf, buf+pos, len);
			//pos += len;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;

	}

end:

	return retCode;
}


int 
SC_PKEY_CheckKeyPair(SC_PKEY_PrivateKey *privKey, 
					 SC_PKEY_PublicKey *pubKey, 
					 const int pkeyID)
{
	int retCode = 0;

	switch(pkeyID) {
		case SC_PKEY_ID_RSA:
			privKey->pkeyID  = SC_PKEY_ID_RSA;
			pubKey->pkeyID  = SC_PKEY_ID_RSA;

			retCode = SC_RSA_Check_Pub_Priv((SC_RSA_PublicKey *)pubKey->pubKey, (SC_RSA_PrivateKey *)privKey->privKey);
			if(retCode < 0) goto end;

		break;

		default:
			retCode = SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
	}

end:
	return retCode;
}

int 
SC_PKEY_Encrypt(U8 *cipher, U32 *cipherLength, 
				const U8 *plain, const U32 plainLength, 
				const int pencID, 
				const SC_PKEY_PublicKey * pubKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam)
{
	int retCode = 0;

	if(cipher == NULL || plain == NULL || plainLength == 0 || pubKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(pencID) {
		case SC_PKEY_PENCID_RSA_OAEP:
			// check key id
			if (pubKey->pkeyID != SC_PKEY_ID_RSA) {
				retCode = SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
				goto end;
			}

			retCode = SC_RSA_Check_Pubkey(pubKey->pubKey);
			if(retCode < 0) goto end;
						
			// encrypt
			retCode = SC_RSA_Pkcs1_Encrypt(pubKey->pubKey, SC_RSA_PKCS_V21, plainLength, plain, cipher);
			if(retCode < 0) goto end;

			*cipherLength = retCode;
			retCode = 0;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PENC_ID;
	}

end:
	return retCode;
}

int 
SC_PKEY_Decrypt(U8 *plain, U32 *plainLength, 
				const U8 *cipher, const U32 cipherLength, 
				const int pencID, 
				const SC_PKEY_PrivateKey * privKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam)
{

	int retCode = 0;

	if(plain == NULL || cipher == NULL || cipherLength != 256 || privKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(pencID) {
		case SC_PKEY_PENCID_RSA_OAEP:

			// check key id
			if (privKey->pkeyID != SC_PKEY_ID_RSA) {
				retCode = SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
				goto end;
			}

			// check key pair
			retCode = SC_RSA_Check_Privkey(privKey->privKey);
			if(retCode < 0) goto end;

			// decrypt
			retCode = SC_RSA_Pkcs1_Decrypt(privKey->privKey, SC_RSA_PKCS_V21, plainLength, cipher, plain, 256);
			if(retCode < 0) goto end;
			
			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_PENC_ID;
	}

end:
	return retCode;

}

int 
SC_PKEY_Sign(U8 *signature, U32 *signatureLength,
			 const int msgID,
			 const U8 *message, const U32 messageLength,
			 const int signID,
			 const SC_PKEY_PrivateKey *privKey,
			 const SC_PKEY_Parameters *params,
			 const SC_PKEY_SignParam * signParam)
{
	int retCode = 0;
	U8 hash[SCC_SHA256_DIGEST_SIZE] = {0x00,};
	U32 hashLength = 0;
	SC_PKEY_PublicKey *pubKey = NULL;
	SC_BIGINT *pubkey = NULL;
	U8 buffer[4096] = {0x00,};
	U32 bufferLength = 0;
	SC_HASH_CTX ctx;

	if(signature == NULL || message == NULL || messageLength == 0 || privKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(signID) {
		case SC_PKEY_SIGNID_KCDSA_SHA256:

			// check key id
			if (privKey->pkeyID != SC_PKEY_ID_KCDSA) {
				retCode = SCC_PKEY_ERROR_UNKNOWN_PKEY_ID;
				goto end;
			}

			if(msgID == SC_PKEY_MSGID_MESSAGE) {
				if(signParam == NULL) {
					return SCC_KCDSA_ERROR_INVALID_INPUT;
				}

				pubKey = (SC_PKEY_PublicKey *)signParam->kcdsa.pkPubKey;
				if(pubKey == NULL) {
					return SCC_KCDSA_ERROR_INVALID_INPUT;
				}

				pubkey = sc_calloc(sizeof(SC_BIGINT), 1);
				if(pubkey == NULL) {
					return SCC_KCDSA_ERROR_MALLOC_FAILED;
				}
				SC_Bigint_New(pubkey);

				retCode = SC_Bigint_Copy(pubkey, pubKey->pubKey);
				if(retCode < 0) goto end;
				
				bufferLength = SC_Bigint_Size((SC_BIGINT *)pubKey->pubKey);
				retCode = SC_Bigint_Write_Binary(pubkey, buffer, bufferLength);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Init(&ctx, SCC_HASH_ID_SHA256);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Update(&ctx, buffer + bufferLength - SCC_SHA256_BLOCK_SIZE, SCC_SHA256_BLOCK_SIZE);
				if(retCode < 0) goto end;

				// hash
				retCode = SC_Hash_Update(&ctx, message, messageLength);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Final(&ctx, hash, &hashLength);
				if(retCode < 0) goto end;
				
			}else {
				if(messageLength != SCC_SHA256_DIGEST_SIZE) {
					return SCC_KCDSA_ERROR_INVALID_DATALEN;
				}

				memcpy(hash, message, messageLength);
				hashLength = messageLength;
			}

			// sign
			retCode = SC_KCDSA_Sign((SC_KCDSA_Parameters *)params->params, privKey->privKey, hash, hashLength, signature,signatureLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_SIGN_ID;
	}

end:
	if(pubkey != NULL) {
		SC_Bigint_Free(pubkey);
		sc_free(pubkey);
	}

	return retCode;
}

int 
SC_PKEY_Verify(U8 *signature, U32 signatureLength, 
			   const int msgID, 
			   const U8 *message, const U32 messageLength, 
			   const int signID, 
			   const SC_PKEY_PublicKey *pubKey, 
			   const SC_PKEY_Parameters *params, 
			   const SC_PKEY_SignParam * signParam)
{
	int retCode = 0;
	U8 hash[32] = {0x00,};
	U32 hashLength = 0;

	U8 buffer[4096] = {0x00,};
	U32 bufferLength = 0;
	SC_HASH_CTX ctx;

	if(signature == NULL || message == NULL || messageLength == 0 || pubKey == NULL) {
		return SCC_COMMON_ERROR_INVALID_INPUT;
	}

	switch(signID) {
		case SC_PKEY_SIGNID_KCDSA_SHA256:

			// check key id
			if (pubKey->pkeyID != SC_PKEY_ID_KCDSA) {
				retCode = SCC_PKEY_ERROR_UNKNOWN_PENC_ID;
				goto end;
			}

			if(msgID == SC_PKEY_MSGID_MESSAGE) {

				bufferLength = SC_Bigint_Size((SC_BIGINT *)pubKey->pubKey);
				retCode = SC_Bigint_Write_Binary((SC_BIGINT *)pubKey->pubKey, buffer, bufferLength);
				if(retCode < 0) goto end;

				// hash(Z||M)
				retCode = SC_Hash_Init(&ctx, SCC_HASH_ID_SHA256);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Update(&ctx, buffer + bufferLength - SCC_SHA256_BLOCK_SIZE, SCC_SHA256_BLOCK_SIZE);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Update(&ctx, message, messageLength);
				if(retCode < 0) goto end;

				retCode = SC_Hash_Final(&ctx, hash, &hashLength);
				if(retCode < 0) goto end;
				
			}else {
				memcpy(hash, message, messageLength);
				hashLength = messageLength;
			}

			// verify
			retCode = SC_KCDSA_Verify((SC_KCDSA_Parameters *)params->params, pubKey->pubKey, hash, hashLength, signature, signatureLength);
			if(retCode < 0) goto end;

			break;

		default:
			return SCC_PKEY_ERROR_UNKNOWN_SIGN_ID;
	}

end:
	return retCode;
}

