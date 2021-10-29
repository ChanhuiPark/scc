/* 
========================================
  scc_rsa.h 
    : rsa algorithm
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_RSA_H__
#define __SCC_RSA_H__

#include "scc_bignum.h"
#include "scc_protocol.h"


/* constants */
#define SC_RSA_PUBLIC      0
#define SC_RSA_PRIVATE     1

#define SC_RSA_PKCS_V15    0
#define SC_RSA_PKCS_V21    1

#define SC_RSA_SIGN        1
#define SC_RSA_CRYPT       2

#define SC_RSA_SALT_LEN_ANY    -1

/* structure */

typedef struct{
	SC_BIGINT		*n;			// modulus
	SC_BIGINT		*e;			// publicExponent
} SC_RSA_PublicKey;

typedef struct{
	SC_BIGINT		*n;			//	modulus
	SC_BIGINT		*e;			//	publicExponent
	SC_BIGINT		*d;			//	privateExponent
	SC_BIGINT		*p;			//	prime1 (optional)
	SC_BIGINT		*q;			//	prime2 (optional)
	SC_BIGINT		*dP;		//	exponent1 (optional)
	SC_BIGINT		*dQ;		//	exponent2 (optional)
	SC_BIGINT		*qInv;		//	coefficient (optional)

	SC_BIGINT		*rn;
	SC_BIGINT		*rp;
	SC_BIGINT		*rq;

	SC_BIGINT		*vi;
	SC_BIGINT		*vf;

} SC_RSA_PrivateKey;

#ifdef __cplusplus
extern "C" {
#endif



SC_RSA_PrivateKey * 
SC_RSA_PrivateKey_New(void);

void 
SC_RSA_PrivateKey_Free(SC_RSA_PrivateKey *key);

SC_RSA_PublicKey * 
SC_RSA_PublicKey_New(void);

void 
SC_RSA_PublicKey_Free(SC_RSA_PublicKey *key);

int 
SC_RSA_Check_Privkey(const SC_RSA_PrivateKey *key);

int 
SC_RSA_Check_Pubkey(const SC_RSA_PublicKey *key);

int 
SC_RSA_Check_Pub_Priv(const SC_RSA_PublicKey *pub, const SC_RSA_PrivateKey *prv);

int 
SC_RSA_Public(SC_RSA_PublicKey *key, const U8 *input, U8 *output);

int 
SC_RSA_Private(SC_RSA_PrivateKey *key, const U8 *input, U8 *output);

int 
SC_RSA_Pkcs1_Encrypt(SC_RSA_PublicKey *key, int mode, U32 ilen, const U8 *input, U8 *output);

int 
SC_RSA_Pkcs1_Decrypt(SC_RSA_PrivateKey *key, int mode, U32 *olen, const U8 *input, U8 *output, U32 output_max_len);

int
SC_RSA_Pkcs1_V15_Sign(U8 *sign, U32 *signLen, U8 *hash, int hashLen, SC_RSA_PrivateKey *pKey);

int 
SC_RSA_Pkcs1_V15_Verify(U8 *sign, U32 signLen, U8 *hash, int hashLen, SC_RSA_PublicKey *pKey);

static int 
rsa_prepare_blinding(SC_RSA_PrivateKey *key);

void 
getPublicKey1(unsigned char *output, int *outputLength);

void 
getPublicKey2(unsigned char *output, int *outputLength);

void 
getPublicKey3(unsigned char *output, int *outputLength);

void 
getPublicKey4(unsigned char *output, int *outputLength);

#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
