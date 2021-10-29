/* 
========================================
  scc_main.h 
    : crypto main 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_MAIN_H__
#define __SCC_MAIN_H__

#include "scc_protocol.h"
#include "scc_cipher.h"
#include "scc_hash.h"
#include "scc_mac.h"
#include "scc_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library */
int 
SCC_CM_Initialize(void);

int 
SCC_CM_Finalize(void);

char *
SCC_CM_GetVersion(void);

char *
SCC_CM_GetErrorString(const int errorCode);

int
SCC_CM_GetState(void);

int 
SCC_CM_ChangeState(const int stateID);

int 
SCC_CM_SelfTest(void);

/* Block Cipher */
// Secret Key
SC_SKEY_SecretKey *
SCC_SKEY_SecretKey_New(void);

void
SCC_SKEY_SecretKey_Free(SC_SKEY_SecretKey *key);

int 
SCC_SKEY_GenerateKey(SC_SKEY_SecretKey *key, const int keyID, const U32 keyLength);

// Context
SC_CIPHER_CTX *
SCC_CIPHER_CTX_New(void);

void 
SCC_CIPHER_CTX_Free(SC_CIPHER_CTX *ctx);

// Encode
int 
SCC_CIPHER_Encrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);

int 
SCC_CIPHER_Encrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength);

int 
SCC_CIPHER_Encrypt_Final(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength);

int 
SCC_CIPHER_Encrypt(U8 *output, U32 *outputLength, 
				   const U8 *input, const U32 inputLength, 
				   const SC_SKEY_SecretKey *key, 
				   const int cipherID, 
				   const SC_CIPHER_PARAM *param);

// Decode
int 
SCC_CIPHER_Decrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);

int 
SCC_CIPHER_Decrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength);

int 
SCC_CIPHER_Decrypt_Final(SC_CIPHER_CTX *ctx, U32 *paddingLength);

int
SCC_CIPHER_Decrypt(U8 *output, U32 *outputLength, 
				   const U8 *input, const U32 inputLength, 
				   const SC_SKEY_SecretKey *key, 
				   const int cipherID, 
				   const SC_CIPHER_PARAM *param);

/* Message Digest */
SC_HASH_CTX * 
SCC_HASH_CTX_New(void);

void 
SCC_HASH_CTX_Free(SC_HASH_CTX *hashCtx);

int 
SCC_HASH_Init(SC_HASH_CTX *hashCtx, const int hashID);

int 
SCC_HASH_Update(SC_HASH_CTX *hashCtx, const U8 *input, const U32 inputLength);

int 
SCC_HASH_Final(SC_HASH_CTX *hashCtx, U8 *hash, U32 *hashLength);

int 
SCC_HASH(U8 *hash, U32 *hashLength, U8 *input, U32 inputLength, const int hashID);

/* Mac */
SC_MAC_CTX * 
SCC_MAC_CTX_New(void);

void 
SCC_MAC_CTX_Free(SC_MAC_CTX *macCtx);

int
SCC_MAC_Init(SC_MAC_CTX *macCtx, const SC_SKEY_SecretKey *key, const int macID);

int 
SCC_MAC_Update(SC_MAC_CTX *macCtx, const U8 *input, const U32 inputLength);

int 
SCC_MAC_Final(SC_MAC_CTX *macCtx, U8 *mac, U32 *macLength);

int 
SCC_MAC(U8 *mac, U32 *macLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int macID);

/* Random */
int 
SCC_RAND(U8* output, const U32 outputLength);
int 
SCC_RAND_Final(void);

/* RSA & KCDSA */

SC_PKEY_Parameters *
SCC_PKEY_Parameters_New(void);

void 
SCC_PKEY_Parameters_Free(SC_PKEY_Parameters *params);

SC_PKEY_PrivateKey * 
SCC_PKEY_PrivateKey_New(void);

void 
SCC_PKEY_PrivateKey_Free(SC_PKEY_PrivateKey *privateKey);

SC_PKEY_PublicKey *
SCC_PKEY_PublicKey_New(void);

void 
SCC_PKEY_PublicKey_Free(SC_PKEY_PublicKey *publicKey);

int 
SCC_PKEY_Parameters_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_Parameters *params);

int 
SCC_PKEY_Parameters_FromBinary(SC_PKEY_Parameters *params,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength);

int 
SCC_PKEY_PrivateKey_ToBinary(U8 *output, U32 *outputLength,
							 const SC_PKEY_PrivateKey *privKey,
							 const SC_PKEY_Parameters *params);

int 
SCC_PKEY_PrivateKey_FromBinary(SC_PKEY_PrivateKey *privKey,
							   const int pkeyID,
							   const U8 *input, const U32 inputLength,
							   const SC_PKEY_Parameters *params);

int 
SCC_PKEY_PublicKey_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_PublicKey *pubKey,
							const SC_PKEY_Parameters *params);

int 
SCC_PKEY_PublicKey_FromBinary(SC_PKEY_PublicKey *pubKey,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength,
							  const SC_PKEY_Parameters *params);

int 
SCC_PKEY_Encrypt(U8 *cipher, U32 *cipherLength, 
				const U8 *plain, const U32 plainLength, 
				const int pencID, 
				const SC_PKEY_PublicKey * pubKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam);

int 
SCC_PKEY_Decrypt(U8 *plain, U32 *plainLength, 
				const U8 *cipher, const U32 cipherLength, 
				const int pencID, 
				const SC_PKEY_PrivateKey * privKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam);

int 
SCC_PKEY_Sign(U8 *signature, U32 *signatureLength,
			 const int msgID,
			 const U8 *message, const U32 messageLength,
			 const int signID,
			 const SC_PKEY_PrivateKey *privKey,
			 const SC_PKEY_Parameters *params,
			 const SC_PKEY_SignParam * signParam);

int 
SCC_PKEY_Verify(U8 *signature, U32 signatureLength, 
			   const int msgID, 
			   const U8 *message, const U32 messageLength, 
			   const int signID, 
			   const SC_PKEY_PublicKey *pubKey, 
			   const SC_PKEY_Parameters *params, 
			   const SC_PKEY_SignParam * signParam);

#ifdef __cplusplus
}
#endif

#endif
