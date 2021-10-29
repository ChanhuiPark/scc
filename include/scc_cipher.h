/* 
========================================
  scc_cipher.h 
    : cipher function
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_CIPHER_H__
#define __SCC_CIPHER_H__

#include "scc_protocol.h"
#include "scc_aria.h"


typedef struct {
	int cipherID;
	U8 key[SCC_CIPHER_MAX_KEY_SIZE];
	U32 keyLength;
} SC_SKEY_SecretKey;

typedef struct {
	int cipherID;
	union {
		SC_ARIA_CONTEXT aria;
	}cipherKey;
} SC_CIPHER_CTX;

typedef struct {
	U8 iv[SCC_CIPHER_MAX_IV_SIZE];
	U32 ivLength;
	U32 modeSize;
} SC_CIPHER_MODE_PARAM;

typedef struct {
	int modeID;
	SC_CIPHER_MODE_PARAM modeParam;
	int paddingID;
} SC_CIPHER_PARAM;


// Secret Key
SC_SKEY_SecretKey *
SC_SKEY_SecretKey_New(void);

void
SC_SKEY_SecretKey_Free(SC_SKEY_SecretKey *key);

int 
SC_SKEY_GenerateKey(SC_SKEY_SecretKey *key, const int keyID, const U32 keyLength);

// Context
SC_CIPHER_CTX *
SC_CIPHER_CTX_New(void);

void 
SC_CIPHER_CTX_Free(SC_CIPHER_CTX *ctx);

// Encrypt
int 
SC_Cipher_Encrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);

int 
SC_Cipher_Encrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength);

int 
SC_Cipher_Encrypt_Final(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength);

int 
SC_Cipher_Encrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);

// Decrypt
int 
SC_Cipher_Decrypt_Init(SC_CIPHER_CTX *ctx, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);

int 
SC_Cipher_Decrypt_Update(SC_CIPHER_CTX *ctx, U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength);

int 
SC_Cipher_Decrypt_Final(SC_CIPHER_CTX *ctx, U32 *paddingLength);

int
SC_Cipher_Decrypt(U8 *output, U32 *outputLength, const U8 *input, const U32 inputLength, const SC_SKEY_SecretKey *key, const int cipherID, const SC_CIPHER_PARAM *param);


#endif
