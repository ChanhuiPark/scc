/* 
========================================
  scc_pkey.h 
    : public key cryptography
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_PKEY_H__
#define __SCC_PKEY_H__

#include "scc_protocol.h"

#define SC_PKEY_ID_RSA				1
#define SC_PKEY_ID_KCDSA			2

#define SC_PKEY_PENCID_RSA_OAEP		2

#define	SC_PKEY_SIGNID_KCDSA_SHA256			4

#define SC_PKEY_MSGID_MESSAGE	1
#define SC_PKEY_MSGID_HASH		2


#define	SC_PKEY_OPID_SIGN			1
#define	SC_PKEY_OPID_VERIFY			2

typedef struct {
	int opID;
	void *opCtx;
} SC_PKEY_CTX;

typedef struct {
	int			pkeyID;
	void		*params;
} SC_PKEY_Parameters;

typedef struct {
	int			typeID;
	int			pkeyID;
	void		*privKey;
} SC_PKEY_PrivateKey;

typedef struct {
	int			typeID;
	int			pkeyID;
	void		*pubKey;
} SC_PKEY_PublicKey;


typedef struct {
	int hashID;
	int mgfID;
	int sourceID;
	U8 *source;
	U32 sourceLength;
} SC_PKCS1_OAEP_PARAM;

typedef union {
	SC_PKCS1_OAEP_PARAM rsa_oaep;
} SC_PKEY_PEncParam;

typedef struct {
	int	hashID;
	int	mgfID;
} SC_PKCS1_PSS_PARAM;

typedef union {
	SC_PKCS1_PSS_PARAM rsa_pss;
	struct {
		SC_PKEY_PublicKey *pkPubKey;
	} kcdsa;
} SC_PKEY_SignParam;

#ifdef __cplusplus
extern "C" {
#endif

SC_PKEY_CTX * 
SC_PKEY_CTX_New(void);

void 
SC_PKEY_CTX_Free(SC_PKEY_CTX *ctx);

SC_PKEY_Parameters *
SC_PKEY_Parameters_New(void);

void 
SC_PKEY_Parameters_Free(SC_PKEY_Parameters *params);

SC_PKEY_PrivateKey * 
SC_PKEY_PrivateKey_New(void);

void 
SC_PKEY_PrivateKey_Free(SC_PKEY_PrivateKey *privateKey);

SC_PKEY_PublicKey *
SC_PKEY_PublicKey_New(void);

void 
SC_PKEY_PublicKey_Free(SC_PKEY_PublicKey *publicKey);

int 
SC_PKEY_Parameters_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_Parameters *params);

int 
SC_PKEY_Parameters_FromBinary(SC_PKEY_Parameters *params,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength);

int 
SC_PKEY_PublicKey_ToBinary(U8 *output, U32 *outputLength,
							const SC_PKEY_PublicKey *pubKey,
							const SC_PKEY_Parameters *params);

int 
SC_PKEY_PublicKey_FromBinary(SC_PKEY_PublicKey *pubKey,
							  const int pkeyID,
							  const U8 *input, const U32 inputLength,
							  const SC_PKEY_Parameters *params);

int 
SC_PKEY_PrivateKey_ToBinary(U8 *output, U32 *outputLength,
							 const SC_PKEY_PrivateKey *privKey,
							 const SC_PKEY_Parameters *params);

int 
SC_PKEY_PrivateKey_FromBinary(SC_PKEY_PrivateKey *privKey,
							   const int pkeyID,
							   const U8 *input, const U32 inputLength,
							   const SC_PKEY_Parameters *params);

int 
SC_PKEY_CheckKeyPair(SC_PKEY_PrivateKey *privKey, 
					 SC_PKEY_PublicKey *pubKey, 
					 const int pkeyID);

int 
SC_PKEY_Encrypt(U8 *cipher, U32 *cipherLength, 
				const U8 *plain, const U32 plainLength, 
				const int pencID, 
				const SC_PKEY_PublicKey * pubKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam);

int 
SC_PKEY_Decrypt(U8 *plain, U32 *plainLength, 
				const U8 *cipher, const U32 cipherLength, 
				const int pencID, 
				const SC_PKEY_PrivateKey * privKey, 
				const SC_PKEY_Parameters *params, 
				const SC_PKEY_PEncParam *encParam);

int 
SC_PKEY_Sign(U8 *signature, U32 *signatureLength,
			 const int msgID,
			 const U8 *message, const U32 messageLength,
			 const int signID,
			 const SC_PKEY_PrivateKey *privKey,
			 const SC_PKEY_Parameters *params,
			 const SC_PKEY_SignParam * signParam);

int 
SC_PKEY_Verify(U8 *signature, U32 signatureLength, 
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
