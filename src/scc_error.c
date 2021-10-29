/* 
========================================
  scc_error.c 
    : error code
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdlib.h>
#ifdef	_WIN32
#include <windows.h>
#endif

#include "scc_error.h"
#include "scc_cmvp.h"

/**
 *
 *
 *
 */
char *
SC_GetErrorString(const int errorCode)
{
	switch (errorCode) {
	case SCC_SUCCESS:						return "Success";

	case SCC_COMMON_ERROR_INVALID_INPUT :	return "Invalid input";
	case SCC_COMMON_ERROR_INTERNAL :		return "Internal error";
	case SCC_COMMON_ERROR_MALLOC_FAILED :	return "Malloc failed";

	// SCSELFTEST 50~
	case SCC_SELFTEST_ERROR_ENTROPY_COMPARE :			return "Entropy compare failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_ARIA_KAT:			return "ARIA KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_HASH_SHA256_KAT:	return "Hash SHA256 KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_HASH_SHA512_KAT:	return "Hash SHA512 KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_HMAC_SHA256_KAT:	return "HMAC SHA256 KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_HMAC_SHA512_KAT:	return "HMAC SHA512 KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_RSA_KAT:			return "RSA KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_KCDSA_KAT:		return "KCDSA KAT failed";
	case SCC_SELFTEST_ERROR_ALGORITHM_DRBG_KAT:			return "DRBG KAT failed";
	case SCC_SELFTEST_ERROR_INTEGRITY:					return "Integrity failed";

	// SCMAIN 100~
	case SCC_MAIN_ERROR_NOT_IMPLEMENTED :			return "crypto function is not implemented";
	case SCC_MAIN_ERROR_SELFTESTCASE_FAILED:		return "SelfTestCase failed ";
	
	// SCCMVP 120~ 
	case SCC_CMVP_ERROR_STATE_NOT_ALLOWED:			return "Not allowed cmvp state";
	case SCC_CMVP_ERROR_UNKNOWN_STATEID:			return "Unknown State ID";
	case SCC_CMVP_ERROR_STATE_IN_FINALIZED:			return "Cmvp state in Finalized";
	case SCC_CMVP_CIPHER_ERROR_UNKNOWN_ID:			return "Unknown Cipher ID";
	case SCC_CMVP_HASH_ERROR_UNKNOWN_ID:			return "Unknown Hash ID";
	case SCC_CMVP_ERROR_STATE_IN_ERROR:				return "Cmvp State In Error";
	case SCC_CMVP_ERROR_CHECKPARAM_UNKNOWN_MODE:	return "Unknown parameter mode";
	case SCC_CMVP_ERROR_CHECKPARAM_UNKNOWN_PADDING:	return "Unknown padding";
	case SCC_CMVP_ERROR_NOT_INITIALIZED:			return "Cmvp Not Initialized";
	case SCC_CMVP_ERROR_SELFTEST_FAILED:			return "Cmvp Selftest Fail";
	case SCC_CMVP_MAC_ERROR_UNKNOWN_ID:				return "Unknown MAC ID";
	case SCC_CMVP_PKEY_ERROR_UNKNOWN_ID:			return "Unknown PublicKey ID";
	case SCC_CMVP_PENC_ERROR_UNKNOWN_ID:			return "Unknown PublicKey encryption ID";
	case SCC_CMVP_SIGN_ERROR_UNKNOWN_ID:			return "Unknown sign ID";
	
	// SCCIPHER 140~
	case SCC_CIPHER_ERROR_UNKNOWN_ID :		return "Unkown Cipher ID";
	case SCC_CIPHER_ERROR_UNKNOWN_PADDING :	return "Unkown Cipher Padding";
	case SCC_CIPHER_ERROR_INVALID_PADDING :	return "Cipher IV length is invalid";
	case SCC_CIPHER_ERROR_IV_LENGTH :		return "Cipher IV length is invalid";
	case SCC_CIPHER_ERROR_MODE_SIZE :		return "Cipher mode size is invalid";
	case SCC_CIPHER_ERROR_KEY_LENGTH :		return "Cipher key length is invalid";
	case SCC_CIPHER_ERROR_ENCRYPT_FAILED :	return "Cipher encrypt is failed";
	case SCC_CIPHER_ERROR_DECRYPT_FAILED :	return "Cipher decrypt is failed";
	
	// ARIA 160~
	case SCC_ARIA_ERROR_INVALID_INPUT:		return "Invalid ARIA input";
	case SCC_ARIA_ERROR_KEY_LENGTH:			return "Invalid ARIA key length";
	case SCC_ARIA_ERROR_INVALID_PADDING:	return "Invalid ARIA padding";
	case SCC_ARIA_ERROR_ENCRYPT_FAILED:		return "ARIA Encrypt Fail";
	case SCC_ARIA_ERROR_IV_LENGTH:			return "Invalid ARIA IV length";
	case SCC_ARIA_ERROR_DECRYPT_FAILED:		return "ARIA Decrypt Fail";

	// SCSHA 170~
	case SCC_SHA256_ERROR_INVALID_INPUT:		return "Invalid SHA256 Input";
	case SCC_SHA256_ERROR_INVALID_INPUTLEN:		return "Invalid SHA256 Input Length";
	case SCC_SHA512_ERROR_INVALID_INPUT:		return "Invalid SHA512 Input";
	case SCC_SHA512_ERROR_INVALID_INPUTLEN:		return "Invalid SHA512 Input Length";

	// SCHMACSHA 180~
	case SCC_HMACSHA256_ERROR_INVALID_INPUT:		return "Invalid HMAC SHA256 Input";
	case SCC_HMACSHA256_ERROR_INVALID_INPUTLEN:		return "Invalid HMAC SHA256 Input Length";
	case SCC_HMACSHA512_ERROR_INVALID_INPUT:		return "Invalid HMAC SHA512 Input";
	case SCC_HMACSHA512_ERROR_INVALID_INPUTLEN:		return "Invalid HMAC SHA512 Input Length";

	// SCBIGINT 200~
	case SCC_BIGNUM_ERROR_FILE_IO_ERROR:		return "Bigint File IO ERROR";
	case SCC_BIGNUM_ERROR_BAD_INPUT_DATA:		return "Bad Bigint Input Data";
	case SCC_BIGNUM_ERROR_INVALID_CHARACTER:	return "Invalid Bigint Character";
	case SCC_BIGNUM_ERROR_BUFFER_TOO_SMALL:		return "Bigint Buffer too small";
	case SCC_BIGNUM_ERROR_NEGATIVE_VALUE:		return "Bigint negative data";
	case SCC_BIGNUM_ERROR_DIVISION_BY_ZERO:		return "Bigint Division by Zero";
	case SCC_BIGNUM_ERROR_NOT_ACCEPTABLE:		return "Bigint Not Acceptable";
	case SCC_BIGNUM_ERROR_ALLOC_FAILED:			return "Bigint Alloc Failed";

	// SCBIGINTKCDSA 250~
	case SCC_BIGNUMKCDSA_ERROR_VERIFY_FAIL:			return "Bigint KCDSA Verify Fail";
	case SCC_BIGNUMKCDSA_ERROR_BUFFER_TOO_SMALL:	return "Bigint KCDSA Buffer to small";
	case SCC_BIGNUMKCDSA_ERROR_OVER_MODULUS:		return "Bigint KCDSA Over Modulus";
	case SCC_BIGNUMKCDSA_ERROR_MEMORY_ALLOC_FAILED:	return "Bigint KCDSA Memory Alloc Fail";
	case SCC_BIGNUMKCDSA_ERROR_BN_NEGATIVE_RESULT:	return "Bigint KCDSA Negative Result";

	// SCRSA 300~
	case SCC_RSA_ERROR_BAD_INPUT_DATA:					return "Invalid RSA Input Data";
	case SCC_RSA_ERROR_INVALID_PADDING:					return "Invalid RSA Input Padding";
	case SCC_RSA_ERROR_KEY_CHECK_FAILED:				return "Check RSA Key Fail";
	case SCC_RSA_ERROR_PUBLIC_FAILED:					return "RSA Public Fail";
	case SCC_RSA_ERROR_PRIVATE_FAILED:					return "RSA Private Fail";
	case SCC_RSA_ERROR_VERIFY_FAILED:					return "RSA Verify Fail";
	case SCC_RSA_ERROR_OUTPUT_TOO_LARGE:				return "RSA Output too large";
	case SCC_RSA_ERROR_RNG_FAILED:						return "RSA Random Generate Fail";
	case SCC_RSA_ERROR_MEMORY_ALLOC_FAILED:				return "RSA Memory Alloc Fail";
	case SCC_RSA_ERROR_INTENDED_MSG_LENGTH_TOO_SHORT:	return "RSA Intended Message Length too short";
	case SCC_RSA_ERROR_MODULUS_TOO_SHORT:				return "RSA Modulus too short";
	case SCC_RSA_ERROR_INVALID_SIGNATURE:				return "Invalid RSA Signature";
	case SCC_RSA_ERROR_INVALID_DATALEN:					return "Invalid RSA Data Length";
	case SCC_RSA_ERROR_INVALID_KEYLEN:					return "Invalid RSA Key Length";
	
	// SCENTROPY 400~
	case SCC_ENTROPY_ERROR_BAD_INPUT_DATA:		return "Bad Entropy Input Data";
	case SCC_ENTROPY_ERROR_INVALID_PADDING:		return "Invalid Entropy Padding";

	// SCHASHDRBG 500~
	case SCC_HASHDRBG_ERROR_INVALID_INPUT:		return "Invalid Hash DRBG Input";
	case SCC_HASHDRBG_ERROR_INVALID_INPUTLEN:	return "Invalid Hash DRBG Input Length";
	case SCC_HASHDRBG_ERROR_INVALID_LIMITREQ:	return "Invalid Hash DRBG LIMITREQ";
	case SCC_HASHDRBG_ERROR_MALLOC_FAILED:		return "Hash DRBG Malloc Failed";

	// SCKCDSA 600~
	case SCC_KCDSA_ERROR_INVALID_INPUT:			return "Invalid KCDSA Input";
	case SCC_KCDSA_ERROR_INVALID_INPUTLEN:		return "Invalid KCDSA Input Length";
	case SCC_KCDSA_ERROR_MALLOC_FAILED:			return "KCDSA Malloc Failed";
	case SCC_KCDSA_ERROR_INVALID_POINTER:		return "Invalid KCDSA Pointer";
	case SCC_KCDSA_ERROR_INVALID_KEYFILE:		return "Invalid KCDSA Key File";
	case SCC_KCDSA_ERROR_INVALID_ALG_PARAMS:	return "Invalid KCDSA Algorithm Parameters";
	case SCC_KCDSA_ERROR_BUFFER_TOO_SMALL:		return "KCDSA Buffer too small";
	case SCC_KCDSA_ERROR_INVALID_DATALEN:		return "Invalid KCDSA Data Length";
	case SCC_KCDSA_ERROR_INVALID_SIGNATURE_LEN:	return "Invalid KCDSA Signature Length";
	case SCC_KCDSA_ERROR_VERIFY_FAIL:			return "KCDSA Verify Fail";

	// SCPKEY 700~
	case SCC_PKEY_ERROR_UNKNOWN_PKEY_ID:		return "Unknown PKEY ID";
	case SCC_PKEY_ERROR_UNKNOWN_PENC_ID:		return "Unknown PENC ID";
	case SCC_PKEY_ERROR_UNKNOWN_SIGN_ID:		return "Unknown SIGN ID";

	// SCASN1 800~
	case SCC_ASN1_ERROR_BAD_DATA:			return "Bad ASN1 Data";
	case SCC_ASN1_ERROR_INVALID_LENGTH:		return "Invalid ASN1 Length";
			
	}

	return "Not Defined Error Message";
}

/**
 *
 *
 *
 */

#ifdef	_WIN32
HMODULE	g_crypto_hmodule = NULL;

BOOL APIENTRY DllMain(HANDLE hModule, 
                      DWORD  fdwReason, 
                      LPVOID lpReserved)
{
	//int retCode = 0;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		// get module handle
		g_crypto_hmodule = (HMODULE) hModule;

		// do powerup selftest
		SC_CMVP_Status_init();
	}
	else if ((fdwReason == DLL_PROCESS_DETACH) && (lpReserved != NULL))
	{
		SC_CMVP_RAND_Final();
		SC_CMVP_Status_Final();
	}
	
	return TRUE;
	
}

#endif

