/* 
========================================
  scc_protocol.h 
    : crypto define constant 
----------------------------------------
  softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_PROTOCOL_H__
#define __SCC_PROTOCOL_H__

#define	UBOOL					unsigned char		//  1 bits
#define	U8						unsigned char		//  8 bits
#define	U16						unsigned short		// 16 bits
#define	U32						unsigned int		// 32 bits
	
#if (defined(WIN32) || defined(_WIN32))
#define	U64						unsigned __int64	// 64 bits
#else
#define	U64			p			unsigned long long	// for gcc
#endif

#define MAXINPUTSIZE	1024*1024*1024

/* Status Id */
#define	SCC_STATUS_LOADED					1		// 적재됨 상태
#define	SCC_STATUS_SELFTEST					2		// 동작 전 자가시험
#define	SCC_STATUS_SELFTESTCASE				3		// Á¶°ÇºÎ ÀÚ°¡½ÃÇè »óÅÂ
#define	SCC_STATUS_KCMVP					4		// 검증대상 동작 상태
#define	SCC_STATUS_ERROR					5		// ´Ü¼ø¿À·ù »óÅÂ
#define	SCC_STATUS_CRITICAL_ERROR			6		// ½É°¢ÇÑ ¿À·ù »óÅÂ
#define	SCC_STATUS_FINALIZED				7		// ¸ðµâ Á¾·á »óÅÂ

// key
#define SCC_KEY_ID_ARIA					12

// cipher
#define	SCC_CIPHER_ID_ARIA					12

#define	SCC_CIPHER_MODE_CBC					1
#define	SCC_CIPHER_MODE_CTR					2

#define	SCC_CIPHER_DIR_ENCRYPT				0
#define	SCC_CIPHER_DIR_DECRYPT				1

#define SCC_CIPHER_PADDING_NO				1
#define SCC_CIPHER_PADDING_ZERO				2
#define SCC_CIPHER_PADDING_HASH				3
#define SCC_CIPHER_PADDING_PKCS				4

#define SCC_CIPHER_MAX_KEY_SIZE				256
#define SCC_CIPHER_MAX_IV_SIZE				32

#define	SCC_SEED_KEY_SIZE					16		// BYTE
#define	SCC_SEED_BLOCK_SIZE					16		// BYTE
#define	SCC_SEED_IV_SIZE					16		// BYTE

#define	SCC_HASH_ID_SHA256					3
#define	SCC_HASH_ID_SHA512					4

#define	SCC_MAC_ID_SHA256					3
#define	SCC_MAC_ID_SHA512					4

#define	SCC_MAC_ID_HMAC_SHA256					3
#define	SCC_MAC_ID_HMAC_SHA512					4


#define	SCC_SHA256_DIGEST_SIZE				32		// BYTE
#define	SCC_SHA512_DIGEST_SIZE				64		// BYTE

#define	SCC_SHA256_BLOCK_SIZE				64		// BYTE
#define	SCC_SHA512_BLOCK_SIZE				128		// BYTE

#endif
