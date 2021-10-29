/* 
========================================
  scc_rsa.c
    : The RSA public-key algorithm - RSA was designed by Ron Rivest, Adi Shamir and Len Adleman
	: FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "scc_rsa.h"
#include "scc_sha256.h"
#include "scc_error.h"
#include "scc_random.h"
#include "scc_malloc.h"
#include "scc_bignum.h"
#include "scc_cmvp.h"
#include "scc_util.h"



static void mgf_mask( U8 *dst, U32 dlen, U8 *src,
                      U32 slen, SC_SHA256_CONTEXT *h_ctx )
{
    U8 mask[SCC_SHA256_DIGEST_SIZE];
    U8 counter[4];
    U8 *p;
    U32 hlen;
    U32 i, use_len;

    SC_Memzero( mask, 0, SCC_SHA256_DIGEST_SIZE );
    SC_Memzero( counter, 0, 4 );

    hlen = SCC_SHA256_DIGEST_SIZE;

    // Generate and apply dbMask
    //
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;
		
		SC_SHA256_Init(h_ctx);
		SC_SHA256_Update(h_ctx, src, slen);
		SC_SHA256_Update(h_ctx, counter, 4);
		SC_SHA256_Final(h_ctx, mask);

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }
}

SC_RSA_PrivateKey * 
SC_RSA_PrivateKey_New(void)
{
	SC_RSA_PrivateKey *key;

	key = (SC_RSA_PrivateKey *)sc_calloc(sizeof(SC_RSA_PrivateKey), 1);
	if(key == NULL) {
		return NULL;
	}

	key->n    = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->n);
	key->e    = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->e);
	key->d    = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->d);
	key->p    = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->p);
	key->q    = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->q);
	key->dP   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->dP);
	key->dQ   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->dQ);
	key->qInv = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->qInv);

	key->rn   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->rn);
	key->rp   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->rp);
	key->rq   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->rq);
	key->vi   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->vi);
	key->vf   = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->vf);

	return key;
}

void 
SC_RSA_PrivateKey_Free(SC_RSA_PrivateKey *key)
{
	if(key != NULL) {

		SC_Bigint_Free(key->n);   sc_free(key->n);
		SC_Bigint_Free(key->e);   sc_free(key->e);
		SC_Bigint_Free(key->d);   sc_free(key->d);
		SC_Bigint_Free(key->p);   sc_free(key->p);
		SC_Bigint_Free(key->q);   sc_free(key->q);
		SC_Bigint_Free(key->dP);  sc_free(key->dP);
		SC_Bigint_Free(key->dQ);  sc_free(key->dQ);
		SC_Bigint_Free(key->qInv);sc_free(key->qInv);
		
		SC_Bigint_Free(key->rn);  sc_free(key->rn);
		SC_Bigint_Free(key->rp);  sc_free(key->rp);
		SC_Bigint_Free(key->rq);  sc_free(key->rq);
		SC_Bigint_Free(key->vi);  sc_free(key->vi);
		SC_Bigint_Free(key->vf);  sc_free(key->vf);

		SC_Memzero(key, 0x00, sizeof(SC_RSA_PrivateKey));
		sc_free(key);

	}

	return;
}

SC_RSA_PublicKey * 
SC_RSA_PublicKey_New(void)
{
	SC_RSA_PublicKey *key;

	key = (SC_RSA_PublicKey *)sc_calloc(sizeof(SC_RSA_PublicKey), 1);
	if(key == NULL) {
		return NULL;
	}

	 key->n = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->n);
	 key->e = sc_malloc(sizeof(SC_BIGINT));SC_Bigint_New(key->e);

	return key;
}

void 
SC_RSA_PublicKey_Free(SC_RSA_PublicKey *key)
{
	if(key != NULL) {

		SC_Bigint_Free(key->n);sc_free(key->n);
		SC_Bigint_Free(key->e);sc_free(key->e);

		SC_Memzero(key, 0x00, sizeof(SC_RSA_PublicKey));
		sc_free(key);

	}

	return;
}

/*
 * Check a public RSA key
 */
int 
SC_RSA_Check_Pubkey(const SC_RSA_PublicKey *key)
{
	if(!key) 
		return( SCC_RSA_ERROR_KEY_CHECK_FAILED );
	
	if(!key->n || !key->e) 
		return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    if( !key->n->p || !key->e->p )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    if( ( key->n->p[0] & 1 ) == 0 ||
        ( key->e->p[0] & 1 ) == 0 )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    if( SC_Bigint_Bitlen( key->n ) < 128 ||
        SC_Bigint_Bitlen( key->n ) > SCC_BIGINT_MAX_BITS )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    if( SC_Bigint_Bitlen( key->e ) < 2 ||
        SC_Bigint_Cmp_Bignum( key->e, key->n ) >= 0 )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int 
SC_RSA_Check_Privkey(const SC_RSA_PrivateKey *key)
{
    int retCode;
    SC_BIGINT PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

	if(!key) 
		return( SCC_RSA_ERROR_KEY_CHECK_FAILED );
	
	if(!key->n || !key->e) 
		return( SCC_RSA_ERROR_KEY_CHECK_FAILED );
    
    if( !key->n->p || !key->e->p || !key->d->p )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );

    SC_Bigint_New( &PQ ); SC_Bigint_New( &DE ); SC_Bigint_New( &P1 ); SC_Bigint_New( &Q1 );
    SC_Bigint_New( &H  ); SC_Bigint_New( &I  ); SC_Bigint_New( &G  ); SC_Bigint_New( &G2 );
    SC_Bigint_New( &L1 ); SC_Bigint_New( &L2 ); SC_Bigint_New( &DP ); SC_Bigint_New( &DQ );
    SC_Bigint_New( &QP );

    SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &PQ, key->p, key->q ) );
    SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &DE, key->d, key->e ) );
    SC_BIGINT_CHK( SC_Bigint_Sub_Int( &P1, key->p, 1 ) );
    SC_BIGINT_CHK( SC_Bigint_Sub_Int( &Q1, key->q, 1 ) );
    SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &H, &P1, &Q1 ) );
    SC_BIGINT_CHK( SC_Bigint_Gcd( &G, key->e, &H  ) );

    SC_BIGINT_CHK( SC_Bigint_Gcd( &G2, &P1, &Q1 ) );
    SC_BIGINT_CHK( SC_Bigint_Div_Bignum( &L1, &L2, &H, &G2 ) );
    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &I, &DE, &L1  ) );

    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &DP, key->d, &P1 ) );
    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &DQ, key->d, &Q1 ) );
    SC_BIGINT_CHK( SC_Bigint_Inv_Mod( &QP, key->q, key->p ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
	if(!key->dP->p || !key->dQ->p || !key->qInv->p) {

		if( SC_Bigint_Cmp_Bignum( &PQ, key->n    ) != 0 ||
			SC_Bigint_Cmp_Int( &L2, 0 ) != 0 ||
			SC_Bigint_Cmp_Int( &I, 1 ) != 0 ||
			SC_Bigint_Cmp_Int( &G, 1 ) != 0 )
		{
			retCode = SCC_RSA_ERROR_KEY_CHECK_FAILED;
		}
	}else {
		if( SC_Bigint_Cmp_Bignum( &PQ, key->n    ) != 0 ||
			SC_Bigint_Cmp_Bignum( &DP, key->dP   ) != 0 ||
			SC_Bigint_Cmp_Bignum( &DQ, key->dQ   ) != 0 ||
			SC_Bigint_Cmp_Bignum( &QP, key->qInv ) != 0 ||
			SC_Bigint_Cmp_Int( &L2, 0 ) != 0 ||
			SC_Bigint_Cmp_Int( &I, 1 ) != 0 ||
			SC_Bigint_Cmp_Int( &G, 1 ) != 0 )
		{
			retCode = SCC_RSA_ERROR_KEY_CHECK_FAILED;
		}
	}

end:
    SC_Bigint_Free( &PQ ); SC_Bigint_Free( &DE ); SC_Bigint_Free( &P1 ); SC_Bigint_Free( &Q1 );
    SC_Bigint_Free( &H  ); SC_Bigint_Free( &I  ); SC_Bigint_Free( &G  ); SC_Bigint_Free( &G2 );
    SC_Bigint_Free( &L1 ); SC_Bigint_Free( &L2 ); SC_Bigint_Free( &DP ); SC_Bigint_Free( &DQ );
    SC_Bigint_Free( &QP );

    if( retCode == SCC_RSA_ERROR_KEY_CHECK_FAILED )
        return( retCode );

    if( retCode != 0 )
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED + retCode );

    return( 0 );
}

/*
 * Check if contexts holding a public and private key match
 */
int 
SC_RSA_Check_Pub_Priv(const SC_RSA_PublicKey *pub, const SC_RSA_PrivateKey *prv)
{
    if( SC_RSA_Check_Pubkey( pub ) != 0 ||
        SC_RSA_Check_Privkey( prv ) != 0 )
    {
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );
    }

    if( SC_Bigint_Cmp_Bignum( pub->n, prv->n ) != 0 ||
        SC_Bigint_Cmp_Bignum( pub->e, prv->e ) != 0 )
    {
        return( SCC_RSA_ERROR_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int SC_RSA_Rsaes_Oaep_Encrypt(SC_RSA_PublicKey *key, int mode, const U8 *label, U32 label_len, U32 ilen, const U8 *input, U8 *output)
{
    U32 olen;
    U8 *p = output;
    U32 hlen, p_len;
	SC_SHA256_CONTEXT h_ctx;
	int retCode = 0;

	if(key == NULL || input == NULL) {
		return SCC_RSA_ERROR_BAD_INPUT_DATA;
	}

	if(SC_Bigint_Bitlen(key->n) != 2048) {
		return SCC_RSA_ERROR_INVALID_KEYLEN;
	}

	if (label_len > MAXINPUTSIZE)
	{
		return (SCC_RSA_ERROR_BAD_INPUT_DATA);
	}

    if( mode != SC_RSA_PKCS_V21 )
        return( SCC_RSA_ERROR_INVALID_PADDING );

    olen = (key->n->n) * 4;
    hlen = SCC_SHA256_DIGEST_SIZE;

	if (ilen > olen - (2 * hlen) - 2) // 190byte
		return SCC_RSA_ERROR_BAD_INPUT_DATA;

	if( olen < ilen + 2 * hlen + 2 )
        return( SCC_RSA_ERROR_BAD_INPUT_DATA );

    SC_Memzero( output, 0, olen );

    *p++ = 0;

    // Generate a random octet string seed
	if(g_cmvp_status_id == SCC_STATUS_SELFTEST) {
		SC_Memzero(p, 0, hlen);
	}
	else {
		SC_GetRandom(p, hlen);	
	}

    p += hlen;

    // Construct DB
    //
	//label == NULL -> error
	retCode = SC_SHA256_Digest(p, &p_len, label, label_len);
	if (retCode != 0)
		return retCode;
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen; // padding length
    *p++ = 1;
    memcpy( p, input, ilen );

    SC_SHA256_New( &h_ctx );

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen, &h_ctx );

    // maskedSeed: Apply seedMask to seed
    //
    mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1, &h_ctx );

    SC_SHA256_Free( &h_ctx );

	return SC_RSA_Public(key, output, output);

}



/*
 * Add the message padding, then do an RSA operation
 */
int SC_RSA_Pkcs1_Encrypt(SC_RSA_PublicKey *key, int mode, U32 ilen, const U8 *input, U8 *output)
{
    return SC_RSA_Rsaes_Oaep_Encrypt(key, mode, NULL, 0, ilen, input, output);
}

/*
 * Do an RSA public key operation
 */
int 
SC_RSA_Public(SC_RSA_PublicKey *key, const U8 *input, U8 *output)
{
    int retCode;
    U32 olen;
    SC_BIGINT T;

    SC_Bigint_New( &T );

    SC_BIGINT_CHK( SC_Bigint_Read_Binary( &T, input, (key->n->n) * 4 ) );

    if( SC_Bigint_Cmp_Bignum( &T, key->n ) >= 0 )
    {
        retCode = SCC_BIGNUM_ERROR_BAD_INPUT_DATA;
        goto end;
    }

    olen = (key->n->n) * 4;
    SC_BIGINT_CHK( SC_Bigint_Exp_Mod( &T, &T, key->e, key->n, NULL ) );
    SC_BIGINT_CHK( SC_Bigint_Write_Binary( &T, output, olen ) );

end:

    SC_Bigint_Free( &T );

    if( retCode != 0 )
        return( SCC_RSA_ERROR_PUBLIC_FAILED );

    return (key->n->n) * 4;
}

/*
 * Do an RSA private key operation
 */
int 
SC_RSA_Private(SC_RSA_PrivateKey *key, const U8 *input, U8 *output)
{
    int retCode;
    U32 olen;
    SC_BIGINT T, T1, T2, T3;

    SC_Bigint_New( &T ); SC_Bigint_New( &T1 ); SC_Bigint_New( &T2 ); SC_Bigint_New( &T3 );

    SC_BIGINT_CHK( SC_Bigint_Read_Binary( &T, input, (key->n->n) * 4 ) );
    if( SC_Bigint_Cmp_Bignum( &T, key->n ) >= 0 )
    {
        retCode = SCC_BIGNUM_ERROR_BAD_INPUT_DATA;
        goto end;
    }

    /*
     * Blinding
     * T = T * Vi mod N
     */
    SC_BIGINT_CHK( rsa_prepare_blinding( key ) );
    SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T, &T, key->vi ) );
    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &T, &T, key->n ) );

	if(!key->dP->p || !key->dQ->p || !key->qInv->p) {
        직/*
         *  Exponent Blinding
         *
         *  T1 = p - 1
         *  T2 = q - 1
         *  T3 = d + r * T1 * T2
         */
        
        SC_BIGINT_CHK( SC_Bigint_Sub_Int( &T1, key->p, 1 ) );
        SC_BIGINT_CHK( SC_Bigint_Sub_Int( &T2, key->q, 1 ) );
        
        SC_BIGINT_CHK( SC_Bigint_Fill_Random(&T3, key->d->n * 4 + 1 ) );
        SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T3, &T3, &T1 ) );
        SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T3, &T3, &T2 ) );
        SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &T3, key->d, &T3 ) );

        SC_BIGINT_CHK( SC_Bigint_Exp_Mod( &T, &T, &T3, key->n, key->rn ) );
	}else {

		/*
		 * faster decryption using the CRT
		 *
		 * T1 = input ^ dP mod P
		 * T2 = input ^ dQ mod Q
		 */
		SC_BIGINT_CHK( SC_Bigint_Exp_Mod( &T1, &T, key->dP, key->p, key->rp ) );
		SC_BIGINT_CHK( SC_Bigint_Exp_Mod( &T2, &T, key->dQ, key->q, key->rq ) );

		/*
		 * T = (T1 - T2) * (Q^-1 mod P) mod P
		 */
		SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &T, &T1, &T2 ) );
		SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T1, &T, key->qInv ) );
		SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &T, &T1, key->p ) );

		/*
		 * T = T2 + T * Q
		 */
		SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T1, &T, key->q ) );
		SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &T, &T2, &T1 ) );
	}

    /*
     * Unblind
     * T = T * Vf mod N
     */
    SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T, &T, key->vf ) );
    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &T, &T, key->n ) );

    olen = (key->n->n) * 4;
    SC_BIGINT_CHK( SC_Bigint_Write_Binary( &T, output, olen ) );

end:

    SC_Bigint_Free( &T ); SC_Bigint_Free( &T1 ); SC_Bigint_Free( &T2 ); SC_Bigint_Free( &T3 );

    // Å° Á¦·ÎÈ­
    SC_Bigint_Free(key->vf);
    SC_Bigint_Free(key->vi);

    if( retCode != 0 )
        return( SCC_RSA_ERROR_PRIVATE_FAILED );

    return( 0 );
}

static int rsa_prepare_blinding(SC_RSA_PrivateKey *key)
{
	int retCode, count = 0;

	if( key->vf->p != NULL )
	{
		/* We already have blinding values, just update them by squaring */
		SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( key->vi, key->vi, key->vi ) );
		SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( key->vi, key->vi, key->n ) );
		SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( key->vf, key->vf, key->vf ) );
		SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( key->vf, key->vf, key->n ) );

		goto end;
	}

	/* Unblinding value: Vf = random number, invertible mod N */
	do {
		if( count++ > 10 )
			return( SCC_RSA_ERROR_RNG_FAILED );

		SC_BIGINT_CHK( SC_Bigint_Fill_Random( key->vf, (key->n->n) * 4 - 1 ));
		SC_BIGINT_CHK( SC_Bigint_Gcd( key->vi, key->vf, key->n ) );
	} while( SC_Bigint_Cmp_Int( key->vi, 1 ) != 0 );

	/* Blinding value: Vi =  Vf^(-e) mod N */
	SC_BIGINT_CHK( SC_Bigint_Inv_Mod( key->vi, key->vf, key->n ) );
	//SC_BIGINT_CHK( SC_Bigint_Exp_Mod( key->vi, key->vi, key->e, key->n, key->rn ) );
	SC_BIGINT_CHK( SC_Bigint_Exp_Mod( key->vi, key->vi, key->e, key->n, NULL ) );


end:
	return( retCode );
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int 
SC_RSA_Rsaes_Oaep_Decrypt(SC_RSA_PrivateKey *key, int mode, const U8 *label, U32 label_len, U32 *olen, const U8 *input, U8 *output, U32 output_max_len)
{
    int retCode;
    U32 ilen, i, pad_len;
    U8 *p, bad, pad_done;
    U8 buf[SC_BIGINT_MAX_SIZE];
	U8 lhash[SCC_SHA256_DIGEST_SIZE] ={0x00,};
    U32 hlen, lhash_len;
	SC_SHA256_CONTEXT h_ctx;

	if(key == NULL || input == NULL || output == NULL) {
		return SCC_RSA_ERROR_BAD_INPUT_DATA;
	}

	if(SC_Bigint_Bitlen(key->n) != 2048 ) {
		return SCC_RSA_ERROR_INVALID_KEYLEN;
	}

    /*
     * Parameters sanity checks
     */
    if( mode != SC_RSA_PKCS_V21 )
        return( SCC_RSA_ERROR_INVALID_PADDING );

    ilen = (key->n->n) * 4;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( SCC_RSA_ERROR_BAD_INPUT_DATA );

    /*
     * RSA operation
     */
    retCode = SC_RSA_Private(key, input, buf);

    if( retCode != 0 )
        return( retCode );

    /*
     * Unmask data and generate lHash
     */
    hlen = SCC_SHA256_DIGEST_SIZE;

    SC_SHA256_New( &h_ctx );

    /* Generate lHash */
	SC_SHA256_Digest(lhash, &lhash_len, label, label_len);

    /* seed: Apply seedMask to maskedSeed */
    mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
               &h_ctx );

    /* DB: Apply dbMask to maskedDB */
    mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
               &h_ctx );

    SC_SHA256_Free( &h_ctx );

    /*
     * Check contents, in "constant-time"
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += hlen; /* Skip seed */

    /* Check lHash */
    for( i = 0; i < hlen; i++ )
        bad |= lhash[i] ^ *p++;

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 01 byte) */
    pad_len = 0;
    pad_done = 0;
    for( i = 0; i < ilen - 2 * hlen - 2; i++ )
    {
        pad_done |= p[i];
        pad_len += ((pad_done | (U8)-pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if( bad != 0 )
        return( SCC_RSA_ERROR_INVALID_PADDING );

    if( ilen - ( p - buf ) > output_max_len )
        return( SCC_RSA_ERROR_OUTPUT_TOO_LARGE );

    *olen = (unsigned int)(ilen - (p - buf));
    memcpy( output, p, *olen );

    return 0;
}

/*
 * Do an RSA operation, then remove the message padding
 */
int 
SC_RSA_Pkcs1_Decrypt(SC_RSA_PrivateKey *key, int mode, U32 *olen, const U8 *input, U8 *output, U32 output_max_len)
{
	return SC_RSA_Rsaes_Oaep_Decrypt(key, mode, NULL, 0, olen, input, output, output_max_len);
}

int
SC_RSA_Pkcs1_EMSA_V15_Encode(U8 *output,
							 const U32 outputLength,
							 const U8 *hash,
							 const U32 hashLength)
{
	U8	sha256DER[19] = {
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
			0x00, 0x04, 0x20 };

	U8 *hashDER = NULL;
	U32	i, hashDERLength;
	int retCode;

	if ((output == NULL) || (hash == NULL))
		return SCC_RSA_ERROR_BAD_INPUT_DATA;

	//only sha256 hash algorithm 
	hashDER = sha256DER;
	hashDERLength = 19;

	if (outputLength < (hashLength + hashDERLength + 11)) {
		retCode = SCC_RSA_ERROR_INTENDED_MSG_LENGTH_TOO_SHORT;
		goto end;
	}
	
	*(output++) = 0x00;
	*(output++) = 0x01;
	for (i = 0; i <(outputLength - (hashLength + hashDERLength + 3)); i++)
			*(output++) = 0xff;
	*(output++) = 0x00;

	memcpy(output, hashDER, hashDERLength);
	memcpy(output + hashDERLength, hash, hashLength);
	
	retCode = 0;

end:

	return retCode;
}

int
SC_RSA_Pkcs1_V15_Sign(U8 *sign, U32 *signLen, U8 *hash, int hashLen, SC_RSA_PrivateKey *pKey)
{
/*
	1. EM = EMSA-PKCS1-V1_5-ENCODE (M, k)
	2. m = IS2IP (EM)
	3. s = RSASP1 (K, m)
	4. S = I2OSP(s, k)

	skip 2,4
*/

	U8	*buffer = NULL;
	U32	keyByteLength = 0;
	int retCode;

	if ((sign == NULL) || (hash == NULL) || (pKey == NULL))
		return SCC_RSA_ERROR_BAD_INPUT_DATA;

	keyByteLength = (pKey->n->n) * 4;

	if (hashLen != 32) {
		//only sha256
		return SCC_RSA_ERROR_BAD_INPUT_DATA;
	}

	buffer = (U8 *) sc_malloc(keyByteLength);
	if (buffer == NULL) {
		retCode = SCC_RSA_ERROR_MEMORY_ALLOC_FAILED;
		goto end;
	}
	SC_Memzero(buffer, 0x00, keyByteLength);

	retCode = SC_RSA_Pkcs1_EMSA_V15_Encode(buffer, keyByteLength, hash, hashLen);
	if (retCode) {
		if (retCode == SCC_RSA_ERROR_INTENDED_MSG_LENGTH_TOO_SHORT)
			retCode = SCC_RSA_ERROR_MODULUS_TOO_SHORT;
		goto end;
	}

	retCode = SC_RSA_Private(pKey, buffer, sign);
	if (retCode) {
		goto end;
	}
	*signLen = keyByteLength;

	retCode = 0;

end:
	if (buffer != NULL)
		sc_free(buffer);

	return retCode;
}

int 
SC_RSA_Pkcs1_V15_Verify(U8 *sign, U32 signLen, U8 *hash, int hashLen, SC_RSA_PublicKey *pKey)
{
/*
	1. Check Signature S Length [S == k octets]
	2. s = IS2IP(S)
	3. m = RSAVP1 ((n, e), s)
	4. EM = I2OSP (m, k)
	5. EM' = EMSA-PKCS1-V1_5-ENCODE (M, k)
	6. compare EM == EM'

	skip 2,4
*/
	U8	*buffer = NULL;
	U8	*encodeValue = NULL;
	U32	keyByteLength;
	int retCode;

	if ((sign == NULL) || (hash == NULL) || (pKey == NULL))
		return SCC_RSA_ERROR_BAD_INPUT_DATA;
	
	keyByteLength = pKey->n->n * 4;

	buffer = (U8 *) sc_malloc(keyByteLength);
	if (buffer == NULL) {
		retCode = SCC_RSA_ERROR_MEMORY_ALLOC_FAILED;
		goto end;
	}
	encodeValue = (U8 *)sc_malloc(keyByteLength);
	if (encodeValue == NULL) {
		retCode = SCC_RSA_ERROR_MEMORY_ALLOC_FAILED;
		goto end;
	}

	SC_Memzero (buffer, 0x00, keyByteLength);
	SC_Memzero (encodeValue, 0x00, keyByteLength);

	if (signLen != keyByteLength) {
		retCode = SCC_RSA_ERROR_INVALID_SIGNATURE;
		goto end;
	}

	retCode = SC_RSA_Public(pKey, sign, buffer);
	if (retCode != signLen) {
		goto end;
	}

	retCode = SC_RSA_Pkcs1_EMSA_V15_Encode(encodeValue, keyByteLength, hash, hashLen);
	if (retCode) {
		if (retCode == SCC_RSA_ERROR_INTENDED_MSG_LENGTH_TOO_SHORT)
			retCode = SCC_RSA_ERROR_MODULUS_TOO_SHORT;
		goto end;
	}

	if (memcmp(encodeValue, buffer, keyByteLength)) {
		retCode = SCC_RSA_ERROR_VERIFY_FAILED;
		goto end;
	}


	retCode = 0;
end:
	if (buffer != NULL) 
		sc_free(buffer);
	if (encodeValue != NULL) 
		sc_free(encodeValue);

	return retCode;

}

void getPublicKey1(unsigned char *output, int *outputLength)
{
	U8 p[] = {0x63,0x5A,0x99,0xE2,0x0D,0x99,0x32,0x68, 0x9C,0xB5,0x15,0x15,0x8F,0x12,0x31,0x96,
			  0xC7,0xB0,0xD8,0xCD,0x8A,0xE1,0xB9,0xFC, 0x7C,0xA6,0x1C,0xC9,0x43,0xE4,0x19,0xE7, 
			  0xD0,0xC9,0x99,0xCF,0x55,0x7F,0xDE,0x7A, 0x82,0xFD,0x3E,0x60,0xA0,0xD9,0x92,0xE5,
			  0x5F,0x5D,0x7E,0x6B,0xE8,0x1D,0x8B,0xB3, 0x68,0x01,0xC4,0xBD,0x9D,0xFC,0x07,0x97,
			  0xE2,0x9C,0xBB,0xBA,0xB6,0x11,0x16,0xED, 0x14,0x44,0xCC,0x87,0x7E,0xD2,0x8D,0xBF,
			  0x23,0x7A,0x6C,0x3E,0x02,0x22,0xC3,0x4B, 0x1B,0xA7,0x76,0xCA,0x7C,0xD6,0x95,0xFF,
			  0x56,0xF8,0xF0,0xB5,0x03,0xE3,0x8D,0x85, 0x7A,0xFB,0xFB,0x8E,0x79,0x41,0x16,0xAA,
			  0x88,0xE8,0x6C,0x0A,0x4F,0xEE,0x39,0xEA, 0xFF,0x33,0x23,0x90,0x05,0x82,0x9F,0xDA,
			  0xD5,0x7A,0xBB,0x96,0xDD,0x4A,0x9A,0x37, 0x44,0x93,0xF4,0x66,0x21,0x9D,0x0C,0xD5,
			  0x10,0xF0,0xFD,0x0A,0x24,0x2B,0x37,0xF4, 0x70,0xFF,0x39,0x89,0xCF,0xE4,0xED,0x7F,
			  0xC2,0x03,0x6F,0xD0,0x21,0x1F,0xE2,0x44, 0xC3,0x05,0x42,0x78,0x69,0x9C,0x09,0xBE,
			  0xAB,0x6C,0xF9,0x6D,0x46,0xC1,0x7E,0xF8, 0xAF,0xA8,0x34,0x23,0x36,0xD8,0x84,0x30,
			  0x32,0xA2,0x13,0x00,0xA2,0x10,0xFF,0x98, 0x09,0x37,0x93,0x1F,0x42,0x98,0x8E,0xEC,
			  0x5A,0xFF,0x15,0xF8,0xC1,0xE7,0x35,0xDB, 0x21,0xD3,0xBB,0x10,0x00,0x89,0x1C,0x59,
			  0x3B,0xF0,0xC8,0xFE,0x17,0x9F,0x7A,0xFC, 0x44,0x87,0x64,0x51,0x28,0x9A,0xDA,0xF8,
			  0x15,0x25,0xB8,0x7A,0xF7,0xBA,0xAA,0xAC, 0x8C,0xF1,0xDF,0x87,0x6B,0x39,0x0B,0xAD };

	memcpy(output, p, sizeof(p));
	*outputLength = sizeof(p);

	return;
}

void getPublicKey2(unsigned char *output, int *outputLength)
{
	U8 q[] = {0xA6,0x42,0xBB,0x70,0xA8,0xF4,0xE4,0x51, 0x16,0x3B,0xDF,0x5E,0xB7,0xA8,0xDC,0x8C,
	          0x20,0x39,0x4B,0x1D,0xAF,0x03,0x48,0xFE, 0x33,0x52,0x78,0x45,0x80,0xE4,0xF1,0x7D };

	memcpy(output, q, sizeof(q));
	*outputLength = sizeof(q);

	return;
}

void getPublicKey3(unsigned char *output, int *outputLength)
{
	U8 g[] = {0x51,0xEC,0x21,0x82,0x2F,0x19,0x9F,0x31, 0x5D,0xED,0xFE,0xCA,0x02,0x4F,0x95,0x20,
			  0xE6,0x9D,0xA6,0x8C,0xF9,0x5F,0x95,0x6B, 0xFC,0x90,0xDF,0x50,0x50,0x8A,0x5A,0x3F,
			  0xB7,0x3A,0x8C,0xB0,0x4B,0xB7,0x90,0xCA, 0x62,0xF7,0xF0,0xD7,0xDD,0xC7,0x09,0x53,
			  0x12,0x78,0x2D,0x3F,0xAE,0xB8,0x19,0xA5, 0xC7,0x2D,0xA5,0xF7,0xA6,0xF4,0x07,0xD7,
			  0x4F,0x0A,0xEA,0x60,0x04,0x16,0xC9,0xDA, 0xE8,0x8F,0x70,0x94,0x13,0xC4,0xED,0xF0,
			  0x58,0xFD,0x07,0x20,0x65,0x98,0xA2,0x8F, 0x12,0x04,0x84,0xAE,0xDF,0xC5,0x99,0x85,
			  0xCD,0x89,0x02,0x1C,0x61,0x08,0x58,0x0B, 0x0B,0x40,0xCF,0x9A,0xE2,0xEB,0xD3,0xF9,
			  0x41,0xD5,0x7E,0x14,0xA4,0x3F,0x29,0x60, 0x35,0xA1,0xD6,0x59,0x97,0xF5,0x7B,0x5B,
			  0x63,0x43,0x5D,0xF1,0x15,0xAA,0x37,0x2A, 0x87,0x6E,0xC3,0x9C,0x8F,0x19,0x0C,0xB0,
			  0x07,0x27,0x0B,0x93,0xE5,0x8C,0xED,0x5C, 0x4B,0x2D,0x9B,0xD4,0xEF,0xAD,0xDF,0xFD,
			  0x76,0x0D,0xDB,0xE5,0x25,0x94,0x9C,0xA7, 0x63,0xFF,0xD2,0x3E,0x73,0x25,0xA8,0xE9,
			  0x68,0x5B,0xF8,0xCC,0xE0,0xFB,0xE9,0x72, 0xA0,0xE9,0x4B,0x00,0x00,0xE4,0x21,0x63,
			  0x93,0xD2,0x20,0x18,0xCE,0x37,0x02,0xF4, 0x1B,0xF3,0x8C,0x7F,0xCD,0x7D,0xE6,0x2C,
			  0xBD,0xA7,0x7F,0x55,0x0F,0xD5,0xF1,0xA9, 0x87,0x5C,0xB1,0xD0,0x52,0x02,0x80,0x2D,
			  0xA4,0x64,0xD2,0x95,0xA4,0x83,0xE7,0xEF, 0xC2,0x2E,0x2D,0x74,0xD3,0x9A,0x64,0x73,
			  0x4A,0xB6,0xA8,0xA6,0x6F,0x51,0x04,0x95, 0x9C,0xC6,0x1A,0x2E,0xD2,0x37,0xCA,0xE6};

	memcpy(output, g, sizeof(g));
	*outputLength = sizeof(g);

	return;
}

void getPublicKey4(unsigned char *output, int *outputLength)
{
	U8 y[] = {0x6D,0x57,0xAB,0x86,0x26,0xB5,0xAA,0x72, 0x49,0x36,0x8C,0xD5,0xB1,0x82,0x57,0x1E,
			  0x59,0x55,0x77,0x94,0xA2,0xF4,0xEE,0x91, 0xEF,0x83,0x9C,0x23,0x3F,0xDF,0x30,0xC4,
			  0xDB,0x23,0x6B,0x64,0x26,0x9F,0xE3,0xEA, 0x35,0x92,0xEB,0x11,0x04,0xF9,0x9C,0x12,
			  0x88,0x03,0x0D,0x11,0xD4,0x99,0xB7,0xF9, 0xB8,0x1F,0xA6,0xBC,0x7B,0x6C,0x53,0x7E,
			  0xEC,0x04,0xBE,0xF3,0x48,0x28,0x07,0x78, 0x54,0x35,0x86,0xFB,0xD3,0x0C,0xC9,0x2B,
			  0x0B,0x82,0xF5,0x1E,0x47,0x78,0x9C,0x8C, 0x77,0x8F,0x43,0xD0,0x13,0x8C,0x96,0x59,
			  0x79,0x48,0xF1,0x1C,0x85,0x07,0x7A,0xFF, 0x31,0x85,0x29,0x83,0xE9,0xF9,0xF2,0x35,
			  0x47,0xAF,0x07,0xAA,0x10,0xD1,0x13,0x2A, 0xA0,0x04,0x52,0x4A,0xC9,0x2E,0xD0,0xB9,
			  0x47,0xB9,0x79,0x2B,0x5B,0x4C,0xE5,0x40, 0xEB,0x38,0xA8,0x32,0x02,0xC3,0x09,0x7C,
			  0x76,0xEB,0x25,0x7E,0x05,0x5E,0xA9,0x11, 0xAC,0x4B,0x49,0xA6,0xB1,0xB6,0x42,0x79,
			  0x9C,0x78,0x4E,0x29,0xCE,0xFA,0xCF,0x47, 0xC1,0x7C,0x06,0x61,0xC6,0xB3,0xD0,0x8C,
			  0x52,0x1E,0x81,0xF3,0x5A,0x77,0x97,0xCC, 0x80,0xB0,0x9E,0xF2,0x5D,0xC2,0x88,0x24,
			  0x14,0x5D,0x1F,0xD8,0xAF,0xE3,0x67,0xA4, 0xDD,0x6C,0xC6,0x3E,0x0C,0x57,0xFA,0x8F,
			  0x0C,0xE4,0x19,0xE5,0x8E,0x6F,0x1A,0x3A, 0x2A,0x6F,0xBB,0x23,0xAF,0x33,0x0D,0x29,
			  0xB4,0xEA,0x91,0x43,0x20,0x3D,0xC9,0x80, 0x00,0x46,0xE0,0xCF,0xA8,0xA7,0x7C,0x39,
			  0x83,0x15,0xF3,0x24,0x87,0x49,0x43,0x17, 0x8E,0x3E,0x17,0x47,0x7B,0xBC,0xCD,0x4B };

	memcpy(output, y, sizeof(y));
	*outputLength = sizeof(y);

	return;
}
