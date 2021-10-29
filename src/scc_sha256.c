/* 
========================================
  scc_sha256.c
    : sha256 algorithm
	: FIPS-180-2 compliant SHA-256 implementation
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <string.h>
#include <stdio.h>
#include "scc_sha256.h"
#include "scc_error.h"
#include "scc_util.h"

/* Implementation that should never be optimized out by the compiler */
static void sc_zeroize( void *v, U32 n ) {
    volatile U8 *p = v; while( n-- ) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
do {                                                    \
    (n) = ( (U32) (b)[(i)    ] << 24 )             \
        | ( (U32) (b)[(i) + 1] << 16 )             \
        | ( (U32) (b)[(i) + 2] <<  8 )             \
        | ( (U32) (b)[(i) + 3]       );            \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
do {                                                    \
    (b)[(i)    ] = (U8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (U8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (U8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (U8) ( (n)       );       \
} while( 0 )
#endif

void SC_SHA256_New( SC_SHA256_CONTEXT *ctx )
{
    SC_Memzero( ctx, 0, sizeof( SC_SHA256_CONTEXT ) );
}

void SC_SHA256_Free( SC_SHA256_CONTEXT *ctx )
{
    if( ctx == NULL )
        return;

    sc_zeroize( ctx, sizeof( SC_SHA256_CONTEXT ) );
}

void SC_SHA256_Clone( SC_SHA256_CONTEXT *dst,
                           const SC_SHA256_CONTEXT *src )
{
    *dst = *src;
}

/*
 * SHA-256 context setup
 */
int SC_SHA256_Init( SC_SHA256_CONTEXT *ctx)
{
	int retCode;

	if (ctx == NULL){
		retCode = SCC_SHA256_ERROR_INVALID_INPUT;
		goto end;
	}

	SC_Memzero(ctx, 0, sizeof(SC_SHA256_CONTEXT));

    ctx->total[0] = 0;
    ctx->total[1] = 0;

    /* SHA-256 */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
	
	retCode = 0;
end:
	return retCode;
}

static const U32 K[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

void SC_SHA256_Process( SC_SHA256_CONTEXT *ctx, const U8 data[64] )
{
    U32 temp1, temp2, W[64];
    U32 A[8];
    U32 i;

    for( i = 0; i < 8; i++ )
        A[i] = ctx->state[i];

    for( i = 0; i < 16; i++ )
        GET_UINT32_BE( W[i], data, 4 * i );

    for( i = 0; i < 16; i += 8 )
    {
        P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i+0], K[i+0] );
        P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i+1], K[i+1] );
        P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i+2], K[i+2] );
        P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i+3], K[i+3] );
        P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i+4], K[i+4] );
        P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i+5], K[i+5] );
        P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i+6], K[i+6] );
        P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i+7], K[i+7] );
    }

    for( i = 16; i < 64; i += 8 )
    {
        P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i+0), K[i+0] );
        P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i+1), K[i+1] );
        P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i+2), K[i+2] );
        P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i+3), K[i+3] );
        P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i+4), K[i+4] );
        P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i+5), K[i+5] );
        P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i+6), K[i+6] );
        P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i+7), K[i+7] );
    }

    for( i = 0; i < 8; i++ )
        ctx->state[i] += A[i];
}

/*
 * SHA-256 process buffer
 */
int SC_SHA256_Update( SC_SHA256_CONTEXT *ctx, const U8 *input,
                    U32 inputLength )
{
    U32 fill;
    U32 left;
	int retCode;

	if (ctx == NULL){
		retCode = SCC_SHA256_ERROR_INVALID_INPUT;
		goto end;
	}

	if (inputLength > MAXINPUTSIZE || inputLength < 0)
	{
		retCode = SCC_SHA256_ERROR_INVALID_INPUTLEN;
		goto end;
	}

	if ((input == NULL) || (inputLength == 0)) {
		retCode = 0;
		goto end;
	}

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (U32) inputLength;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (U32) inputLength )
        ctx->total[1]++;

    if( left && inputLength >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        SC_SHA256_Process( ctx, ctx->buffer );
        input += fill;
        inputLength  -= fill;
        left = 0;
    }

    while( inputLength >= 64 )
    {
        SC_SHA256_Process( ctx, input );
        input += 64;
        inputLength  -= 64;
    }

    if( inputLength > 0 )
        memcpy( (void *) (ctx->buffer + left), input, inputLength );

	retCode = 0;
end: 
	if (retCode < 0)
	{
		SC_Memzero(&ctx, 0x00, sizeof(SC_SHA256_CONTEXT));
	}
	return retCode;
}

static const U8 sha256_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-256 final digest
 */
int SC_SHA256_Final( SC_SHA256_CONTEXT *ctx, U8 output[32] )
{
    U32 last, padn;
    U32 high, low;
    U8 msglen[8];
	int retCode;

	if (ctx == NULL || output == NULL){
		retCode = SCC_SHA256_ERROR_INVALID_INPUT;
		goto end;
	}

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( high, msglen, 0 );
    PUT_UINT32_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    SC_SHA256_Update( ctx, sha256_padding, padn );
    SC_SHA256_Update( ctx, msglen, 8 );

    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );
    PUT_UINT32_BE( ctx->state[5], output, 20 );
    PUT_UINT32_BE( ctx->state[6], output, 24 );
    PUT_UINT32_BE( ctx->state[7], output, 28 );

	retCode = 0;
end: 
	return retCode;
}

/*
 * output = SHA-256( input buffer )
 */
int SC_SHA256_Digest(U8 *output, U32 *outputLength,
             const U8 *input, U32 inputLength)
{
    SC_SHA256_CONTEXT ctx;
	int retCode;
		
    retCode = SC_SHA256_Init(&ctx);
	if(retCode != 0) goto end;

    retCode = SC_SHA256_Update(&ctx, input, inputLength);
	if(retCode != 0) goto end;

    retCode = SC_SHA256_Final(&ctx, output);
	if(retCode != 0) goto end;
   
	retCode = 0;
	*outputLength = SCC_SHA256_DIGEST_SIZE;
	
end:
	SC_Memzero(&ctx, 0x00, sizeof(SC_SHA256_CONTEXT));
	return retCode;
}