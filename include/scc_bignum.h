/* 
========================================
  scc_bignum.h 
    : big integer
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_BIGNUM_H__
#define __SCC_BIGNUM_H__

#include <stddef.h>
#include <stdio.h>
#include "scc_protocol.h"

/* constants */
#define SC_BIGINT_CHK(f) do { if( ( retCode = f ) != 0 ) goto end; } while( 0 )

#define SC_BIGINT_MAX_LIMBS                             10000
#define SC_BIGINT_WINDOW_SIZE                           6        /**< Maximum windows size used. */
#define SC_BIGINT_MAX_SIZE                              2048     /**< Maximum number of bytes for usable MPIs. */
#define SCC_BIGINT_MAX_BITS                             ( 8 * SC_BIGINT_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */
#define SC_BIGINT_MAX_BITS_SCALE100						( 100 * SCC_BIGINT_MAX_BITS )
#define SC_LN_2_DIV_LN_10_SCALE100						332
#define SC_BIGINT_RW_BUFFER_SIZE						( ((SC_BIGINT_MAX_BITS_SCALE100 + SC_LN_2_DIV_LN_10_SCALE100 - 1) / SC_LN_2_DIV_LN_10_SCALE100) + 10 + 6 )
#define SC_DIGITSIZE										4
#define SC_BitsInDIGIT										(8*SC_DIGITSIZE)

#define SC_CHECK_BIT_D(A, k)	( 1 & ( (A)[(k)>>5] >> ((k) & (32-1)) ) )
#define SC_SetBitDIGIT(A, k)		(A)[(k)>>5] |= ((U32)1 << ((k) & (32-1)) )
#define SC_BIG_D2B(D, B)		*(U32 *)(B) = SC_ENDIAN_REVERSE_DWORD(D)
#define SC_ENDIAN_REVERSE_DWORD(dwS)	( (SC_ROTL_DWORD((dwS),  8) & 0x00ff00ff)	\
	| (SC_ROTL_DWORD((dwS), 24) & 0xff00ff00) )
#define SC_ROTL_DWORD(x, n) _lrotl((x), (n))

#define BIG_IS_ONE(a) \
	((a)->n == 1 && (a)->p[0] == 1)

#define MULADDC_INIT                    \
{                                       \
	U32 s0, s1, b0, b1;					\
	U32 r0, r1, rx, ry;					\
	b0 = ( b << biH ) >> biH;           \
	b1 = ( b >> biH );

#define MULADDC_CORE                    \
	s0 = ( *s << biH ) >> biH;          \
	s1 = ( *s >> biH ); s++;            \
	rx = s0 * b1; r0 = s0 * b0;         \
	ry = s1 * b0; r1 = s1 * b1;         \
	r1 += ( rx >> biH );                \
	r1 += ( ry >> biH );                \
	rx <<= biH; ry <<= biH;             \
	r0 += rx; r1 += (r0 < rx);          \
	r0 += ry; r1 += (r0 < ry);          \
	r0 +=  c; r1 += (r0 <  c);          \
	r0 += *d; r1 += (r0 < *d);          \
	c = r1; *(d++) = r0;

#define MULADDC_STOP                    \
}

/* structure */
typedef struct
{
	int s;              /*!<  integer sign      */
	U32 n;              /*!<  total # of limbs  */
	U32 *p;             /*!<  pointer to limbs  */
}
SC_BIGINT;

#ifdef __cplusplus
extern "C" {
#endif

void 
SC_Bigint_New( SC_BIGINT *X );

void 
SC_Bigint_Free( SC_BIGINT *X );

int 
SC_Bigint_Grow( SC_BIGINT *X, U32 nblimbs );

int 
SC_Bigint_Shrink( SC_BIGINT *X, U32 nblimbs );

int 
SC_Bigint_Copy( SC_BIGINT *X, const SC_BIGINT *Y );

void 
SC_Bigint_Swap( SC_BIGINT *X, SC_BIGINT *Y );

int 
SC_Bigint_Safe_Cond_Assign( SC_BIGINT *X, const SC_BIGINT *Y, U8 assign );

int 
SC_Bigint_Safe_Cond_Swap( SC_BIGINT *X, SC_BIGINT *Y, U8 assign );

int 
SC_Bigint_Lset( SC_BIGINT *X, int z );

int 
SC_Bigint_Get_Bit( const SC_BIGINT *X, U32 pos );

int 
SC_Bigint_Set_Bit( SC_BIGINT *X, U32 pos, U8 val );

U32 
SC_Bigint_Lsb( const SC_BIGINT *X );

U32 
SC_Bigint_Bitlen( const SC_BIGINT *X );

U32 
SC_Bigint_Size( const SC_BIGINT *X );

int 
SC_Bigint_Read_String( SC_BIGINT *X, int radix, const char *s );

int 
SC_Bigint_Write_String( const SC_BIGINT *X, int radix, char *buf, U32 buflen, U32 *olen );

int 
SC_Bigint_Read_Binary( SC_BIGINT *X, const U8 *buf, U32 buflen );

int 
SC_Bigint_Write_Binary( const SC_BIGINT *X, U8 *buf, U32 buflen );

int 
SC_Bigint_Shift_I( SC_BIGINT *X, U32 count );

int 
SC_Bigint_Shift_R( SC_BIGINT *X, U32 count );

int 
SC_Bigint_Cmp_Abs( const SC_BIGINT *X, const SC_BIGINT *Y );

int 
SC_Bigint_Cmp_Bignum( const SC_BIGINT *X, const SC_BIGINT *Y );

int 
SC_Bigint_Cmp_Int( const SC_BIGINT *X, int z );

int 
SC_Bigint_Add_Abs( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Sub_Abs( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Add_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Sub_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Add_Int( SC_BIGINT *X, const SC_BIGINT *A, int b );

int 
SC_Bigint_Sub_Int( SC_BIGINT *X, const SC_BIGINT *A, int b );

int 
SC_Bigint_Mul_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Mul_Int( SC_BIGINT *X, const SC_BIGINT *A, U32 b );

int 
SC_Bigint_Div_Bignum( SC_BIGINT *Q, SC_BIGINT *R, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Div_Int( SC_BIGINT *Q, SC_BIGINT *R, const SC_BIGINT *A, int b );

int 
SC_Bigint_Mod_Bignum( SC_BIGINT *R, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Mod_Int( U32 *r, const SC_BIGINT *A, int b );

int 
SC_Bigint_Exp_Mod( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *E, const SC_BIGINT *N, SC_BIGINT *_RR );

int 
SC_Bigint_Fill_Random( SC_BIGINT *X, U32 size);

int 
SC_Bigint_Gcd( SC_BIGINT *G, const SC_BIGINT *A, const SC_BIGINT *B );

int 
SC_Bigint_Inv_Mod( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *N );

int 
SC_Bigint_Is_Prime( const SC_BIGINT *X);

int 
SC_Bigint_Gen_Prime( SC_BIGINT *X, U32 nbits);

int 
SC_Big_MulMod(SC_BIGINT *output, SC_BIGINT *inputA, SC_BIGINT *inputB, SC_BIGINT *mod);

int 
SC_Big_SubMod(SC_BIGINT *r, SC_BIGINT *a, SC_BIGINT *b, SC_BIGINT *m);	

int 
SC_Miller_Rabin( const SC_BIGINT *X);

#ifdef __cplusplus
}
#endif

#endif 
