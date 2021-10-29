/* 
========================================
  scc_bignum.c
    : big integer
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/ 

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "scc_bignum.h"
#include "scc_error.h"
#include "scc_random.h"
#include "scc_malloc.h"
#include "scc_cmvp.h"
#include "scc_util.h"


/* Implementation that should never be optimized out by the compiler */
static void scc_bigint_zeroize( void *v, U32 n ) {
    volatile U8 *p = v; while( n-- ) *p++ = 0;
}

#define ciL    (sizeof(U32))			/* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1) / biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)

/*
 * Initialize one MPI
 */
void SC_Bigint_New( SC_BIGINT *X )
{
    if( X == NULL )
        return;

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void SC_Bigint_Free( SC_BIGINT *X )
{
    if( X == NULL )
        return;

    if( X->p != NULL )
    {
        scc_bigint_zeroize( X->p, X->n * ciL );
        sc_free( X->p );
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
int SC_Bigint_Grow( SC_BIGINT *X, U32 nblimbs )
{
    U32 *p;
	int retCode;

	if( nblimbs > SC_BIGINT_MAX_LIMBS ){
		retCode = SCC_BIGNUM_ERROR_ALLOC_FAILED;
		goto end;
	}

    if( X->n < nblimbs )
    {
		if( ( p = sc_calloc( nblimbs, ciL ) ) == NULL ){
			retCode = SCC_BIGNUM_ERROR_ALLOC_FAILED;
			goto end;
		}

        if( X->p != NULL )
        {
            memcpy( p, X->p, X->n * ciL );
            scc_bigint_zeroize( X->p, X->n * ciL );
            sc_free( X->p );
        }

        X->n = nblimbs;
        X->p = p;
    }

	retCode = 0;
end:
    return retCode;
}

/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
int SC_Bigint_Shrink( SC_BIGINT *X, U32 nblimbs )
{
    U32 *p;
    U32 i;
	int retCode;

    /* Actually resize up in this case */
	if( X->n <= nblimbs ){
		retCode = SC_Bigint_Grow( X, nblimbs );
		goto end;
	}

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;
    i++;

    if( i < nblimbs )
        i = nblimbs;

	if( ( p = sc_calloc( i, ciL ) ) == NULL ){
		retCode = SCC_BIGNUM_ERROR_ALLOC_FAILED;
		goto end;
	}

    if( X->p != NULL )
    {
        memcpy( p, X->p, i * ciL );
        scc_bigint_zeroize( X->p, X->n * ciL );
        sc_free( X->p );
    }

    X->n = i;
    X->p = p;

	retCode = 0;
end:
    return retCode;
}

/*
 * Copy the contents of Y into X
 */
int SC_Bigint_Copy( SC_BIGINT *X, const SC_BIGINT *Y )
{
    int retCode = 0;
    U32 i;

    if( X == Y )
        return( 0 );

    if( Y->p == NULL )
    {
        SC_Bigint_Free( X );
        return( 0 );
    }

    for( i = Y->n - 1; i > 0; i-- )
        if( Y->p[i] != 0 )
            break;
    i++;

    X->s = Y->s;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, i ) );

    SC_Memzero( X->p, 0, X->n * ciL );
    memcpy( X->p, Y->p, i * ciL );

end:

    return( retCode );
}

/*
 * Swap the contents of X and Y
 */
void SC_Bigint_Swap( SC_BIGINT *X, SC_BIGINT *Y )
{
    SC_BIGINT T;

    memcpy( &T,  X, sizeof( SC_BIGINT ) );
    memcpy(  X,  Y, sizeof( SC_BIGINT ) );
    memcpy(  Y, &T, sizeof( SC_BIGINT ) );
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
int SC_Bigint_Safe_Cond_Assign( SC_BIGINT *X, const SC_BIGINT *Y, U8 assign )
{
    int retCode = 0;
    U32 i;

    /* make sure assign is 0 or 1 in a time-constant manner */
    assign = (assign | (U8)-assign) >> 7;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, Y->n ) );

    X->s = X->s * ( 1 - assign ) + Y->s * assign;

    for( i = 0; i < Y->n; i++ )
        X->p[i] = X->p[i] * ( 1 - assign ) + Y->p[i] * assign;

    for( ; i < X->n; i++ )
        X->p[i] *= ( 1 - assign );

end:
    return( retCode );
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which whould lead to
 * different memory access patterns when X and Y are used afterwards.
 */
int SC_Bigint_Safe_Cond_Swap( SC_BIGINT *X, SC_BIGINT *Y, U8 swap )
{
    int retCode, s;
    U32 i;
    U32 tmp;

    if( X == Y )
        return( 0 );

    /* make sure swap is 0 or 1 in a time-constant manner */
    swap = (swap | (U8)-swap) >> 7;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, Y->n ) );
    SC_BIGINT_CHK( SC_Bigint_Grow( Y, X->n ) );

    s = X->s;
    X->s = X->s * ( 1 - swap ) + Y->s * swap;
    Y->s = Y->s * ( 1 - swap ) +    s * swap;


    for( i = 0; i < X->n; i++ )
    {
        tmp = X->p[i];
        X->p[i] = X->p[i] * ( 1 - swap ) + Y->p[i] * swap;
        Y->p[i] = Y->p[i] * ( 1 - swap ) +     tmp * swap;
    }

end:
    return( retCode );
}

/*
 * Set value from integer
 */
int SC_Bigint_Lset( SC_BIGINT *X, int z )
{
    int retCode;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, 1 ) );
    SC_Memzero( X->p, 0, X->n * ciL );

    X->p[0] = ( z < 0 ) ? -z : z;
    X->s    = ( z < 0 ) ? -1 : 1;

end:
    return( retCode );
}

/*
 * Get a specific bit
 */
int SC_Bigint_Get_Bit( const SC_BIGINT *X, U32 pos )
{
    if( X->n * biL <= pos )
        return( 0 );

    return( ( X->p[pos / biL] >> ( pos % biL ) ) & 0x01 );
}

/*
 * Set a bit to a specific value of 0 or 1
 */
int SC_Bigint_Set_Bit( SC_BIGINT *X, U32 pos, U8 val )
{
    int retCode = 0;
    U32 off = pos / biL;
    U32 idx = pos % biL;

    if( val != 0 && val != 1 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    if( X->n * biL <= pos )
    {
        if( val == 0 )
            return( 0 );

        SC_BIGINT_CHK( SC_Bigint_Grow( X, off + 1 ) );
    }

    X->p[off] &= ~( (U32) 0x01 << idx );
    X->p[off] |= (U32) val << idx;

end:

    return( retCode );
}

/*
 * Return the number of less significant zero-bits
 */
U32 SC_Bigint_Lsb( const SC_BIGINT *X )
{
    U32 i, j, count = 0;

    for( i = 0; i < X->n; i++ )
        for( j = 0; j < biL; j++, count++ )
            if( ( ( X->p[i] >> j ) & 1 ) != 0 )
                return( count );

    return( 0 );
}

/*
 * Return the number of bits
 */
U32 SC_Bigint_Bitlen( const SC_BIGINT *X )
{
    U32 i, j;

    if( X->n == 0 )
        return( 0 );

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;

    for( j = biL; j > 0; j-- )
        if( ( ( X->p[i] >> ( j - 1 ) ) & 1 ) != 0 )
            break;

    return( ( i * biL ) + j );
}

/*
 * Return the total size in bytes
 */
U32 SC_Bigint_Size( const SC_BIGINT *X )
{
    return( ( SC_Bigint_Bitlen( X ) + 7 ) >> 3 );
}

/*
 * Convert an ASCII character to U32 value
 */
static int SCC_Get_Digit( U32 *d, int radix, char c )
{
    *d = 255;

    if( c >= 0x30 && c <= 0x39 ) *d = c - 0x30;
    if( c >= 0x41 && c <= 0x46 ) *d = c - 0x37;
    if( c >= 0x61 && c <= 0x66 ) *d = c - 0x57;

    if( *d >= (U32) radix )
        return( SCC_BIGNUM_ERROR_INVALID_CHARACTER );

    return( 0 );
}

/*
 * Import from an ASCII string
 */
int SC_Bigint_Read_String( SC_BIGINT *X, int radix, const char *s )
{
    int retCode;
    U32 i, j, slen, n;
    U32 d;
    SC_BIGINT T;

    if( radix < 2 || radix > 16 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    SC_Bigint_New( &T );

    slen = (U32)strlen( s );

    if( radix == 16 )
    {
        n = BITS_TO_LIMBS( slen << 2 );

        SC_BIGINT_CHK( SC_Bigint_Grow( X, n ) );
        SC_BIGINT_CHK( SC_Bigint_Lset( X, 0 ) );

        for( i = slen, j = 0; i > 0; i--, j++ )
        {
            if( i == 1 && s[i - 1] == '-' )
            {
                X->s = -1;
                break;
            }

            SC_BIGINT_CHK( SCC_Get_Digit( &d, radix, s[i - 1] ) );
            X->p[j / ( 2 * ciL )] |= d << ( ( j % ( 2 * ciL ) ) << 2 );
        }
    }
    else
    {
        SC_BIGINT_CHK( SC_Bigint_Lset( X, 0 ) );

        for( i = 0; i < slen; i++ )
        {
            if( i == 0 && s[i] == '-' )
            {
                X->s = -1;
                continue;
            }

            SC_BIGINT_CHK( SCC_Get_Digit( &d, radix, s[i] ) );
            SC_BIGINT_CHK( SC_Bigint_Mul_Int( &T, X, radix ) );

            SC_BIGINT_CHK( SC_Bigint_Add_Int( X, &T, d ) );
            SC_BIGINT_CHK( SC_Bigint_Sub_Int( X, &T, d ) );
        }
    }

end:

    SC_Bigint_Free( &T );

    return( retCode );
}

/*
 * Helper to write the digits high-order first
 */
static int SCC_Write_Hlp( SC_BIGINT *X, int radix, char **p )
{
    int retCode;
    U32 r;

    if( radix < 2 || radix > 16 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    SC_BIGINT_CHK( SC_Bigint_Mod_Int( &r, X, radix ) );
    SC_BIGINT_CHK( SC_Bigint_Div_Int( X, NULL, X, radix ) );

    if( SC_Bigint_Cmp_Int( X, 0 ) != 0 )
        SC_BIGINT_CHK( SCC_Write_Hlp( X, radix, p ) );

    if( r < 10 )
        *(*p)++ = (char)( r + 0x30 );
    else
        *(*p)++ = (char)( r + 0x37 );

end:

    return( retCode );
}

/*
 * Export into an ASCII string
 */
int SC_Bigint_Write_String( const SC_BIGINT *X, int radix,
                              char *buf, U32 buflen, U32 *olen )
{
    int retCode = 0;
    U32 n;
    char *p;
    SC_BIGINT T;

    if( radix < 2 || radix > 16 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    n = SC_Bigint_Bitlen( X );
    if( radix >=  4 ) n >>= 1;
    if( radix >= 16 ) n >>= 1;
    n += 3;

    if( buflen < n )
    {
        *olen = n;
        return( SCC_BIGNUM_ERROR_BUFFER_TOO_SMALL );
    }

    p = buf;
    SC_Bigint_New( &T );

    if( X->s == -1 )
        *p++ = '-';

    if( radix == 16 )
    {
        int c;
        U32 i, j, k;

        for( i = X->n, k = 0; i > 0; i-- )
        {
            for( j = ciL; j > 0; j-- )
            {
                c = ( X->p[i - 1] >> ( ( j - 1 ) << 3) ) & 0xFF;

                if( c == 0 && k == 0 && ( i + j ) != 2 )
                    continue;

                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
    }
    else
    {
        SC_BIGINT_CHK( SC_Bigint_Copy( &T, X ) );

        if( T.s == -1 )
            T.s = 1;

        SC_BIGINT_CHK( SCC_Write_Hlp( &T, radix, &p ) );
    }

    *p++ = '\0';
    *olen = (U32)(p - buf);

end:

    SC_Bigint_Free( &T );

    return( retCode );
}

/*
 * Import X from unsigned binary data, big endian
 */
int SC_Bigint_Read_Binary( SC_BIGINT *X, const U8 *buf, U32 buflen )
{
    int retCode;
    U32 i, j, n;

    for( n = 0; n < buflen; n++ )
        if( buf[n] != 0 )
            break;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, CHARS_TO_LIMBS( buflen - n ) ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( X, 0 ) );

    for( i = buflen, j = 0; i > n; i--, j++ )
        X->p[j / ciL] |= ((U32) buf[i - 1]) << ((j % ciL) << 3);

end:

    return( retCode );
}

/*
 * Export X into unsigned binary data, big endian
 */
int SC_Bigint_Write_Binary( const SC_BIGINT *X, U8 *buf, U32 buflen )
{
    U32 i, j, n;

    n = SC_Bigint_Size( X );

    if( buflen < n )
        return( SCC_BIGNUM_ERROR_BUFFER_TOO_SMALL );

    SC_Memzero( buf, 0, buflen );

    for( i = buflen - 1, j = 0; n > 0; i--, j++, n-- )
        buf[i] = (U8)( X->p[j / ciL] >> ((j % ciL) << 3) );

    return( 0 );
}

/*
 * Left-shift: X <<= count
 */
int SC_Bigint_Shift_I( SC_BIGINT *X, U32 count )
{
    int retCode;
    U32 i, v0, t1;
    U32 r0 = 0, r1;

    v0 = count / (biL    );
    t1 = count & (biL - 1);

    i = SC_Bigint_Bitlen( X ) + count;

    if( X->n * biL < i )
        SC_BIGINT_CHK( SC_Bigint_Grow( X, BITS_TO_LIMBS( i ) ) );

    retCode = 0;

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = X->n; i > v0; i-- )
            X->p[i - 1] = X->p[i - v0 - 1];

        for( ; i > 0; i-- )
            X->p[i - 1] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( t1 > 0 )
    {
        for( i = v0; i < X->n; i++ )
        {
            r1 = X->p[i] >> (biL - t1);
            X->p[i] <<= t1;
            X->p[i] |= r0;
            r0 = r1;
        }
    }

end:

    return( retCode );
}

/*
 * Right-shift: X >>= count
 */
int SC_Bigint_Shift_R( SC_BIGINT *X, U32 count )
{
    U32 i, v0, v1;
    U32 r0 = 0, r1;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if( v0 > X->n || ( v0 == X->n && v1 > 0 ) )
        return SC_Bigint_Lset( X, 0 );

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < X->n - v0; i++ )
            X->p[i] = X->p[i + v0];

        for( ; i < X->n; i++ )
            X->p[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        for( i = X->n; i > 0; i-- )
        {
            r1 = X->p[i - 1] << (biL - v1);
            X->p[i - 1] >>= v1;
            X->p[i - 1] |= r0;
            r0 = r1;
        }
    }

    return( 0 );
}

/*
 * Compare unsigned values
 */
int SC_Bigint_Cmp_Abs( const SC_BIGINT *X, const SC_BIGINT *Y )
{
    U32 i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  1 );
    if( j > i ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  1 );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -1 );
    }

    return( 0 );
}


/*
 * Compare signed values
 */
int SC_Bigint_Cmp_Bignum( const SC_BIGINT *X, const SC_BIGINT *Y )
{
    U32 i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  X->s );
    if( j > i ) return( -Y->s );

    if( X->s > 0 && Y->s < 0 ) return(  1 );
    if( Y->s > 0 && X->s < 0 ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  X->s );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -X->s );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
int SC_Bigint_Cmp_Int( const SC_BIGINT *X, int z )
{
    SC_BIGINT Y;
    U32 p[1];

    *p  = ( z < 0 ) ? -z : z;
    Y.s = ( z < 0 ) ? -1 : 1;
    Y.n = 1;
    Y.p = p;

    return( SC_Bigint_Cmp_Bignum( X, &Y ) );
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int SC_Bigint_Add_Abs( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode;
    U32 i, j;
    U32 *o, *p, c;

    if( X == B )
    {
        const SC_BIGINT *T = A; A = X; B = T;
    }

    if( X != A )
        SC_BIGINT_CHK( SC_Bigint_Copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned additions.
     */
    X->s = 1;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, j ) );

    o = B->p; p = X->p; c = 0;

    for( i = 0; i < j; i++, o++, p++ )
    {
        *p +=  c; c  = ( *p <  c );
        *p += *o; c += ( *p < *o );
    }

    while( c != 0 )
    {
        if( i >= X->n )
        {
            SC_BIGINT_CHK( SC_Bigint_Grow( X, i + 1 ) );
            p = X->p + i;
        }

        *p += c; c = ( *p < c ); i++; p++;
    }

end:

    return( retCode );
}

/*
 * Helper for SC_BIGINT subtraction
 */
static void SCC_Bigint_Sub_Hlp( U32 n, U32 *s, U32 *d )
{
    U32 i;
    U32 c, z;

    for( i = c = 0; i < n; i++, s++, d++ )
    {
        z = ( *d <  c );     *d -=  c;
        c = ( *d < *s ) + z; *d -= *s;
    }

    while( c != 0 )
    {
        z = ( *d < c ); *d -= c;
        c = z; i++; d++;
    }
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
int SC_Bigint_Sub_Abs( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B )
{
    SC_BIGINT TB;
    int retCode;
    U32 n;

    if( SC_Bigint_Cmp_Abs( A, B ) < 0 )
        return( SCC_BIGNUM_ERROR_NEGATIVE_VALUE );

    SC_Bigint_New( &TB );

    if( X == B )
    {
        SC_BIGINT_CHK( SC_Bigint_Copy( &TB, B ) );
        B = &TB;
    }

    if( X != A )
        SC_BIGINT_CHK( SC_Bigint_Copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned subtractions.
     */
    X->s = 1;

    retCode = 0;

    for( n = B->n; n > 0; n-- )
        if( B->p[n - 1] != 0 )
            break;

    SCC_Bigint_Sub_Hlp( n, B->p, X->p );

end:

    SC_Bigint_Free( &TB );

    return( retCode );
}

/*
 * Signed addition: X = A + B
 */
int SC_Bigint_Add_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode, s = A->s;

    if( A->s * B->s < 0 )
    {
        if( SC_Bigint_Cmp_Abs( A, B ) >= 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        SC_BIGINT_CHK( SC_Bigint_Add_Abs( X, A, B ) );
        X->s = s;
    }

end:

    return( retCode );
}

/*
 * Signed subtraction: X = A - B
 */
int SC_Bigint_Sub_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode, s = A->s;

    if( A->s * B->s > 0 )
    {
        if( SC_Bigint_Cmp_Abs( A, B ) >= 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        SC_BIGINT_CHK( SC_Bigint_Add_Abs( X, A, B ) );
        X->s = s;
    }

end:

    return( retCode );
}

/*
 * Signed addition: X = A + b
 */
int SC_Bigint_Add_Int( SC_BIGINT *X, const SC_BIGINT *A, int b )
{
    SC_BIGINT _B;
    U32 p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( SC_Bigint_Add_Bignum( X, A, &_B ) );
}

/*
 * Signed subtraction: X = A - b
 */
int SC_Bigint_Sub_Int( SC_BIGINT *X, const SC_BIGINT *A, int b )
{
    SC_BIGINT _B;
    U32 p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( SC_Bigint_Sub_Bignum( X, A, &_B ) );
}

/*
 * Helper for SC_BIGINT multiplication
 */
static
void SCC_Bigint_Mul_Hlp( U32 i, U32 *s, U32 *d, U32 b )
{
    U32 c = 0, t = 0;

#if defined(MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_HUIT
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#else /* MULADDC_HUIT */
    for( ; i >= 16; i -= 16 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#endif /* MULADDC_HUIT */

    t++;

    do {
        *d += c; c = ( *d < c ); d++;
    }
    while( c != 0 );
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int SC_Bigint_Mul_Bignum( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode;
    U32 i, j;
    SC_BIGINT TA, TB;

    SC_Bigint_New( &TA ); SC_Bigint_New( &TB );

    if( X == A ) { SC_BIGINT_CHK( SC_Bigint_Copy( &TA, A ) ); A = &TA; }
    if( X == B ) { SC_BIGINT_CHK( SC_Bigint_Copy( &TB, B ) ); B = &TB; }

    for( i = A->n; i > 0; i-- )
        if( A->p[i - 1] != 0 )
            break;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    SC_BIGINT_CHK( SC_Bigint_Grow( X, i + j ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( X, 0 ) );

    for( i++; j > 0; j-- )
        SCC_Bigint_Mul_Hlp( i - 1, A->p, X->p + j - 1, B->p[j - 1] );

    X->s = A->s * B->s;

end:

    SC_Bigint_Free( &TB ); SC_Bigint_Free( &TA );

    return( retCode );
}

/*
 * Baseline multiplication: X = A * b
 */
int SC_Bigint_Mul_Int( SC_BIGINT *X, const SC_BIGINT *A, U32 b )
{
    SC_BIGINT _B;
    U32 p[1];

    _B.s = 1;
    _B.n = 1;
    _B.p = p;
    p[0] = b;

    return( SC_Bigint_Mul_Bignum( X, A, &_B ) );
}

/*
 * Division by SC_BIGINT: A = Q * B + R  (HAC 14.20)
 */
int SC_Bigint_Div_Bignum( SC_BIGINT *Q, SC_BIGINT *R, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode;
    U32 i, n, t, k;
    SC_BIGINT X, Y, Z, T1, T2;

    if( SC_Bigint_Cmp_Int( B, 0 ) == 0 )
        return( SCC_BIGNUM_ERROR_DIVISION_BY_ZERO );

    SC_Bigint_New( &X ); SC_Bigint_New( &Y ); SC_Bigint_New( &Z );
    SC_Bigint_New( &T1 ); SC_Bigint_New( &T2 );

    if( SC_Bigint_Cmp_Abs( A, B ) < 0 )
    {
        if( Q != NULL ) SC_BIGINT_CHK( SC_Bigint_Lset( Q, 0 ) );
        if( R != NULL ) SC_BIGINT_CHK( SC_Bigint_Copy( R, A ) );
        return( 0 );
    }

    SC_BIGINT_CHK( SC_Bigint_Copy( &X, A ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( &Y, B ) );
    X.s = Y.s = 1;

    SC_BIGINT_CHK( SC_Bigint_Grow( &Z, A->n + 2 ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( &Z,  0 ) );
    SC_BIGINT_CHK( SC_Bigint_Grow( &T1, 2 ) );
    SC_BIGINT_CHK( SC_Bigint_Grow( &T2, 3 ) );

    k = SC_Bigint_Bitlen( &Y ) % biL;
    if( k < biL - 1 )
    {
        k = biL - 1 - k;
        SC_BIGINT_CHK( SC_Bigint_Shift_I( &X, k ) );
        SC_BIGINT_CHK( SC_Bigint_Shift_I( &Y, k ) );
    }
    else k = 0;

    n = X.n - 1;
    t = Y.n - 1;
    SC_BIGINT_CHK( SC_Bigint_Shift_I( &Y, biL * ( n - t ) ) );

    while( SC_Bigint_Cmp_Bignum( &X, &Y ) >= 0 )
    {
        Z.p[n - t]++;
        SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &X, &X, &Y ) );
    }
    SC_BIGINT_CHK( SC_Bigint_Shift_R( &Y, biL * ( n - t ) ) );

    for( i = n; i > t ; i-- )
    {
        if( X.p[i] >= Y.p[t] )
            Z.p[i - t - 1] = ~0;
        else
        {
            /*
             * __udiv_qrnnd_c, from gmp/longlong.h
             */
            U32 q0, q1, r0, r1;
            U32 d0, d1, d, m;

            d  = Y.p[t];
            d0 = ( d << biH ) >> biH;
            d1 = ( d >> biH );

            q1 = X.p[i] / d1;
            r1 = X.p[i] - d1 * q1;
            r1 <<= biH;
            r1 |= ( X.p[i - 1] >> biH );

            m = q1 * d0;
            if( r1 < m )
            {
                q1--, r1 += d;
                while( r1 >= d && r1 < m )
                    q1--, r1 += d;
            }
            r1 -= m;

            q0 = r1 / d1;
            r0 = r1 - d1 * q0;
            r0 <<= biH;
            r0 |= ( X.p[i - 1] << biH ) >> biH;

            m = q0 * d0;
            if( r0 < m )
            {
                q0--, r0 += d;
                while( r0 >= d && r0 < m )
                    q0--, r0 += d;
            }
            //r0 -= m;

            Z.p[i - t - 1] = ( q1 << biH ) | q0;
        }

        Z.p[i - t - 1]++;
        do
        {
            Z.p[i - t - 1]--;

            SC_BIGINT_CHK( SC_Bigint_Lset( &T1, 0 ) );
            T1.p[0] = ( t < 1 ) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            SC_BIGINT_CHK( SC_Bigint_Mul_Int( &T1, &T1, Z.p[i - t - 1] ) );

            SC_BIGINT_CHK( SC_Bigint_Lset( &T2, 0 ) );
            T2.p[0] = ( i < 2 ) ? 0 : X.p[i - 2];
            T2.p[1] = ( i < 1 ) ? 0 : X.p[i - 1];
            T2.p[2] = X.p[i];
        }
        while( SC_Bigint_Cmp_Bignum( &T1, &T2 ) > 0 );

        SC_BIGINT_CHK( SC_Bigint_Mul_Int( &T1, &Y, Z.p[i - t - 1] ) );
        SC_BIGINT_CHK( SC_Bigint_Shift_I( &T1,  biL * ( i - t - 1 ) ) );
        SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &X, &X, &T1 ) );

        if( SC_Bigint_Cmp_Int( &X, 0 ) < 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Copy( &T1, &Y ) );
            SC_BIGINT_CHK( SC_Bigint_Shift_I( &T1, biL * ( i - t - 1 ) ) );
            SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &X, &X, &T1 ) );
            Z.p[i - t - 1]--;
        }
    }

    if( Q != NULL )
    {
        SC_BIGINT_CHK( SC_Bigint_Copy( Q, &Z ) );
        Q->s = A->s * B->s;
    }

    if( R != NULL )
    {
        SC_BIGINT_CHK( SC_Bigint_Shift_R( &X, k ) );
        X.s = A->s;
        SC_BIGINT_CHK( SC_Bigint_Copy( R, &X ) );

        if( SC_Bigint_Cmp_Int( R, 0 ) == 0 )
            R->s = 1;
    }

end:

    SC_Bigint_Free( &X ); SC_Bigint_Free( &Y ); SC_Bigint_Free( &Z );
    SC_Bigint_Free( &T1 ); SC_Bigint_Free( &T2 );

    return( retCode );
}

/*
 * Division by int: A = Q * b + R
 */
int SC_Bigint_Div_Int( SC_BIGINT *Q, SC_BIGINT *R, const SC_BIGINT *A, int b )
{
    SC_BIGINT _B;
    U32 p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( SC_Bigint_Div_Bignum( Q, R, A, &_B ) );
}

/*
 * Modulo: R = A mod B
 */
int SC_Bigint_Mod_Bignum( SC_BIGINT *R, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode;

    if( SC_Bigint_Cmp_Int( B, 0 ) < 0 )
        return( SCC_BIGNUM_ERROR_NEGATIVE_VALUE );

    SC_BIGINT_CHK( SC_Bigint_Div_Bignum( NULL, R, A, B ) );

    while( SC_Bigint_Cmp_Int( R, 0 ) < 0 )
      SC_BIGINT_CHK( SC_Bigint_Add_Bignum( R, R, B ) );

    while( SC_Bigint_Cmp_Bignum( R, B ) >= 0 )
      SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( R, R, B ) );

end:

    return( retCode );
}

/*
 * Modulo: r = A mod b
 */
int SC_Bigint_Mod_Int( U32 *r, const SC_BIGINT *A, int b )
{
    U32 i;
    U32 x, y, z;

    if( b == 0 )
        return( SCC_BIGNUM_ERROR_DIVISION_BY_ZERO );

    if( b < 0 )
        return( SCC_BIGNUM_ERROR_NEGATIVE_VALUE );

    /*
     * handle trivial cases
     */
    if( b == 1 )
    {
        *r = 0;
        return( 0 );
    }

    if( b == 2 )
    {
        *r = A->p[0] & 1;
        return( 0 );
    }

    /*
     * general case
     */
    for( i = A->n, y = 0; i > 0; i-- )
    {
        x  = A->p[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if( A->s < 0 && y != 0 )
        y = b - y;

    *r = y;

    return( 0 );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void SCC_Bigint_Montg_Init( U32 *mm, const SC_BIGINT *N )
{
    U32 x, m0 = N->p[0];
    U32 i;

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;

    for( i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( m0 * x ) );

    *mm = ~x + 1;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 */
static void SCC_Bigint_Montmul( SC_BIGINT *A, const SC_BIGINT *B, const SC_BIGINT *N, U32 mm,
                         const SC_BIGINT *T )
{
    U32 i, n, m;
    U32 u0, u1, *d;

    SC_Memzero( T->p, 0, T->n * ciL );

    d = T->p;
    n = N->n;
    m = ( B->n < n ) ? B->n : n;

    for( i = 0; i < n; i++ )
    {
        /*
         * T = (T + u0*B + u1*N) / 2^biL
         */
        u0 = A->p[i];
        u1 = ( d[0] + u0 * B->p[0] ) * mm;

        SCC_Bigint_Mul_Hlp( m, B->p, d, u0 );
        SCC_Bigint_Mul_Hlp( n, N->p, d, u1 );

        *d++ = u0; d[n + 1] = 0;
    }

    memcpy( A->p, d, ( n + 1 ) * ciL );

    if( SC_Bigint_Cmp_Abs( A, N ) >= 0 )
        SCC_Bigint_Sub_Hlp( n, N->p, A->p );
    else
        /* prevent timing attacks */
        SCC_Bigint_Sub_Hlp( n, A->p, T->p );
}

/*
 * Montgomery reduction: A = A * R^-1 mod N
 */
static void SCC_Bigint_Montred( SC_BIGINT *A, const SC_BIGINT *N, U32 mm, const SC_BIGINT *T )
{
    U32 z = 1;
    SC_BIGINT U;

    U.n = U.s = (int) z;
    U.p = &z;

    SCC_Bigint_Montmul( A, &U, N, mm, T );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
int SC_Bigint_Exp_Mod( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *E, const SC_BIGINT *N, SC_BIGINT *_RR )
{
    int retCode;
    U32 wbits, wsize, one = 1;
    U32 i, j, nblimbs;
    U32 bufsize, nbits;
    U32 ei, mm, state;
    SC_BIGINT RR, T, W[ 2 << SC_BIGINT_WINDOW_SIZE ], Apos;
    int neg;

    if( SC_Bigint_Cmp_Int( N, 0 ) < 0 || ( N->p[0] & 1 ) == 0 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    if( SC_Bigint_Cmp_Int( E, 0 ) < 0 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    /*
     * Init temps and window size
     */
    SCC_Bigint_Montg_Init( &mm, N );
    SC_Bigint_New( &RR ); SC_Bigint_New( &T );
    SC_Bigint_New( &Apos );
    SC_Memzero( W, 0, sizeof( W ) );

    i = SC_Bigint_Bitlen( E );

    wsize = ( i > 671 ) ? 6 : ( i > 239 ) ? 5 :
            ( i >  79 ) ? 4 : ( i >  23 ) ? 3 : 1;

    //if( wsize > SC_BIGINT_WINDOW_SIZE )
    //    wsize = SC_BIGINT_WINDOW_SIZE;

    j = N->n + 1;
    SC_BIGINT_CHK( SC_Bigint_Grow( X, j ) );
    SC_BIGINT_CHK( SC_Bigint_Grow( &W[1],  j ) );
    SC_BIGINT_CHK( SC_Bigint_Grow( &T, j * 2 ) );

    /*
     * Compensate for negative A (and correct at the end)
     */
    neg = ( A->s == -1 );
    if( neg )
    {
        SC_BIGINT_CHK( SC_Bigint_Copy( &Apos, A ) );
        Apos.s = 1;
        A = &Apos;
    }

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if( _RR == NULL || _RR->p == NULL )
    {
        SC_BIGINT_CHK( SC_Bigint_Lset( &RR, 1 ) );
        SC_BIGINT_CHK( SC_Bigint_Shift_I( &RR, N->n * 2 * biL ) );
        SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &RR, &RR, N ) );

        if( _RR != NULL )
            memcpy( _RR, &RR, sizeof( SC_BIGINT ) );
    }
    else
        memcpy( &RR, _RR, sizeof( SC_BIGINT ) );

    /*
     * W[1] = A * R^2 * R^-1 mod N = A * R mod N
     */
    if( SC_Bigint_Cmp_Bignum( A, N ) >= 0 )
        SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &W[1], A, N ) );
    else
        SC_BIGINT_CHK( SC_Bigint_Copy( &W[1], A ) );

    SCC_Bigint_Montmul( &W[1], &RR, N, mm, &T );

    /*
     * X = R^2 * R^-1 mod N = R mod N
     */
    SC_BIGINT_CHK( SC_Bigint_Copy( X, &RR ) );
    SCC_Bigint_Montred( X, N, mm, &T );

    if( wsize > 1 )
    {
        /*
         * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
         */
        j =  one << ( wsize - 1 );

        SC_BIGINT_CHK( SC_Bigint_Grow( &W[j], N->n + 1 ) );
        SC_BIGINT_CHK( SC_Bigint_Copy( &W[j], &W[1]    ) );

        for( i = 0; i < wsize - 1; i++ )
            SCC_Bigint_Montmul( &W[j], &W[j], N, mm, &T );

        /*
         * W[i] = W[i - 1] * W[1]
         */
        for( i = j + 1; i < ( one << wsize ); i++ )
        {
            SC_BIGINT_CHK( SC_Bigint_Grow( &W[i], N->n + 1 ) );
            SC_BIGINT_CHK( SC_Bigint_Copy( &W[i], &W[i - 1] ) );

            SCC_Bigint_Montmul( &W[i], &W[1], N, mm, &T );
        }
    }

    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs == 0 )
                break;

            nblimbs--;

            bufsize = sizeof( U32 ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
            SCC_Bigint_Montmul( X, X, N, mm, &T );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= ( ei << ( wsize - nbits ) );

        if( nbits == wsize )
        {
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ )
                SCC_Bigint_Montmul( X, X, N, mm, &T );

            /*
             * X = X * W[wbits] R^-1 mod N
             */
            SCC_Bigint_Montmul( X, &W[wbits], N, mm, &T );

            state--;
            nbits = 0;
            wbits = 0;
        }
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        SCC_Bigint_Montmul( X, X, N, mm, &T );

        wbits <<= 1;

        if( ( wbits & ( one << wsize ) ) != 0 )
            SCC_Bigint_Montmul( X, &W[1], N, mm, &T );
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    SCC_Bigint_Montred( X, N, mm, &T );

    if( neg )
    {
        X->s = -1;
        SC_BIGINT_CHK( SC_Bigint_Add_Bignum( X, N, X ) );
    }

end:

    for( i = ( one << ( wsize - 1 ) ); i < ( one << wsize ); i++ )
        SC_Bigint_Free( &W[i] );

    SC_Bigint_Free( &W[1] ); SC_Bigint_Free( &T ); SC_Bigint_Free( &Apos );

    if( _RR == NULL || _RR->p == NULL )
        SC_Bigint_Free( &RR );

    return( retCode );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int SC_Bigint_Gcd( SC_BIGINT *G, const SC_BIGINT *A, const SC_BIGINT *B )
{
    int retCode;
    U32 lz, lzt;
    SC_BIGINT TG, TA, TB;

    SC_Bigint_New( &TG ); SC_Bigint_New( &TA ); SC_Bigint_New( &TB );

    SC_BIGINT_CHK( SC_Bigint_Copy( &TA, A ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( &TB, B ) );

    lz = SC_Bigint_Lsb( &TA );
    lzt = SC_Bigint_Lsb( &TB );

    if( lzt < lz )
        lz = lzt;

    SC_BIGINT_CHK( SC_Bigint_Shift_R( &TA, lz ) );
    SC_BIGINT_CHK( SC_Bigint_Shift_R( &TB, lz ) );

    TA.s = TB.s = 1;

    while( SC_Bigint_Cmp_Int( &TA, 0 ) != 0 )
    {
        SC_BIGINT_CHK( SC_Bigint_Shift_R( &TA, SC_Bigint_Lsb( &TA ) ) );
        SC_BIGINT_CHK( SC_Bigint_Shift_R( &TB, SC_Bigint_Lsb( &TB ) ) );

        if( SC_Bigint_Cmp_Bignum( &TA, &TB ) >= 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( &TA, &TA, &TB ) );
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &TA, 1 ) );
        }
        else
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Abs( &TB, &TB, &TA ) );
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &TB, 1 ) );
        }
    }

    SC_BIGINT_CHK( SC_Bigint_Shift_I( &TB, lz ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( G, &TB ) );

end:

    SC_Bigint_Free( &TG ); SC_Bigint_Free( &TA ); SC_Bigint_Free( &TB );

    return( retCode );
}

/*
 * Fill X with size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
int SC_Bigint_Fill_Random( SC_BIGINT *X, U32 size)
{
    int retCode;
    U8 buf[SC_BIGINT_MAX_SIZE];

    if( size > SC_BIGINT_MAX_SIZE )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );
	
    SC_BIGINT_CHK( SC_GetRandom(buf, size));
    SC_BIGINT_CHK( SC_Bigint_Read_Binary( X, buf, size ) );

end:
    return( retCode );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
int SC_Bigint_Inv_Mod( SC_BIGINT *X, const SC_BIGINT *A, const SC_BIGINT *N )
{
    int retCode;
    SC_BIGINT G, TA, TU, U1, U2, TB, TV, V1, V2;

    if( SC_Bigint_Cmp_Int( N, 0 ) <= 0 )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    SC_Bigint_New( &TA ); SC_Bigint_New( &TU ); SC_Bigint_New( &U1 ); SC_Bigint_New( &U2 );
    SC_Bigint_New( &G ); SC_Bigint_New( &TB ); SC_Bigint_New( &TV );
    SC_Bigint_New( &V1 ); SC_Bigint_New( &V2 );

    SC_BIGINT_CHK( SC_Bigint_Gcd( &G, A, N ) );

    if( SC_Bigint_Cmp_Int( &G, 1 ) != 0 )
    {
        retCode = SCC_BIGNUM_ERROR_NOT_ACCEPTABLE;
        goto end;
    }

    SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &TA, A, N ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( &TU, &TA ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( &TB, N ) );
    SC_BIGINT_CHK( SC_Bigint_Copy( &TV, N ) );

    SC_BIGINT_CHK( SC_Bigint_Lset( &U1, 1 ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( &U2, 0 ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( &V1, 0 ) );
    SC_BIGINT_CHK( SC_Bigint_Lset( &V2, 1 ) );

    do
    {
        while( ( TU.p[0] & 1 ) == 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &TU, 1 ) );

            if( ( U1.p[0] & 1 ) != 0 || ( U2.p[0] & 1 ) != 0 )
            {
                SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &U1, &U1, &TB ) );
                SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &U2, &U2, &TA ) );
            }

            SC_BIGINT_CHK( SC_Bigint_Shift_R( &U1, 1 ) );
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &U2, 1 ) );
        }

        while( ( TV.p[0] & 1 ) == 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &TV, 1 ) );

            if( ( V1.p[0] & 1 ) != 0 || ( V2.p[0] & 1 ) != 0 )
            {
                SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &V1, &V1, &TB ) );
                SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &V2, &V2, &TA ) );
            }

            SC_BIGINT_CHK( SC_Bigint_Shift_R( &V1, 1 ) );
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &V2, 1 ) );
        }

        if( SC_Bigint_Cmp_Bignum( &TU, &TV ) >= 0 )
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &TU, &TU, &TV ) );
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &U1, &U1, &V1 ) );
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &U2, &U2, &V2 ) );
        }
        else
        {
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &TV, &TV, &TU ) );
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &V1, &V1, &U1 ) );
            SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &V2, &V2, &U2 ) );
        }
    }
    while( SC_Bigint_Cmp_Int( &TU, 0 ) != 0 );

    while( SC_Bigint_Cmp_Int( &V1, 0 ) < 0 )
        SC_BIGINT_CHK( SC_Bigint_Add_Bignum( &V1, &V1, N ) );

    while( SC_Bigint_Cmp_Bignum( &V1, N ) >= 0 )
        SC_BIGINT_CHK( SC_Bigint_Sub_Bignum( &V1, &V1, N ) );

    SC_BIGINT_CHK( SC_Bigint_Copy( X, &V1 ) );

end:

    SC_Bigint_Free( &TA ); SC_Bigint_Free( &TU ); SC_Bigint_Free( &U1 ); SC_Bigint_Free( &U2 );
    SC_Bigint_Free( &G ); SC_Bigint_Free( &TB ); SC_Bigint_Free( &TV );
    SC_Bigint_Free( &V1 ); SC_Bigint_Free( &V2 );

    return( retCode );
}

static const int small_prime[] =
{
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,  709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  797,  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, -103
};

/*
 * Small divisors test (X must be positive)
 *
 * Return values:
 * 0: no small factor (possible prime, more tests needed)
 * 1: certain prime
 * SCC_BIGNUM_ERROR_NOT_ACCEPTABLE: certain non-prime
 * other negative: error
 */
static int SC_Check_Small_Factors( const SC_BIGINT *X )
{
    int retCode = 0;
    U32 i;
    U32 r;

    if( ( X->p[0] & 1 ) == 0 )
        return( SCC_BIGNUM_ERROR_NOT_ACCEPTABLE );

    for( i = 0; small_prime[i] > 0; i++ )
    {
        if( SC_Bigint_Cmp_Int( X, small_prime[i] ) <= 0 )
            return( 1 );

        SC_BIGINT_CHK( SC_Bigint_Mod_Int( &r, X, small_prime[i] ) );

        if( r == 0 )
            return( SCC_BIGNUM_ERROR_NOT_ACCEPTABLE );
    }

end:
    return( retCode );
}

/*
 * Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
int SC_Miller_Rabin( const SC_BIGINT *X)
{
    int retCode, count;
    U32 i, j, k, n, s;
    SC_BIGINT W, R, T, A, RR;

    SC_Bigint_New( &W ); SC_Bigint_New( &R ); SC_Bigint_New( &T ); SC_Bigint_New( &A );
    SC_Bigint_New( &RR );

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    SC_BIGINT_CHK( SC_Bigint_Sub_Int( &W, X, 1 ) );
    s = SC_Bigint_Lsb( &W );
    SC_BIGINT_CHK( SC_Bigint_Copy( &R, &W ) );
    SC_BIGINT_CHK( SC_Bigint_Shift_R( &R, s ) );

    i = SC_Bigint_Bitlen( X );
    /*
     * HAC, table 4.4
     */
    n = ( ( i >= 1300 ) ?  2 : ( i >=  850 ) ?  3 :
          ( i >=  650 ) ?  4 : ( i >=  350 ) ?  8 :
          ( i >=  250 ) ? 12 : ( i >=  150 ) ? 18 : 27 );

    for( i = 0; i < n; i++ )
    {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        SC_BIGINT_CHK( SC_Bigint_Fill_Random( &A, X->n * ciL) );

        if( SC_Bigint_Cmp_Bignum( &A, &W ) >= 0 )
        {
            j = SC_Bigint_Bitlen( &A ) - SC_Bigint_Bitlen( &W );
            SC_BIGINT_CHK( SC_Bigint_Shift_R( &A, j + 1 ) );
        }
        A.p[0] |= 3;

        count = 0;
        do {
            SC_BIGINT_CHK( SC_Bigint_Fill_Random( &A, X->n * ciL) );

            j = SC_Bigint_Bitlen( &A );
            k = SC_Bigint_Bitlen( &W );
            if (j > k) {
                SC_BIGINT_CHK( SC_Bigint_Shift_R( &A, j - k ) );
            }

            if (count++ > 30) {
                return SCC_BIGNUM_ERROR_NOT_ACCEPTABLE;
            }

        } while ( SC_Bigint_Cmp_Bignum( &A, &W ) >= 0 ||
                  SC_Bigint_Cmp_Int( &A, 1 )  <= 0    );

        /*
         * A = A^R mod |X|
         */
        SC_BIGINT_CHK( SC_Bigint_Exp_Mod( &A, &A, &R, X, &RR ) );

        if( SC_Bigint_Cmp_Bignum( &A, &W ) == 0 ||
            SC_Bigint_Cmp_Int( &A,  1 ) == 0 )
            continue;

        j = 1;
        while( j < s && SC_Bigint_Cmp_Bignum( &A, &W ) != 0 )
        {
            /*
             * A = A * A mod |X|
             */
            SC_BIGINT_CHK( SC_Bigint_Mul_Bignum( &T, &A, &A ) );
            SC_BIGINT_CHK( SC_Bigint_Mod_Bignum( &A, &T, X  ) );

            if( SC_Bigint_Cmp_Int( &A, 1 ) == 0 )
                break;

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if( SC_Bigint_Cmp_Bignum( &A, &W ) != 0 ||
            SC_Bigint_Cmp_Int( &A,  1 ) == 0 )
        {
            retCode = SCC_BIGNUM_ERROR_NOT_ACCEPTABLE;
            break;
        }
    }

end:
    SC_Bigint_Free( &W ); SC_Bigint_Free( &R ); SC_Bigint_Free( &T ); SC_Bigint_Free( &A );
    SC_Bigint_Free( &RR );

    return( retCode );
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int SC_Bigint_Is_Prime( const SC_BIGINT *X)
{
    int retCode;
    SC_BIGINT XX;

    XX.s = 1;
    XX.n = X->n;
    XX.p = X->p;

    if( SC_Bigint_Cmp_Int( &XX, 0 ) == 0 ||
        SC_Bigint_Cmp_Int( &XX, 1 ) == 0 )
        return( SCC_BIGNUM_ERROR_NOT_ACCEPTABLE );

    if( SC_Bigint_Cmp_Int( &XX, 2 ) == 0 )
        return( 0 );

    if( ( retCode = SC_Check_Small_Factors( &XX ) ) != 0 )
    {
        if( retCode == 1 )
            return( 0 );

        return( retCode );
    }

    return( SC_Miller_Rabin( &XX) );
}

/*
 * Prime number generation
 */
int SC_Bigint_Gen_Prime( SC_BIGINT *X, U32 nbits)
{
    int retCode;
    U32 k, n;
    SC_BIGINT Y;

    if( nbits < 3 || nbits > SCC_BIGINT_MAX_BITS )
        return( SCC_BIGNUM_ERROR_BAD_INPUT_DATA );

    SC_Bigint_New( &Y );

    n = BITS_TO_LIMBS( nbits );

	// n 정수길이 난수 채우기
    SC_BIGINT_CHK( SC_Bigint_Fill_Random( X, n * ciL) );

    k = SC_Bigint_Bitlen( X );
    if( k > nbits ) SC_BIGINT_CHK( SC_Bigint_Shift_R( X, k - nbits + 1 ) );

    SC_Bigint_Set_Bit( X, nbits-1, 1 );

    X->p[0] |= 1;

    /*
     * An necessary condition for Y and X = 2Y + 1 to be prime
     * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
     * Make sure it is satisfied, while keeping X = 3 mod 4
     */

    while( ( retCode = SC_Bigint_Is_Prime( X) ) != 0 )
    {
        if( retCode != SCC_BIGNUM_ERROR_NOT_ACCEPTABLE )
            goto end;

        SC_BIGINT_CHK( SC_Bigint_Add_Int( X, X, 2 ) );
    }


end:

    SC_Bigint_Free( &Y );

    return( retCode );
}

//added by hnkwon for kcdsa 2015.12.02
int SC_Big_SubMod(SC_BIGINT *r, SC_BIGINT *a, SC_BIGINT *b, SC_BIGINT *m)				 
{
	int			retCode = 0;
	// to be freed {{
	SC_BIGINT	r0;
	// }}
	if (r == NULL || a == NULL || b == NULL || m == NULL)
		return SCC_BIGNUM_ERROR_BAD_INPUT_DATA;
	
	SC_Bigint_New( &r0 );

	retCode = SC_Bigint_Sub_Bignum(&r0, a, b);
	retCode |= SC_Bigint_Mod_Bignum(r, &r0, m);
	
	SC_Bigint_Free( &r0 );

	return retCode;
}

int SC_Big_MulMod(SC_BIGINT *output, SC_BIGINT *inputA, SC_BIGINT *inputB, SC_BIGINT *mod)
{
	SC_BIGINT	temp;
	int	retCode;

	if ((output == NULL) || (inputA == NULL) || (inputB == NULL) ||	(mod == NULL))
		return SCC_BIGNUM_ERROR_BAD_INPUT_DATA;
	
	SC_Bigint_New( &temp );

	retCode  = SC_Bigint_Mul_Bignum(&temp, inputA, inputB);
	retCode |= SC_Bigint_Mod_Bignum(output, &temp, mod);
	if (retCode != 0) goto end;

	retCode = 0;

end:
	SC_Bigint_Free( &temp );
	return retCode;
}