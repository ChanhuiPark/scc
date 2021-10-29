/* 
========================================
  scc_util.c
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scc_util.h"

int SC_Uint32ToByte (U8 *buf, U32 a)
{
	int pos = 0;

	buf[pos++] = (U8)((a >> 24) & 0x000000FF);
	buf[pos++] = (U8)((a >> 16) & 0x000000FF);
	buf[pos++] = (U8)((a >> 8) & 0x000000FF);
	buf[pos++] = (U8)(a & 0x000000FF);

	return pos;
}

/* For Network Byte Order : Big Endian */
U32 SC_ByteToUint32 (U8 *buf)
{
	U32 a = 0;
	int pos = 0;

	a = (U32)buf[pos++] << 24;
	a|= (U32)buf[pos++] << 16;
	a|= (U32)buf[pos++] << 8;
	a|= (U32)buf[pos++];

	return a;
}

// 자가무결성 검증용 공개키 노출방지를 위한 인코딩
int SC_Codec(U8 *output, U8 *input, int inputLength)
{
	int i = 0;
	U8 codecSeed[] = {0x13, 0x3D, 0x27, 0x03, 0xC2, 0x8C, 0xf1, 0x77, 0x93, 0x22, 0x86, 0x0F, 0x56, 0x6A, 0xBC, 0x32};
	
	for(i=0; i<inputLength; i++) {
		output[i] = input[i] ^ codecSeed[i % sizeof(codecSeed)];
	}

	return i;
}

// 컴파일러 최적화를 하지 않고 제로화 시킴
void SC_Memzero( void *v, U8 c, int n ) 
{
    volatile unsigned char *p = v; while( n-- ) *p++ = c;
}
