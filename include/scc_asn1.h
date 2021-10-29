/* 
========================================
  scc_asn1.h 
    : ASN.1
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/


#ifndef __SCC_ASN1_H__
#define __SCC_ASN1_H__

#define	SC_ASN1_TAG_INTEGER					0x02
#define	SC_ASN1_TAG_BIT_STRING				0x03
#define	SC_ASN1_TAG_OCTET_STRING			0x04
#define	SC_ASN1_TAG_NULL					0x05
#define	SC_ASN1_TAG_OBJECT_IDENTIFIER		0x06
#define SC_ASN1_TAG_SEQUENCE				0x30

#define	ASN1_ENCODE_START(buf, pos, eval)			\
{													\
	(pos) = 0;										\
	(buf) = (uint8 *) (eval);						\
}

//	out		: buf, pos
//	in		: eval
//
#define	ASN1_DECODE_START(buf, pos, eval)			\
{													\
	(pos) = 0;										\
	(buf) = (U8 *) (eval);							\
}

//	in/out	: buf, pos
//	in		: tag
//
#define	ASN1_TYPE_ENCODE(buf, pos, tag)				\
{													\
	(buf)[(pos)++] = (tag);							\
}

//	in/out	: buf, pos
//	out		: tag
//
#define	ASN1_TYPE_DECODE(buf, pos, tag)				\
{													\
	(tag) = (buf)[(pos)++];							\
}

//	in/out	: buf, pos
//	in		: tag
//
#define	ASN1_TYPE_CHECK(buf, pos, tag)				\
	if ((buf)[(pos)++] != (tag)) {					\
		retCode = SCC_ASN1_ERROR_BAD_DATA;			\
		goto end;									\
	}

//	in/out	: buf, pos
//	out		: len_size
//	in		: len
//
#define	ASN1_LENGTH_ENCODE(buf, pos, len_size, len)		\
{														\
	U8		c, i;										\
	c = 0;												\
	if ((len) >= 0x80) {								\
		c += 1;											\
		for (i=1; i<4; i++) 							\
			if ((len) >> (i << 3)) c++;					\
		(buf)[(pos)++] = 0x80 ^ c;						\
		for (i=0; i<c; i++)								\
			(buf)[(pos)++] = ((len) >> ((c-i-1) << 3));	\
	}													\
	else												\
		(buf)[(pos)++] = (len);							\
	len_size = c + 1;									\
}

//	in/out	: buf, pos
//	out		: len, len_size
//
#define	ASN1_LENGTH_DECODE(buf, pos, len, len_size)	\
{													\
	U8		c, i;									\
	c = 0;											\
	if ((buf)[(pos)] & 0x80) {						\
		c = (buf)[(pos)++] & 0x7F;					\
		(len) = 0;									\
		for (i=0; i<c; i++)							\
			(len) = ((len) << 8) | (buf)[(pos)++];	\
	}												\
	else											\
		(len) = (buf)[(pos)++] & 0x7F;				\
	len_size = c + 1;								\
}

//	in		: pos, len, total
//
#define	ASN1_LENGTH_CHECK(pos, len, total)			\
	if ((pos + len) > total) {						\
		retCode = SCC_ASN1_ERROR_INVALID_LENGTH;	\
		goto end;									\
	}												\


#endif