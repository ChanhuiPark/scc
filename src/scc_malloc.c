/* 
========================================
  scc_malloc.c 
    : memory allocation
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include "scc_malloc.h"

void *sc_malloc(unsigned int size)
{
	return malloc(size);
}

void *sc_calloc(unsigned int size, unsigned int count)
{
	return calloc(size, count);
}

void sc_free(volatile void *p)
{
	free((void *)p);
	p = NULL;
}