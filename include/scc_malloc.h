/* 
========================================
  scc_malloc.h 
    : memory allocation 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_MALLOC_H__
#define __SCC_MALLOC_H__

#include <stdlib.h>

void 
*sc_malloc(unsigned int size);

void 
*sc_calloc(unsigned int size, unsigned int count);

void 
sc_free(void *p);

#endif

