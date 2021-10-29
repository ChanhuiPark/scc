/* 
========================================
  scc_random.c
    : 
----------------------------------------
  softcamp(c).
  2015.10.
========================================
*/

#include <stdlib.h>
#include <string.h>

#ifdef	_WIN32
#include <windows.h>

#else
#include <pthread.h>
#endif
#include <time.h>

#include "scc_random.h"
#include "scc_sha256.h"
#include "scc_entropy.h"
#include "scc_error.h"
#include "scc_drbg.h"
#include "scc_cmvp.h"
#include "scc_util.h"

#define MINOUT	16
#define MAXOUT	16*1024*1014

int SC_GetRandom(U8* output, U32 outputbytes)
{	
	int remain = 0;
	int retCode = 0;
	U8 buffer[SC_HashDRBG_SEED_LEN] = {0x00,};
	int pos = 0;
	
	if (outputbytes < MINOUT || outputbytes > MAXOUT) 
		return SCC_RANDOM_ERROR_INVALID_INPUTLEN;

	remain = outputbytes;
	while(remain > 0) {
		if(remain > SC_HashDRBG_SEED_LEN) {
			retCode = SC_CMVP_RAND_GetRandom(buffer, SC_HashDRBG_SEED_LEN);		
			if(retCode < 0) goto end;

			memcpy(output + pos, buffer, SC_HashDRBG_SEED_LEN);
			pos += SC_HashDRBG_SEED_LEN;
			remain -= SC_HashDRBG_SEED_LEN;

		}else {
			retCode = SC_CMVP_RAND_GetRandom(buffer, remain);		
			if(retCode < 0) goto end;

			memcpy(output + pos, buffer, remain);
			pos += remain;
			remain -= remain;	
		}
	}

end:
	SC_Memzero(buffer, 0x00, sizeof(buffer));
	return retCode;
}
