/* 
========================================
  scc_cmvp.h 
    : crypto status etc. 
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#ifndef __SCC_CMVP_H__
#define __SCC_CMVP_H__

#include "scc_protocol.h"

extern int g_cmvp_status_id;

#ifdef __cplusplus
extern "C" {
#endif

int 
SC_CMVP_MoveStatus(const int stateID);
int 
SC_CMVP_Status_init(void);
int 
SC_CMVP_Status_Final(void);
int 
SC_CMVP_GetStatus(void);

int 
SC_CMVP_Status_CheckState(void);
int 
SC_CMVP_Status_CheckCipherID(const int cipherID);
int 
SC_CMVP_Status_CheckHashID(const int hashID);
int 
SC_CMVP_Status_CheckMacID(const int macID);
int 
SC_CMVP_Status_CheckPkeyID(const int pkeyID);
int 
SC_CMVP_Status_CheckPencID(const int pencID);
int 
SC_CMVP_Status_CheckSignID(const int signID);
int 
SC_CMVP_Cipher_CheckParams(const int modeID, const int paddingID);

int
SC_CMVP_RAND_Init(void);
void 
SC_CMVP_RAND_Final(void);
int
SC_CMVP_RAND_GetRandom(U8 *output, const U32 outputLength);

// for test
int
SC_CMVP_RAND_GetRandomTestVector(U8 *output, const U32 outputLength, int flag);

#ifdef __cplusplus
}
#endif

#endif
