/* 
========================================
  scc_entropy.c 
    : accumulate entropy
----------------------------------------
  Softcamp(c).
  2015.10.
========================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include "scc_entropy.h"
#include "scc_error.h"
#include "scc_malloc.h"
#include "scc_util.h"

/**
 *
 *
 *
 */
static
int
SC_Entropy_Source_Add(SC_ENTROPY_CTX *entropy,
			   const U8 *data,
			   const U32 dataLength)
{
	U32		pos, i;
	int retCode;

	if ((entropy == NULL) || (data == NULL)){
		retCode = SCC_ENTROPY_ERROR_BAD_INPUT_DATA;
		goto end;
	}

	// STEP 1 :
	//
	if (entropy->dataLength + dataLength >= SC_ENTROPY_MAX_DATA_LENGTH)
		entropy->dataLength = SC_ENTROPY_MAX_DATA_LENGTH;
	else
		entropy->dataLength += dataLength;

	// STEP 2 : 
	//
	pos = entropy->pos;
	for (i=0; i<dataLength; i++, pos++) {
		pos = pos % SC_ENTROPY_MAX_DATA_LENGTH;
		entropy->data[pos] ^= data[i];
	}
	entropy->pos = pos;
	
	retCode = 0;
end:
	return retCode;
}

/**
 *
 *
 *
 */
static
int
SC_Entropy_EncodeRL(U8 *output,
     U32 *outputLength,
     const U8 *input,
     const U32 inputLength)
{
	 U32  i, j, k;
	 int  retCode;
	 U8 buf;

	 if ((output == NULL) || (input == NULL)){
		retCode = SCC_ENTROPY_ERROR_BAD_INPUT_DATA;
		goto end;
	 }

	 for (i=0, k=0; i<inputLength; ) {
		// get length of successive value
		buf = input[i];
		for (j=0; (i+j < inputLength) && (input[i+j] == input[i]); j++);
		// encode value using run-length method
		if (j >= 2)
			output[k++] = j;
			output[k++] = buf;
		i += j;
	 }

	 *outputLength = k;
	 retCode = 0;

end:
	 return retCode;
} 


void
SC_Entropy_GetBasicPieces (U8 *out, U32 *outputLength)
{
	long long	temp[128];
	U32		pos;

	pos = 0;
	temp[pos++] = (long long) GetClipboardOwner();
	temp[pos++] = (long long) GetCurrentProcessId();
	temp[pos++] = (long long) GetCurrentThreadId();
	temp[pos++] = (long long) GetProcessHeap();
	temp[pos++] = (long long) GetTickCount();

	*outputLength = pos*sizeof(long long);
	memcpy(out, temp, *outputLength);

	return;
}

int
SC_Entropy_Accumulate(SC_ENTROPY_CTX *entropy)
{
	U8			temp[128*sizeof(U32)];
	U32			templength = 0;
	time_t		t;
	clock_t		c;
	POINT		point;
	MEMORYSTATUSEX	memory;
	HANDLE		handle;
	FILETIME	cTime, eTime, kTime, uTime;

	LARGE_INTEGER performanceCounter;
	ULONGLONG interruptTime;
	ULONG bufferLength;
	SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION cycleTimeInformation[8];
	GUID guid;

	int retCode;

	if (entropy == NULL){
		retCode = SCC_ENTROPY_ERROR_BAD_INPUT_DATA;
		goto end;
	}

	SC_Memzero(entropy, 0, sizeof(SC_ENTROPY_CTX));

	// STEP 1 : following method is taken from cryptlib 3.0's fastPoll
	//			function.
	//
	Sleep(10);
	time(&t);
	SC_Entropy_Source_Add(entropy, (U8 *) &t, sizeof(time_t));
	SC_Memzero(&t, 0, sizeof(time_t));

	c = clock();
	SC_Entropy_Source_Add(entropy, (U8 *) &c, sizeof(clock_t));
	SC_Memzero(&c, 0, sizeof(clock_t));
	
	// Get various basic pieces of system information: Handle of active
	// window, handle of window with mouse capture, handle of clipboard owner
	// handle of start of clpboard viewer list, pseudohandle of current
	// process, current process ID, pseudohandle of current thread, current
	// thread ID, handle of desktop window, handle  of window with keyboard
	// focus, whether system queue has any events, cursor position for last
	// message, 1 ms time for last message, handle of window with clipboard
	// open, handle of process heap, handle of procs window station, types of
	// events in input queue, and milliseconds since Windows was started
	//

	SC_Entropy_GetBasicPieces(temp, &templength);
	SC_Entropy_Source_Add(entropy, temp, templength);
	SC_Memzero(temp, 0, templength);
	
	// Get multiword system information: Current caret position, current
	// mouse cursor position
	//
	GetCursorPos(&point);
	SC_Entropy_Source_Add(entropy, (U8 *) &point, sizeof(POINT));
	SC_Memzero(&point, 0, sizeof(POINT));

	// Get percent of memory in use, U8s of physical memory, U8s of free
	// physical memory, U8s in paging file, free U8s in paging file, user
	// U8s of address space, and free user U8s
	//
	memory.dwLength = sizeof(MEMORYSTATUSEX);
	retCode = GlobalMemoryStatusEx(&memory);
	if(retCode == 0) {
		retCode = SCC_SELFTEST_ERROR_ENTROPY_COMPARE;
		goto end;
	}
	SC_Entropy_Source_Add(entropy, (U8 *) &memory, sizeof(MEMORYSTATUSEX));
	SC_Memzero(&memory, 0, sizeof(MEMORYSTATUSEX));

	// Get thread and process creation time, exit time, time in kernel mode,
	// and time in user mode in 100ns intervals
	//
	handle = GetCurrentThread();
	GetThreadTimes(handle, &cTime, &eTime, &kTime, &uTime);
	SC_Entropy_Source_Add(entropy, (U8 *) &cTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &eTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &kTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &uTime, sizeof(FILETIME));
	SC_Memzero(&cTime, 0, sizeof(FILETIME));
	SC_Memzero(&eTime, 0, sizeof(FILETIME));
	SC_Memzero(&kTime, 0, sizeof(FILETIME));
	SC_Memzero(&uTime, 0, sizeof(FILETIME));

	handle = GetCurrentProcess();
	GetProcessTimes(handle, &cTime, &eTime, &kTime, &uTime);
	SC_Entropy_Source_Add(entropy, (U8 *) &cTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &eTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &kTime, sizeof(FILETIME));
	SC_Entropy_Source_Add(entropy, (U8 *) &uTime, sizeof(FILETIME));
	SC_Memzero(&cTime, 0, sizeof(FILETIME));
	SC_Memzero(&eTime, 0, sizeof(FILETIME));
	SC_Memzero(&kTime, 0, sizeof(FILETIME));
	SC_Memzero(&uTime, 0, sizeof(FILETIME));

	// Retrieves the current value of the performance counter, 
	// which is a high resolution (<1us) time stamp 
	// that can be used for time-interval measurements.
	//
	QueryPerformanceCounter(&performanceCounter);
	SC_Entropy_Source_Add(entropy, (U8 *) &performanceCounter, sizeof(performanceCounter));
	SC_Memzero(&performanceCounter, 0, sizeof(performanceCounter));
	
	// Gets the current unbiased interrupt-time count, in units of 100 nanoseconds. 
	// The unbiased interrupt-time count does not include time the system spends in sleep or hibernation. 
	//
	QueryUnbiasedInterruptTime(&interruptTime);
	SC_Entropy_Source_Add(entropy, (U8 *) &interruptTime, sizeof(interruptTime));
	SC_Memzero(&interruptTime, 0, sizeof(interruptTime));
		
	// Retrieves the cycle time each processor in the specified processor group spent executing deferred procedure calls 
	// (DPCs) and interrupt service routines (ISRs) since the processor became active.
	//
	bufferLength = 0;
	GetProcessorSystemCycleTime(0, cycleTimeInformation, &bufferLength);
	if(bufferLength > sizeof(cycleTimeInformation)) {
		bufferLength = sizeof(cycleTimeInformation);
	}
	GetProcessorSystemCycleTime(0, cycleTimeInformation, &bufferLength);
	SC_Entropy_Source_Add(entropy, (U8 *) &cycleTimeInformation, bufferLength);
	SC_Memzero(&cycleTimeInformation, 0, bufferLength);
	
	// Creates a GUID, a unique 128-bit integer used for CLSIDs and interface identifiers. 
	//
	CoCreateGuid(&guid);
	SC_Entropy_Source_Add(entropy, (U8 *) &guid, sizeof(guid));
	SC_Memzero(&guid, 0, sizeof(guid));
	
	// Retrieves information about the memory usage of the specified process
	// 	
	{
		DWORD cb;
		DWORD pProcessIds[300];
		DWORD bytesReturned = 0;
		BOOL ret;
				
		int processCount;
		int i=0;
		int j=0;

		HANDLE hProcess;
		PROCESS_MEMORY_COUNTERS process_memory_counters;

		U8 buffer[4096] = {0x00,};
		int pos = 0;
		
		cb = sizeof(pProcessIds);
		ret = EnumProcesses(pProcessIds, cb, &bytesReturned);
		if(ret != 0) { // success
			processCount = bytesReturned / sizeof(DWORD);
			
			for(i=0; i<processCount; i++) {
				hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pProcessIds[i]);
				if(hProcess == NULL) {
					continue;
				}
				if(pos + sizeof(process_memory_counters) > sizeof(buffer)) {
					break;
				}

				GetProcessMemoryInfo(hProcess, &process_memory_counters, sizeof(process_memory_counters));
				memcpy(buffer + pos, &process_memory_counters, sizeof(process_memory_counters));
				pos += sizeof(process_memory_counters);
				
			}
			
			SC_Entropy_Source_Add(entropy, buffer, pos);
			SC_Memzero(buffer, 0, sizeof(buffer));
		}

	}

	// Retrieves the performance values contained in the PERFORMANCE_INFORMATION structure.
	//
	{
		PERFORMACE_INFORMATION performance_info;
		DWORD cb = 0;
		int size;
		
		U8 buffer[56] = {0x00,};

		cb = sizeof(performance_info);
		GetPerformanceInfo(&performance_info, cb);

		if(cb > sizeof(buffer)) {
			size = sizeof(buffer);
		}else {
			size = cb;
		}

		memcpy(buffer, &performance_info, size);
		SC_Entropy_Source_Add(entropy, buffer, size);
		SC_Memzero(buffer, 0, sizeof(buffer));
		
	}

	// Creates a private heap object that can be used by the calling process.
	//
	{
		HANDLE handle;
				
		handle = HeapCreate(0,1,1);
		SC_Entropy_Source_Add(entropy, (unsigned char *)&handle, sizeof(HANDLE));
		HeapDestroy(handle);
	}

	// Retrieves information about the first block of a heap that has been allocated by a process.
	//
	{
		HEAPLIST32 hl;
		HEAPENTRY32 he;
		unsigned char buffer[4096] = {0x00,};
		int pos = 0;

		HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, GetCurrentProcessId());
	
		hl.dwSize = sizeof(HEAPLIST32);

		if(hHeapSnap != INVALID_HANDLE_VALUE) {
		
			if(Heap32ListFirst(hHeapSnap, &hl)) {

				do {
					
					ZeroMemory(&he, sizeof(HEAPENTRY32));
					he.dwSize = sizeof(HEAPENTRY32);

					if(Heap32First(&he, GetCurrentProcessId(), hl.th32HeapID)) {

						do {
							if(pos + sizeof(HEAPENTRY32) > sizeof(buffer)) {
								break;
							}

							memcpy(buffer + pos, &he, sizeof(HEAPENTRY32));
							pos += sizeof(HEAPENTRY32);
							

						} while(Heap32Next(&he));

					}

				} while(Heap32ListNext(hHeapSnap, &hl));

				SC_Entropy_Source_Add(entropy, buffer, pos);
				SC_Memzero(buffer, 0, sizeof(buffer));

			}
		}
	}
	
	// CSP 제공 암호 난수
	//
	{
		HCRYPTPROV hCryptProv = 0;				// handle for a cryptographic provider context
		LPCSTR UserName = "SCCKeyContainer";	// name of the key container to be used
		U8				pbData[128] = {0x00,};

		if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
			retCode = SCC_COMMON_ERROR_INTERNAL;
			goto end;
		}

		if (!CryptGenRandom(hCryptProv, sizeof(pbData), pbData)) {
			retCode = SCC_COMMON_ERROR_INTERNAL;
			goto end;
		}

		SC_Entropy_Source_Add(entropy, pbData, sizeof(pbData));
		SC_Memzero(pbData, 0, sizeof(pbData));

		CryptReleaseContext(hCryptProv,0);
	}
	
	retCode = 0;
end:
	return retCode;

}
