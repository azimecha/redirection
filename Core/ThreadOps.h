#pragma once

#ifndef HEADER_THREADOPS
#define HEADER_THREADOPS

#define _X86_
#include <minwindef.h>

// gets heap allocated buffer (free with CbHeapFree) of thread IDs
// note that threads can come and go
DWORD CbGetProcessThreads(DWORD nProcessID, PDWORD* ppThreadIDs, PULONG pnThreadIDs);

// suspends all other threads in the process
DWORD CbEnterSupercriticalSection(PVOID* ppResumeData);
DWORD CbExitSupercriticalSection(PVOID pResumeData);

#if 0
// very dangerous - forces another thread to run a piece of code
DWORD CbQueueThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam);

// same as CbQueueThreadInterrupt but waits for the interrupt to be processed
DWORD CbPerformThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam);
#endif

// simple spinlock - only CbAcquireSpinLockYielding requires system function call
typedef volatile PVOID CbSpinLock_t;
#define CB_SPINLOCK_INITIAL ((CbSpinLock_t)0)

void CbAcquireSpinLock(CbSpinLock_t* pLockVal);
void CbAcquireSpinLockYielding(CbSpinLock_t* pLockVal);
void CbReleaseSpinLock(CbSpinLock_t* pLockVal);

// opens all-access handle to the current thread
DWORD CbOpenCurrentThread(OUT PHANDLE phCurThread);

#endif
