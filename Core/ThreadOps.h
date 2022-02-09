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

// very dangerous - forces another thread to run a piece of code
DWORD CbQueueThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam);

// same as CbQueueThreadInterrupt but waits for the interrupt to be processed
DWORD CbPerformThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam);

#endif
