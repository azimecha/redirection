#include "ThreadOps.h"
#include "avl.h"
#include <NTDLL.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif

DWORD CbGetProcessThreads(DWORD nProcessID, PDWORD* ppThreadIDs, PULONG pnThreadIDs) {
	PVOID pBuffer = NULL;
	ULONG nBufSize = 512, nValueSize, nThread;
	NTSTATUS status = STATUS_NOT_FOUND;
	PSYSTEM_PROCESSES pproCur;

	// read process and thread information
	for (;;) {
		// allocate buffer
		nBufSize *= 2;
		pBuffer = CbHeapAllocate(nBufSize, FALSE);
		if (pBuffer == NULL) {
			status = STATUS_NO_MEMORY;
			goto L_exit;
		}

		// try call
		status = NtQuerySystemInformation(SystemProcessAndThreadInformation, pBuffer, nBufSize, &nValueSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
			; // continue looping
		else if (CB_NT_FAILED(status))
			goto L_exit; // truly failed
		else
			break; // got it

		// free buffer
		CbHeapFree(pBuffer);
		pBuffer = NULL;
	}

	// find process
	pproCur = pBuffer;
	for (;;) {
		if (pproCur->ProcessId == nProcessID)
			break; // found
		else if (pproCur->NextEntryDelta == 0) {
			status = STATUS_NOT_FOUND;
			goto L_exit;
		} else
			pproCur = (PSYSTEM_PROCESSES)((BYTE*)pproCur + pproCur->NextEntryDelta);
	}

	// get threads
	*ppThreadIDs = CbHeapAllocate(pproCur->ThreadCount * sizeof(DWORD), FALSE);
	if (*ppThreadIDs == NULL) {
		status = STATUS_NO_MEMORY;
		goto L_exit;
	}

	for (nThread = 0; nThread < pproCur->ThreadCount; nThread++)
		(*ppThreadIDs)[nThread] = pproCur->Threads[nThread].ClientId.UniqueThread;

	*pnThreadIDs = pproCur->ThreadCount;
	status = 0;

L_exit:
	if (pBuffer != NULL)
		CbHeapFree(pBuffer);
	return status;
}

static void s_NullKeyDtor(void* p) {}
static void s_ThreadNodeDtor(void* p1, void* p2) {
	NtResumeThread((HANDLE)p2, NULL);
	NtClose((HANDLE)p2);
}

DWORD CbEnterSupercriticalSection(PVOID* ppData) {
	PDWORD pThreadIDs = NULL;
	ULONG nTotalThreads, nRunningThreads, nThread;
	NTSTATUS status;
	avl_tree_t* pdicSusThreads;
	HANDLE hThread = NULL;
	CLIENT_ID idThread;
	OBJECT_ATTRIBUTES attrib;

	pdicSusThreads = CbHeapAllocate(sizeof(avl_tree_t), FALSE);
	if (pdicSusThreads == NULL)
		return STATUS_NO_MEMORY;

	avl_initialize(pdicSusThreads, avl_ptrcmp, s_NullKeyDtor);
	idThread.UniqueProcess = 0;
	memset(&attrib, 0, sizeof(attrib));

	// repeatedly loop through all threads until there are no others running
	do {
		status = CbGetProcessThreads(CbGetTEB()->ClientId.UniqueProcess, &pThreadIDs, &nTotalThreads);
		if (CB_NT_FAILED(status))
			goto L_exit;

		nRunningThreads = 0;
		for (nThread = 0; nThread < nTotalThreads; nThread++) {
			// check if in list
			if (avl_search(pdicSusThreads, (void*)pThreadIDs[nThread]) != NULL)
				continue; // already in list

			// check if it's the current thread
			nRunningThreads++;
			if (pThreadIDs[nThread] == CbGetTEB()->ClientId.UniqueThread)
				continue; // is current thread

			// open it
			idThread.UniqueThread = nThread;
			status = NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, &attrib, &idThread);
			if (CB_NT_FAILED(status))
				goto L_exit;

			// sus it
			status = NtSuspendThread(hThread, NULL);
			if (CB_NT_FAILED(status))
				goto L_exit;

			// put it in the list
			if (avl_insert(pdicSusThreads, (void*)pThreadIDs[nThread], (void*)hThread) == NULL) {
				NtResumeThread(hThread, NULL);
				status = STATUS_NO_MEMORY;
				goto L_exit;
			}

			hThread = NULL;
		}
	} while (nRunningThreads > 1);

	*ppData = pdicSusThreads;

L_exit:
	if (CB_NT_FAILED(status)) avl_destroy(pdicSusThreads, s_ThreadNodeDtor);
	if (pThreadIDs) CbHeapFree(pThreadIDs);
	if (hThread) NtClose(hThread);
	return status;
}

DWORD CbExitSupercriticalSection(PVOID pData) {
	avl_tree_t* pdicSusThreads;

	pdicSusThreads = pData;
	if (pdicSusThreads == NULL)
		return STATUS_INVALID_PARAMETER_1;

	avl_destroy(pdicSusThreads, s_ThreadNodeDtor);
	CbHeapFree(pdicSusThreads);

	return 0;
}

#if 0
DWORD CbQueueThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam) {

}

DWORD CbPerformThreadInterrupt(HANDLE hThread, PAPCFUNC procRoutine, ULONG_PTR nParam) {
	
}
#endif

void CbAcquireSpinLock(CbSpinLock_t* pLockVal) {
	PVOID pThisThreadVal;
	pThisThreadVal = (PVOID)CbGetTEB()->ClientId.UniqueThread;
	while (InterlockedCompareExchangePointer(pLockVal, pThisThreadVal, 0) != 0);
}

void CbAcquireSpinLockYielding(CbSpinLock_t* pLockVal) {
	PVOID pThisThreadVal;
	pThisThreadVal = (PVOID)CbGetTEB()->ClientId.UniqueThread;
	while (InterlockedCompareExchangePointer(pLockVal, pThisThreadVal, 0) != 0)
		NtYieldExecution();
}

void CbReleaseSpinLock(CbSpinLock_t* pLockVal) {
	PVOID pThisThreadVal;
	pThisThreadVal = (PVOID)CbGetTEB()->ClientId.UniqueThread;
	InterlockedCompareExchangePointer(pLockVal, 0, pThisThreadVal);
}

DWORD CbOpenCurrentThread(OUT PHANDLE phCurThread) {
	OBJECT_ATTRIBUTES attrib;

	RtlSecureZeroMemory(&attrib, sizeof(attrib));
	attrib.Length = sizeof(attrib);

	return NtOpenThread(phCurThread, THREAD_ALL_ACCESS, &attrib, &CbGetTEB()->ClientId);
}
