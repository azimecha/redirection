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

static volatile LONG s_bInCritSec = 0;

DWORD CbEnterSupercriticalSection(PVOID* ppData) {
	PDWORD pThreadIDs = NULL;
	ULONG nTotalThreads, nRunningThreads, nThread;
	NTSTATUS status;
	avl_tree_t* pdicSusThreads;
	HANDLE hThread = NULL;
	CLIENT_ID idThread;
	OBJECT_ATTRIBUTES attrib;

	if (InterlockedCompareExchange(&s_bInCritSec, 1, 0) != 0)
		return STATUS_ALREADY_COMMITTED;

	pdicSusThreads = CbHeapAllocate(sizeof(avl_tree_t), FALSE);
	if (pdicSusThreads == NULL) {
		status = STATUS_NO_MEMORY;
		goto L_exit;
	}

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
	if (CB_NT_FAILED(status)) {
		avl_destroy(pdicSusThreads, s_ThreadNodeDtor);
		InterlockedExchange(&s_bInCritSec, 0);
	}

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

	InterlockedExchange(&s_bInCritSec, 0);

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

#if 0
DWORD CbCreateThreadDirect(OUT PHANDLE phThread, OPTIONAL OUT PDWORD pnThreadID, SIZE_T nStackSize, CbDirectCreatedThreadProc_t procStart,
	OPTIONAL ULONG_PTR param, BOOLEAN bSus) 
{
	CONTEXT ctxNewThread;
	CLIENT_ID cidNewThread;
	INITIAL_TEB itebNewThread;
	PVOID pStack = 0, pStackTop;
	NTSTATUS status = 0;
	ULONG nStackSizeUlong;
	OBJECT_ATTRIBUTES oa;

	memset(&ctxNewThread, 0, sizeof(ctxNewThread));
	memset(&cidNewThread, 0, sizeof(cidNewThread));
	memset(&itebNewThread, 0, sizeof(itebNewThread));
	memset(&oa, 0, sizeof(oa));

	nStackSizeUlong = (ULONG)nStackSize;
	status = NtAllocateVirtualMemory(CB_CURRENT_PROCESS, &pStack, 4, &nStackSizeUlong, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (CB_NT_FAILED(status))
		return status;

	pStackTop = (PBYTE)pStack + nStackSize;
	__try {
		RtlInitializeContext(CB_CURRENT_PROCESS, &ctxNewThread, (PVOID)param, procStart, pStackTop);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		goto L_error_freestk;
	}

	itebNewThread.pNewStackBase = pStackTop;
	itebNewThread.pNewStackLimit = pStack;

	oa.Length = sizeof(oa);

	status = NtCreateThread(phThread, THREAD_ALL_ACCESS, &oa, CB_CURRENT_PROCESS, &cidNewThread, &ctxNewThread, &itebNewThread, bSus);
	if (CB_NT_FAILED(status))
		goto L_error_freestk;

	if (pnThreadID)
		*pnThreadID = (DWORD)cidNewThread.UniqueThread;

	return status;

L_error_freestk:
	NtFreeVirtualMemory(CB_CURRENT_PROCESS, &pStack, 0, MEM_DECOMMIT | MEM_RELEASE);
	return status;
}
#endif

BOOLEAN CbIsThreadInLoaderLock(DWORD nThreadID) {
	PPEB_FULL pFullPEB;
	pFullPEB = (PPEB_FULL)CbGetPEB();
	return pFullPEB && pFullPEB->LoaderLock && ((DWORD)pFullPEB->LoaderLock->OwningThread == nThreadID);
}
