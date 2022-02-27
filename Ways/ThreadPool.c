#include "ThreadPool.h"
#include "InterceptIO.h"
#include <NTDLL.h>
#include <ThreadOps.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

typedef struct _MW_THREADPOOL_ITEM {
	struct _MW_THREADPOOL_ITEM* pNext;
	HANDLE hThread;
} MW_THREADPOOL_ITEM, *PMW_THREADPOOL_ITEM;

static void __stdcall s_APCProcessingThreadInitialAPC(PVOID pParam, PIO_STATUS_BLOCK piosbIgnored, ULONG nReservedIgnored);

static PMW_THREADPOOL_ITEM s_pItemZero = NULL;
static CbSpinLock_t s_lock = CB_SPINLOCK_INITIAL;

HANDLE MAGICWAYS_EXPORTED MwGetPoolThread(void) {
	PMW_THREADPOOL_ITEM pItem;
	HANDLE hThread = NULL;
	NTSTATUS status;
	CLIENT_ID client;
	DWORD nThreadID;

	// try to get a thread out
	CbAcquireSpinLockYielding(&s_lock);
	pItem = s_pItemZero;
	if (pItem) s_pItemZero = pItem->pNext;
	CbReleaseSpinLock(&s_lock);

	// got one? return it
	if (pItem != NULL) {
		hThread = pItem->hThread;
		CbHeapFree(pItem);
		return hThread;
	}

	// else, create a new thread
#if 1
	status = RtlCreateUserThread(CB_CURRENT_PROCESS, NULL, TRUE, 0, NULL, NULL, MwAPCProcessingThreadProc, NULL, &hThread, &client);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] RtlCreateUserThread returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return NULL;
	}

	nThreadID = (DWORD)client.UniqueThread;

	status = NtQueueApcThread(hThread, s_APCProcessingThreadInitialAPC, NULL, NULL, 0);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] NtQueueApcThread returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return NULL;
	}
#else
	status = CbCreateThreadDirect(&hThread, &nThreadID, 64 * 1024, MwAPCProcessingThreadProc, 0, TRUE);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] CbCreateThreadDirect returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return NULL;
	}
#endif

	status = DisableIOInterception(nThreadID);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] DisableIOInterception returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		goto L_cancel;
	}

	status = NtResumeThread(hThread, NULL);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] NtResumeThread returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		goto L_cancel;
	}

	return hThread;

L_cancel:
	status = NtTerminateThread(hThread, STATUS_CANCELLED);
	if (CB_NT_FAILED(status))
		DbgPrint("[ThreadPool:MwGetPoolThread] NtTerminateThread returned status 0x%08X\r\n", status);
	NtClose(hThread);
	return NULL;
}

void MAGICWAYS_EXPORTED MwReturnPoolThread(HANDLE hThread) {
	PMW_THREADPOOL_ITEM pItem, pCurItem;
	NTSTATUS status;

	// create item object
	pItem = CbHeapAllocate(sizeof(MW_THREADPOOL_ITEM), TRUE);
	if (pItem == NULL) {
		DbgPrint("[ThreadPool:MwReturnPoolThread] CbHeapAllocate failed, killing thread\r\n");
		status = NtTerminateThread(hThread, STATUS_NO_MEMORY);
		if (CB_NT_FAILED(status))
			DbgPrint("[ThreadPool:MwReturnPoolThread] NtTerminateThread returned status 0x%08X! Thread leaked!\r\n", status);
		NtClose(hThread);
		return;
	}

	pItem->hThread = hThread;
	
	// insert into list - head is fastest
	CbAcquireSpinLockYielding(&s_lock);
	if (s_pItemZero)
		pItem->pNext = s_pItemZero;
	s_pItemZero = pItem;
	CbReleaseSpinLock(&s_lock);
}

DWORD MAGICWAYS_EXPORTED MwAPCProcessingThreadProc(PVOID pParams) {
	NTSTATUS status;
	LARGE_INTEGER liTimeout;

	liTimeout.QuadPart = INT64_MAX;

	for (;;) {
		status = NtDelayExecution(TRUE, &liTimeout);
		if (CB_NT_FAILED(status))
			DbgPrint("[ThreadPool:MwAPCProcessingThreadProc] NtDelayExecution returned 0x%08X\r\n", status);
	}
}

static void __stdcall s_APCProcessingThreadInitialAPC(PVOID pParam, PIO_STATUS_BLOCK piosbIgnored, ULONG nReservedIgnored) {
	NTSTATUS status;

	__try {
		status = MwAPCProcessingThreadProc(pParam);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		DbgPrint("[ThreadPool:s_APCProcessingThreadInitialAPC] Exception 0x%08X in APC processing thread\r\n", status);
	}

	NtTerminateThread(CB_CURRENT_THREAD, status);
}
