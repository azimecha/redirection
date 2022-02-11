#include "ThreadPool.h"
#include <NTDLL.h>
#include <ThreadOps.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

typedef struct _MW_THREADPOOL_ITEM {
	struct _MW_THREADPOOL_ITEM* pNext;
	HANDLE hThread;
} MW_THREADPOOL_ITEM, *PMW_THREADPOOL_ITEM;

static PMW_THREADPOOL_ITEM s_pItemZero = NULL;
static CbSpinLock_t s_lock = CB_SPINLOCK_INITIAL;

HANDLE MAGICWAYS_EXPORTED MwGetPoolThread(void) {
	PMW_THREADPOOL_ITEM pItem;
	HANDLE hThread = NULL;
	NTSTATUS status;
	CLIENT_ID client;

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
	status = RtlCreateUserThread(CB_CURRENT_PROCESS, NULL, FALSE, 0, NULL, NULL, MwAPCProcessingThreadProc, NULL, &hThread, &client);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[ThreadPool:MwGetPoolThread] RtlCreateUserThread returned status 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return NULL;
	}

	return hThread;
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

MAGICWAYS_EXPORTED DWORD __stdcall MwAPCProcessingThreadProc(PVOID pParams) {
	NTSTATUS status;
	LARGE_INTEGER liTimeout;

	liTimeout.QuadPart = INT64_MAX;

	for (;;) {
		status = NtDelayExecution(TRUE, &liTimeout);
		if (CB_NT_FAILED(status))
			DbgPrint("[ThreadPool:MwAPCProcessingThreadProc] NtDelayExecution returned 0x%08X\r\n", status);
	}
}
