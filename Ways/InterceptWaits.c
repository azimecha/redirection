#include "ThreadLocal.h"
#include "ThreadPool.h"
#include <HookFunction.h>
#include <ThreadOps.h>
#include <NTDLL.h>
#include <avl.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <limits.h>
#include <stdint.h>

typedef struct _MW_WAITS_TARGET {
	LPCSTR pcszName;
	PVOID* ppOrigStorage;
	PVOID pNewFunc;
} MW_WAITS_TARGET, *PMW_WAITS_TARGET;

typedef enum _MW_WAITS_FILE_MODE {
	MwWaitsFileMode_Overlapped,
	MwWaitsFileMode_SyncAlert,
	MwWaitsFileMode_Synchronous
} MW_WAITS_FILE_MODE, *PMW_WAITS_FILE_MODE;

struct _MW_WAITS_IO_OP;
typedef NTSTATUS(* MW_WAITS_IO_PROC)(struct _MW_WAITS_IO_OP* pop);

typedef struct _MW_WAITS_IO_METADATA {
	HANDLE hTaskCompleteEvent, hTaskCancelledEvent, hOriginalThread, hNewThread;
	NTSTATUS statusTaskResult;
} MW_WAITS_IO_METADATA, *PMW_WAITS_IO_METADATA;

typedef struct _MW_WAITS_IO_OP {
	MW_WAITS_IO_PROC procDoActualIO;
	MW_WAITS_IO_METADATA meta; // filled by s_PerformIO

	HANDLE hFile;
	HANDLE hEvent;
	PVOID pAPCRoutine;
	PVOID pAPCContext;
	PIO_STATUS_BLOCK piosb;

	union {
		struct {
			PVOID pBuffer;
			ULONG nBytesToRead;
			BOOLEAN bHasOffset, bHasKey;
			LARGE_INTEGER liByteOffset;
			ULONG nKey;
		} ReadWrite;
		struct {
			ULONG nIOCTL;
			PVOID pInBuf;
			ULONG nInBufLen;
			PVOID pOutBuf;
			ULONG nOutBufLen;
		} IOControl;
	};
} MW_WAITS_IO_OP, *PMW_WAITS_IO_OP;

#define MW_WAITS_TARGET_NAMED(n) { "Nt" #n, &s_procNt ##n, s_Ic ##n }

static NTSTATUS s_CheckMode(HANDLE hFile, OUT PMW_WAITS_FILE_MODE pnMode);

static NTSTATUS __stdcall s_IcReadFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToRead, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey);

static NTSTATUS __stdcall s_IcReadFileScatter(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PFILE_SEGMENT_ELEMENT pSegments, ULONG nBytesToRead, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey);

static NTSTATUS __stdcall s_IcWriteFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToWrite, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey);

static NTSTATUS __stdcall s_IcWriteFileGather(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PFILE_SEGMENT_ELEMENT pSegments, ULONG nBytesToWrite, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey);

static NTSTATUS __stdcall s_IcDeviceIoControlFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nIOCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen);

static NTSTATUS __stdcall s_IcFsControlFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nFSCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen);

static NTSTATUS s_ImplReadFile(PMW_WAITS_IO_OP pop);
static NTSTATUS s_ImplReadFileScatter(PMW_WAITS_IO_OP pop);
static NTSTATUS s_ImplWriteFile(PMW_WAITS_IO_OP pop);
static NTSTATUS s_ImplWriteFileGather(PMW_WAITS_IO_OP pop);
static NTSTATUS s_ImplDeviceIoControlFile(PMW_WAITS_IO_OP pop);
static NTSTATUS s_ImplFsControlFile(PMW_WAITS_IO_OP pop);

static void __stdcall s_NonalertableIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_AlertableIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_AlertableIOCancelProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_OverlappedIOObserverProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_OverlappedIOWorkerProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_SetThreadAsNoInterceptProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);

static NTSTATUS s_PerformIO(PMW_WAITS_IO_OP pop);

static NTSTATUS s_InitSyncIOMetadata(PMW_WAITS_IO_METADATA pmeta);
static NTSTATUS s_UninitSyncIOMetadata(PMW_WAITS_IO_METADATA pmeta);
static BOOL __stdcall s_LocalEventCtor(PHANDLE phEvent);
static BOOL __stdcall s_LocalSyncIOThreadCtor(PHANDLE phThread);
static BOOL __stdcall s_LocalThreadHandleCtor(PHANDLE phThread);
static void __stdcall s_LocalHandleDtor(PHANDLE phObject);
static void __stdcall s_LocalSyncIOThreadDtor(PHANDLE phThread);

static NTSTATUS s_InitAsyncIOMetadata(PMW_WAITS_IO_METADATA pmeta);
static void s_UninitAsyncIOMetadata(PMW_WAITS_IO_METADATA pmeta);

static void s_InitReadWriteOp(PMW_WAITS_IO_OP pop, HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToXfer, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey);
static void s_InitIOControlOp(PMW_WAITS_IO_OP pop, HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nIOCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen);

static NTSTATUS s_UnsetThreadAsNoIntercept(DWORD nThreadID);
static NTSTATUS s_CheckNoInterceptStatus(PBOOL pbNoIntercept);

static void s_NullKeyDtor(void* key);
static void s_HandleClosingValueDtor(void* key, HANDLE hValue);

static const GUID s_idSyncIOCompleteEvent = { 0x19345D63, 0x00ED, 0x40B5, {0x94, 0x52, 0x83, 0x25, 0x29, 0x00, 0x38, 0xDF} };
static const GUID s_idSyncIOCancelledEvent = { 0xE81C2100, 0x22CA, 0x45FE, {0x89, 0xC8, 0x84, 0xE4, 0x2E, 0xDA, 0xC6, 0xAF} };
static const GUID s_idOrigThreadHandle = { 0xF2B66FCA, 0x76BB, 0x49E6, {0x8C, 0x13, 0x4E, 0x3B, 0xB6, 0x44, 0x74, 0x4C} };
static const GUID s_idSyncIOThreadHandle = { 0x1B31D371, 0xF2F0, 0x4F3D, {0xB8, 0xF9, 0xA4, 0xB8, 0xAC, 0xE6, 0x06, 0x73} };

static NtReadFile_t s_procNtReadFile = NULL;
static NtReadFileScatter_t s_procNtReadFileScatter = NULL;
static NtWriteFile_t s_procNtWriteFile = NULL;
static NtWriteFileGather_t s_procNtWriteFileGather = NULL;
static NtDeviceIoControlFile_t s_procNtDeviceIoControlFile = NULL;
static NtFsControlFile_t s_procNtFsControlFile = NULL;

static avl_tree_t s_treeNoIntercept = { 0 }; // TODO: Removing dead threads
static CbSpinLock_t s_lockNoInterceptList = CB_SPINLOCK_INITIAL;

static MW_WAITS_TARGET s_arrToIntercept[] = {
	MW_WAITS_TARGET_NAMED(ReadFile),
	MW_WAITS_TARGET_NAMED(ReadFileScatter),
	MW_WAITS_TARGET_NAMED(WriteFile),
	MW_WAITS_TARGET_NAMED(WriteFileGather),
	MW_WAITS_TARGET_NAMED(DeviceIoControlFile),
	MW_WAITS_TARGET_NAMED(FsControlFile)
};

BOOL ApplyWaitHooks(void) {
	SIZE_T nTarget;
	PMW_WAITS_TARGET pTargetInfo;
	PVOID pLocation;

	avl_initialize(&s_treeNoIntercept, avl_ptrcmp, s_NullKeyDtor);

	for (nTarget = 0; nTarget < RTL_NUMBER_OF_V2(s_arrToIntercept); nTarget++) {
		pTargetInfo = &s_arrToIntercept[nTarget];

		pLocation = CbGetNTDLLFunction(pTargetInfo->pcszName);
		if (pLocation == NULL) {
			DbgPrint("[ApplyWaitHooks] %s not found!\r\n", pTargetInfo->pcszName);
			return FALSE;
		}

		*pTargetInfo->ppOrigStorage = PaHookSimpleFunction(pLocation, 16, pTargetInfo->pNewFunc);
		if (*pTargetInfo->ppOrigStorage == NULL) {
			DbgPrint("[ApplyWaitHooks] PaHookSimpleFunction failed on %s with error 0x%08X!\r\n", pTargetInfo->pcszName, CbLastWinAPIError);
			return FALSE;
		}

		DbgPrint("[ApplyWaitHooks] Hooked %s at 0x%08X with function at 0x%08X - original stored at 0x%08X\r\n", pTargetInfo->pcszName,
			pLocation, pTargetInfo->pNewFunc, *pTargetInfo->ppOrigStorage);
	}

	return TRUE;
}

static NTSTATUS __stdcall s_IcReadFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToRead, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey)
{
	MW_WAITS_IO_OP op;
	s_InitReadWriteOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, pBuffer, nBytesToRead, pliByteOffset, pnKey);
	op.procDoActualIO = s_ImplReadFile;
	return s_PerformIO(&op);
}

static NTSTATUS __stdcall s_IcReadFileScatter(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PFILE_SEGMENT_ELEMENT pSegments, ULONG nBytesToRead, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey)
{
	MW_WAITS_IO_OP op;
	s_InitReadWriteOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, pSegments, nBytesToRead, pliByteOffset, pnKey);
	op.procDoActualIO = s_ImplReadFileScatter;
	return s_PerformIO(&op);
}

static NTSTATUS __stdcall s_IcWriteFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToWrite, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey)
{
	MW_WAITS_IO_OP op;
	s_InitReadWriteOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, pBuffer, nBytesToWrite, pliByteOffset, pnKey);
	op.procDoActualIO = s_ImplWriteFile;
	return s_PerformIO(&op);
}

static NTSTATUS __stdcall s_IcWriteFileGather(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PFILE_SEGMENT_ELEMENT pSegments, ULONG nBytesToWrite, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey)
{
	MW_WAITS_IO_OP op;
	s_InitReadWriteOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, pSegments, nBytesToWrite, pliByteOffset, pnKey);
	op.procDoActualIO = s_ImplWriteFileGather;
	return s_PerformIO(&op);
}

static NTSTATUS __stdcall s_IcDeviceIoControlFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nIOCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen)
{
	MW_WAITS_IO_OP op;
	s_InitIOControlOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, nIOCTL, pInBuf, nInBufLen, pOutBuf, nOutBufLen);
	op.procDoActualIO = s_ImplDeviceIoControlFile;
	return s_PerformIO(&op);
}

static NTSTATUS __stdcall s_IcFsControlFile(HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nFSCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen)
{
	MW_WAITS_IO_OP op;
	s_InitIOControlOp(&op, hFile, hEvent, pAPCRoutine, pAPCContext, piosb, nFSCTL, pInBuf, nInBufLen, pOutBuf, nOutBufLen);
	op.procDoActualIO = s_ImplFsControlFile;
	return s_PerformIO(&op);
}

static NTSTATUS s_CheckMode(HANDLE hFile, OUT PMW_WAITS_FILE_MODE pnMode) {
	FILE_MODE_INFORMATION infMode;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	RtlSecureZeroMemory(&iosb, sizeof(iosb));
	status = NtQueryInformationFile(hFile, &iosb, &infMode, sizeof(infMode), FileModeInformation);

	if (!CB_NT_FAILED(status)) {
		if (infMode.Mode & FILE_SYNCHRONOUS_IO_NONALERT)
			*pnMode = MwWaitsFileMode_Synchronous;
		else if (infMode.Mode & FILE_SYNCHRONOUS_IO_ALERT)
			*pnMode = MwWaitsFileMode_SyncAlert;
		else
			*pnMode = MwWaitsFileMode_Overlapped;
	}

	return status;
}

static NTSTATUS s_ImplReadFile(PMW_WAITS_IO_OP pop) {
	return s_procNtReadFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ReadWrite.pBuffer, pop->ReadWrite.nBytesToRead,
		pop->ReadWrite.bHasOffset ? &pop->ReadWrite.liByteOffset : NULL, pop->ReadWrite.bHasKey ? &pop->ReadWrite.nKey : NULL);
}

static NTSTATUS s_ImplReadFileScatter(PMW_WAITS_IO_OP pop) {
	return s_procNtReadFileScatter(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ReadWrite.pBuffer,
		pop->ReadWrite.nBytesToRead, pop->ReadWrite.bHasOffset ? &pop->ReadWrite.liByteOffset : NULL, pop->ReadWrite.bHasKey ? &pop->ReadWrite.nKey : NULL);
}

static NTSTATUS s_ImplWriteFile(PMW_WAITS_IO_OP pop) {
	return s_procNtWriteFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ReadWrite.pBuffer, pop->ReadWrite.nBytesToRead,
		pop->ReadWrite.bHasOffset ? &pop->ReadWrite.liByteOffset : NULL, pop->ReadWrite.bHasKey ? &pop->ReadWrite.nKey : NULL);
}

static NTSTATUS s_ImplWriteFileGather(PMW_WAITS_IO_OP pop) {
	return s_procNtReadFileScatter(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ReadWrite.pBuffer,
		pop->ReadWrite.nBytesToRead, pop->ReadWrite.bHasOffset ? &pop->ReadWrite.liByteOffset : NULL, pop->ReadWrite.bHasKey ? &pop->ReadWrite.nKey : NULL);
}

static NTSTATUS s_ImplDeviceIoControlFile(PMW_WAITS_IO_OP pop) {
	return s_procNtDeviceIoControlFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->IOControl.nIOCTL, pop->IOControl.pInBuf,
		pop->IOControl.nInBufLen, pop->IOControl.pOutBuf, pop->IOControl.nOutBufLen);
}

static NTSTATUS s_ImplFsControlFile(PMW_WAITS_IO_OP pop) {
	return s_procNtFsControlFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->IOControl.nIOCTL, pop->IOControl.pInBuf,
		pop->IOControl.nInBufLen, pop->IOControl.pOutBuf, pop->IOControl.nOutBufLen);
}

static void __stdcall s_NonalertableIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;

	// runs on synchronous I/O thread
	// responsible for actually performing the I/O and setting hTaskCompleteEvent
	// this thread will be terminated on I/O cancellation

	__try {
		pop->meta.statusTaskResult = pop->procDoActualIO(pop);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[InterceptWaits:s_NonalertableIOTaskProc] Exception 0x%08X in synchronous I/O request\r\n", GetExceptionCode());
		pop->meta.statusTaskResult = GetExceptionCode();
	}

	status = NtSetEvent(pop->meta.hTaskCompleteEvent, NULL);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_NonalertableIOTaskProc] Error 0x%08X setting task completion event\r\n", status);
}

static void __stdcall s_AlertableIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;
	HANDLE arrObjects[2];

	// runs on synchronous I/O thread
	// responsible for triggering an APC on the main thread when hTaskCancelledEvent is set
	// main thread will set hTaskCompleteEvent when I/O is complete

	arrObjects[0] = pop->meta.hTaskCompleteEvent;
	arrObjects[1] = pop->meta.hTaskCancelledEvent;

	status = NtWaitForMultipleObjects(RTL_NUMBER_OF(arrObjects), arrObjects, WaitAnyObject, FALSE, NULL);
	switch (status) {
	case WAIT_OBJECT_0 + 0: // complete
		return;

	case WAIT_OBJECT_0 + 1: // cancellation requested
		status = NtQueueApcThread(pop->meta.hOriginalThread, s_AlertableIOCancelProc, pop, piosbIgnored, 0);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_AlertableIOTaskProc] Error 0x%08X queuing cancellation APC\r\n", status);
		return;

	default:
		DbgPrint("[InterceptWaits:s_AlertableIOTaskProc] NtWaitForMultipleObjects returned 0x%08X\r\n", status);
	}
}

// "five threads watch one thread read a file" (not really)
static void __stdcall s_OverlappedIOObserverProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;
	HANDLE arrObjects[2];
	PVOID pAPCRoutine, pAPCParam;
	HANDLE hUserCompleteEvent;
	LARGE_INTEGER liTimeout;
	BOOL bCancelled = FALSE;
	HANDLE hWorkerThread = NULL;

	// runs on a pool thread
	// responsible for starting a worker and waiting for completion or cancellation
	// terminates worker if cancelled

	pAPCRoutine = pop->pAPCRoutine;
	pAPCParam = pop->pAPCContext;
	pop->pAPCRoutine = NULL;
	pop->pAPCContext = NULL;

	hUserCompleteEvent = pop->hEvent;
	pop->hEvent = pop->meta.hTaskCompleteEvent;

	// start worker
	hWorkerThread = MwGetPoolThread();
	if (hWorkerThread == NULL) {
		DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] MwGetPoolThread failed with error 0x%08X\r\n", CbLastWinAPIError);
		pop->meta.statusTaskResult = CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
		goto L_complete;
	}

	status = NtQueueApcThread(hWorkerThread, s_OverlappedIOWorkerProc, pop, piosbIgnored, nReserved);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] NtQueueApcThread returned status 0x%08X\r\n", status);
		pop->meta.statusTaskResult = status;
		goto L_complete;
	}

	// wait for completion
	arrObjects[0] = pop->meta.hTaskCompleteEvent;
	arrObjects[1] = pop->meta.hTaskCancelledEvent;
	liTimeout.QuadPart = INT64_MAX;

	status = NtWaitForMultipleObjects(RTL_NUMBER_OF(arrObjects), arrObjects, WaitAnyObject, FALSE, &liTimeout);
	switch (status) {
	case WAIT_OBJECT_0 + 0: // complete
		if ((pop->meta.statusTaskResult == STATUS_PENDING) && pop->piosb)
			pop->meta.statusTaskResult = pop->piosb->Status;
		goto L_complete;

	default: // failed
		DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] NtWaitForMultipleObjects returned status 0x%08X! Unable to wait for completion!\r\n",
			status);
		// fall through - try to cancel

	case WAIT_OBJECT_0 + 1: // cancelled
		status = NtTerminateThread(hWorkerThread, STATUS_CANCELLED);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] NtTerminateThread returned status 0x%08X! I/O not cancelled!\r\n", status);
		NtClose(hWorkerThread);
		hWorkerThread = NULL; // doesn't get returned to the pool
		pop->meta.statusTaskResult = STATUS_CANCELLED;
		goto L_complete;
	}

L_complete:
	if (hWorkerThread)
		MwReturnPoolThread(hWorkerThread);

	if (pop->piosb)
		pop->piosb->Status = pop->meta.statusTaskResult;

	if (pAPCRoutine) {
		status = NtQueueApcThread(pop->meta.hOriginalThread, pAPCRoutine, pAPCParam, pop->piosb, 0);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] NtQueueApcThread returned status 0x%08X! User APC will not run!\r\n", status);
	}

	if (hUserCompleteEvent) {
		status = NtSetEvent(hUserCompleteEvent, NULL);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_OverlappedIOObserverProc] NtSetEvent returned status 0x%08X! User event not signaled!\r\n", status);
	}

	s_UninitAsyncIOMetadata(&pop->meta);
	CbHeapFree(pop);
}

static void __stdcall s_OverlappedIOWorkerProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	// runs on a pool thread
	// responsible for performing the actual I/O operation
	// will be terminated by observer on cancellation

	__try {
		status = pop->procDoActualIO(pop);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[InterceptWaits:s_OverlappedIOWorkerProc] Exception 0x%08X in overlapped I/O request\r\n", GetExceptionCode());
		pop->meta.statusTaskResult = GetExceptionCode();
		goto L_setevent;
	}

	pop->meta.statusTaskResult = status;
	if (status != STATUS_PENDING)
		goto L_setevent;

	status = NtWaitForSingleObject(pop->meta.hTaskCompleteEvent, FALSE, NULL);
	if (status != WAIT_OBJECT_0) {
		DbgPrint("[InterceptWaits:s_OverlappedIOWorkerProc] Error 0x%08X waiting for completion event! I/O not completed!\r\n", status);
		pop->meta.statusTaskResult = status;
		goto L_setevent;
	}

	return;

L_setevent:
	status = NtSetEvent(pop->meta.hTaskCompleteEvent, NULL);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_OverlappedIOWorkerProc] Error 0x%08X setting completion event! I/O will never complete!\r\n", status);
}

static void __stdcall s_AlertableIOCancelProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	// runs on main thread as an APC
	// used to cancel alertable synchronous I/O, i.e. not overlapped but APCs allowed

	RtlSecureZeroMemory(&iosb, sizeof(iosb));
	status = NtCancelIoFile(pop->hFile, &iosb);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_AlertableIOCancelProc] NtCancelIoFile returned 0x%08X\r\n", status);

}

static NTSTATUS s_PerformIO(PMW_WAITS_IO_OP pop) {
	NTSTATUS status;
	MW_WAITS_FILE_MODE mode;
	PIO_APC_ROUTINE procAPC;
	PMW_WAITS_IO_OP popOriginal = NULL;
	BOOL bSucc = FALSE, bNoIntercept;

	// runs on main thread

	status = s_CheckNoInterceptStatus(&bNoIntercept);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X checking no-intercept status\r\n", status);
		goto L_exit;
	}

	if (bNoIntercept) {
		__try {
			status = pop->procDoActualIO(pop);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}

		return status;
	}

	if (pop->hEvent != NULL) {
		status = NtResetEvent(pop->hEvent, NULL);
		if (CB_NT_FAILED(status)) {
			DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X resetting event 0x%08X\r\n", status, pop->hEvent);
			goto L_exit;
		}
	}

	status = s_CheckMode(pop->hFile, &mode);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X querying mode\r\n", status);
		goto L_exit;
	}

	switch (mode) {
	case MwWaitsFileMode_Overlapped:
		procAPC = s_OverlappedIOObserverProc;
		popOriginal = pop;
		pop = CbHeapAllocate(sizeof(MW_WAITS_IO_OP), FALSE);
		if (pop == NULL) {
			pop = popOriginal;
			popOriginal = NULL;
			status = STATUS_NO_MEMORY;
			goto L_exit;
		}
		memcpy(pop, popOriginal, sizeof(*pop));
		break;

	case MwWaitsFileMode_SyncAlert:
		procAPC = s_AlertableIOTaskProc;
		break;

	case MwWaitsFileMode_Synchronous:
		procAPC = s_NonalertableIOTaskProc;
		break;

	default:
		DbgPrint("[InterceptWaits:s_PerformIO] Unknown mode %u\r\n", mode);
		status = STATUS_INVALID_PARAMETER;
		goto L_exit;
	}

	status = (mode == MwWaitsFileMode_Overlapped) ? s_InitAsyncIOMetadata(&pop->meta) : s_InitSyncIOMetadata(&pop->meta);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X initializing I/O metadata\r\n", status);
		goto L_exit;
	}

	status = NtQueueApcThread(pop->meta.hNewThread, procAPC, pop, pop->piosb, 0);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] NtQueueApcThread returned status 0x%08X\r\n", status);
		goto L_exit;
	}

	switch (mode) {
	case MwWaitsFileMode_Overlapped:
		status = STATUS_PENDING;
		break;

	case MwWaitsFileMode_SyncAlert:
		__try {
			pop->meta.statusTaskResult = pop->procDoActualIO(pop);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[InterceptWaits:s_PerformIO] procDoActualIO encountered exception 0x%08X\r\n", GetExceptionCode());
			pop->meta.statusTaskResult = GetExceptionCode();
		}
		status = NtSetEvent(pop->meta.hTaskCompleteEvent, NULL);
		if (CB_NT_FAILED(status)) {
			DbgPrint("[InterceptWaits:s_PerformIO] NtSetEvent returned status 0x%08X\r\n", status);
			MwDiscardTLS(&s_idSyncIOThreadHandle);
			pop->meta.hNewThread = NULL;
		}
		status = pop->meta.statusTaskResult;
		break;

	case MwWaitsFileMode_Synchronous:
		status = NtWaitForSingleObject(pop->meta.hTaskCompleteEvent, FALSE, NULL);
		if (CB_NT_FAILED(status)) {
			DbgPrint("[InterceptWaits:s_PerformIO] NtWaitForSingleObject returned status 0x%08X\r\n", status);
			MwDiscardTLS(&s_idSyncIOThreadHandle);
			pop->meta.hNewThread = NULL;
		}
		status = pop->meta.statusTaskResult;
		break;
	}

	bSucc = TRUE;

L_exit:
	if (mode == MwWaitsFileMode_Overlapped) {
		if (!bSucc) {
			s_UninitAsyncIOMetadata(&pop->meta);
			if (popOriginal != NULL)
				CbHeapFree(pop);
		}
	} else {
		s_UninitSyncIOMetadata(&pop->meta);
	}
	return status;
}

static NTSTATUS s_InitSyncIOMetadata(PMW_WAITS_IO_METADATA pmeta) {
	PHANDLE phObject;

	phObject = MwGetTLS(&s_idOrigThreadHandle, sizeof(HANDLE), s_LocalThreadHandleCtor, s_LocalHandleDtor, "InterceptWaits orig thread");
	if (phObject == NULL) {
		DbgPrint("[InterceptWaits:s_AlertableIOCancelProc] MwGetTLS for hOriginalThread failed with error 0x%08X\r\n", CbLastWinAPIError);
		return CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
	}
	pmeta->hOriginalThread = *phObject;

	phObject = MwGetTLS(&s_idSyncIOCancelledEvent, sizeof(HANDLE), s_LocalEventCtor, s_LocalHandleDtor, "InterceptWaits cancel evt");
	if (phObject == NULL) {
		DbgPrint("[InterceptWaits:s_AlertableIOCancelProc] MwGetTLS for hTaskCancelledEvent failed with error 0x%08X\r\n", CbLastWinAPIError);
		return CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
	}
	pmeta->hTaskCancelledEvent = *phObject;

	phObject = MwGetTLS(&s_idSyncIOCompleteEvent, sizeof(HANDLE), s_LocalEventCtor, s_LocalHandleDtor, "InterceptWaits complete evt");
	if (phObject == NULL) {
		DbgPrint("[InterceptWaits:s_AlertableIOCancelProc] MwGetTLS for hTaskCompleteEvent failed with error 0x%08X\r\n", CbLastWinAPIError);
		return CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
	}
	pmeta->hTaskCompleteEvent = *phObject;

	phObject = MwGetTLS(&s_idSyncIOThreadHandle, sizeof(HANDLE), s_LocalSyncIOThreadCtor, s_LocalSyncIOThreadDtor, "InterceptWaits I/O thread");
	if (phObject == NULL) {
		DbgPrint("[InterceptWaits:s_AlertableIOCancelProc] MwGetTLS for hNewThread failed with error 0x%08X\r\n", CbLastWinAPIError);
		return CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
	}
	pmeta->hNewThread = *phObject;

	pmeta->statusTaskResult = 0;
	return 0;
}

static NTSTATUS s_UninitSyncIOMetadata(PMW_WAITS_IO_METADATA pmeta) {
	pmeta->hOriginalThread = NULL;
	pmeta->hTaskCancelledEvent = NULL;
	pmeta->hTaskCompleteEvent = NULL;
	pmeta->statusTaskResult = 0;
	return 0;
}

static BOOL __stdcall s_LocalEventCtor(PHANDLE phEvent) {
	NTSTATUS status;

	status = NtCreateEvent(phEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_LocalEventCtor] NtCreateEvent returned 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return TRUE;
}

static BOOL __stdcall s_LocalSyncIOThreadCtor(PHANDLE phThread) {
	NTSTATUS status;
	CLIENT_ID client;

	status = RtlCreateUserThread(CB_CURRENT_PROCESS, NULL, TRUE, 0, NULL, NULL, MwAPCProcessingThreadProc, NULL, phThread, &client);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_LocalSyncIOThreadCtor] RtlCreateUserThread returned 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	status = DisableIOInterception((DWORD)client.UniqueThread);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_LocalSyncIOThreadCtor] DisableIOInterception returned 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	status = NtResumeThread(*phThread, NULL);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_LocalSyncIOThreadCtor] NtResumeThread returned 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return TRUE;
}

static BOOL __stdcall s_LocalThreadHandleCtor(PHANDLE phThread) {
	NTSTATUS status;

	status = CbOpenCurrentThread(phThread);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_LocalThreadHandleCtor] CbOpenCurrentThread returned 0x%08X\r\n", status);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return TRUE;
}

static void __stdcall s_LocalHandleDtor(PHANDLE phObject) {
	NtClose(*phObject);
}

static void __stdcall s_LocalSyncIOThreadDtor(PHANDLE phThread) {
	NTSTATUS status;

	status = NtTerminateThread(*phThread, 0);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_LocalSyncIOThreadDtor] NtTerminateThread returned 0x%08X\r\n", status);

	NtClose(*phThread);
}

static NTSTATUS s_InitAsyncIOMetadata(PMW_WAITS_IO_METADATA pmeta) {
	NTSTATUS status;

	RtlSecureZeroMemory(pmeta, sizeof(*pmeta));

	status = CbOpenCurrentThread(&pmeta->hOriginalThread);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_InitAsyncIOMetadata] CbOpenCurrentThread returned 0x%08X\r\n", status);
		goto L_errorexit;
	}

	status = NtCreateEvent(&pmeta->hTaskCompleteEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_InitAsyncIOMetadata] NtCreateEvent for hTaskCompleteEvent returned 0x%08X\r\n", status);
		goto L_errorexit;
	}

	status = NtCreateEvent(&pmeta->hTaskCancelledEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_InitAsyncIOMetadata] NtCreateEvent for hTaskCancelledEvent returned 0x%08X\r\n", status);
		goto L_errorexit;
	}

	pmeta->hNewThread = MwGetPoolThread();
	if (pmeta->hNewThread == NULL) {
		DbgPrint("[InterceptWaits:s_InitAsyncIOMetadata] MwGetPoolThread failed with error 0x%08X\r\n", CbLastWinAPIError);
		status = CB_WINAPIERR_TO_NTSTATUS(CbLastWinAPIError);
		goto L_errorexit;
	}

	return 0;

L_errorexit:
	s_UninitAsyncIOMetadata(pmeta);
	return status;
}

static void s_UninitAsyncIOMetadata(PMW_WAITS_IO_METADATA pmeta) {
	if (pmeta->hOriginalThread)
		NtClose(pmeta->hOriginalThread);

	if (pmeta->hTaskCompleteEvent)
		NtClose(pmeta->hTaskCompleteEvent);

	if (pmeta->hTaskCancelledEvent)
		NtClose(pmeta->hTaskCancelledEvent);

	if (pmeta->hNewThread)
		MwReturnPoolThread(pmeta->hNewThread);

	RtlSecureZeroMemory(pmeta, sizeof(*pmeta));
}

static void s_InitReadWriteOp(PMW_WAITS_IO_OP pop, HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, PVOID pBuffer, ULONG nBytesToXfer, OPTIONAL PLARGE_INTEGER pliByteOffset, OPTIONAL PULONG pnKey)
{
	RtlSecureZeroMemory(pop, sizeof(*pop));

	pop->hFile = hFile;
	pop->hEvent = hEvent;
	pop->pAPCRoutine = pAPCRoutine;
	pop->pAPCContext = pAPCContext;
	pop->piosb = piosb;
	pop->ReadWrite.pBuffer = pBuffer;
	pop->ReadWrite.nBytesToRead = nBytesToXfer;

	if (pliByteOffset) {
		pop->ReadWrite.bHasOffset = TRUE;
		pop->ReadWrite.liByteOffset = *pliByteOffset;
	}

	if (pnKey) {
		pop->ReadWrite.bHasKey = TRUE;
		pop->ReadWrite.nKey = *pnKey;
	}
}

static void s_InitIOControlOp(PMW_WAITS_IO_OP pop, HANDLE hFile, OPTIONAL HANDLE hEvent, OPTIONAL PVOID pAPCRoutine, OPTIONAL PVOID pAPCContext,
	PIO_STATUS_BLOCK piosb, ULONG nIOCTL, OPTIONAL PVOID pInBuf, ULONG nInBufLen, OPTIONAL PVOID pOutBuf, ULONG nOutBufLen)
{
	RtlSecureZeroMemory(pop, sizeof(*pop));

	pop->hFile = hFile;
	pop->hEvent = hEvent;
	pop->pAPCRoutine = pAPCRoutine;
	pop->pAPCContext = pAPCContext;
	pop->piosb = piosb;
	pop->IOControl.nIOCTL = nIOCTL;
	pop->IOControl.pInBuf = pInBuf;
	pop->IOControl.nInBufLen = nInBufLen;
	pop->IOControl.pOutBuf = pOutBuf;
	pop->IOControl.nOutBufLen = nOutBufLen;
}

NTSTATUS DisableIOInterception(DWORD nThreadID) {
	NTSTATUS status;
	HANDLE hThread = NULL;
	OBJECT_ATTRIBUTES attrib;
	CLIENT_ID client;

	if (nThreadID == 0)
		return STATUS_INVALID_PARAMETER_1;

	RtlSecureZeroMemory(&attrib, sizeof(attrib));
	attrib.Length = sizeof(attrib);
	client.UniqueProcess = CbGetTEB()->ClientId.UniqueProcess;
	client.UniqueThread = nThreadID;

	status = NtOpenThread(&hThread, SYNCHRONIZE, &attrib, &client);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:DisableIOInterception] NtOpenThread failed with error 0x%08X\r\n", status);
		return status;
	}

	CbAcquireSpinLockYielding(&s_lockNoInterceptList);

	__try {
		if (avl_search(&s_treeNoIntercept, (void*)nThreadID) == NULL)
			avl_insert(&s_treeNoIntercept, (void*)nThreadID, (void*)hThread);

		if (avl_search(&s_treeNoIntercept, (void*)nThreadID) == NULL)
			status = STATUS_NO_MEMORY;
		else
			status = 0;
	} __finally {
		CbReleaseSpinLock(&s_lockNoInterceptList);

		if (status != 0)
			NtClose(hThread);
	}

	return status;
}

static NTSTATUS s_UnsetThreadAsNoIntercept(DWORD nThreadID) {
	HANDLE hThread = NULL;

	CbAcquireSpinLockYielding(&s_lockNoInterceptList);
	__try {
		hThread = avl_remove(&s_treeNoIntercept, nThreadID);
	} __finally {
		CbReleaseSpinLock(&s_lockNoInterceptList);
	}

	if (hThread != NULL) {
		NtClose(hThread);
		return 0;
	} else
		return STATUS_NOT_FOUND;
}

static NTSTATUS s_CheckNoInterceptStatus(PBOOL pbNoIntercept) {
	CbAcquireSpinLockYielding(&s_lockNoInterceptList);
	__try {
		*pbNoIntercept = avl_search(&s_treeNoIntercept, (void*)CbGetTEB()->ClientId.UniqueThread) != NULL;
	} __finally {
		CbReleaseSpinLock(&s_lockNoInterceptList);
	}
	return 0;
}

static void s_NullKeyDtor(void* key) { }

static void s_HandleClosingValueDtor(void* key, HANDLE hValue) {
	NtClose(hValue);
}
