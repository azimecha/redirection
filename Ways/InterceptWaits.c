#include "ThreadLocal.h"
#include <HookFunction.h>
#include <NTDLL.h>

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
	HANDLE hTaskCompleteEvent, hTaskCancelledEvent, hOriginalThread;
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
			PLARGE_INTEGER pliByteOffset;
			PULONG pnKey;
		} ReadWrite;
		struct {
			PFILE_SEGMENT_ELEMENT pSegments;
			ULONG nBytesToRead;
			PLARGE_INTEGER pliByteOffset;
			PULONG pnKey;
		} ScatterGather;
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

static NTSTATUS __stdcall s_SyncIOThreadProc(PVOID pParams);
static void __stdcall s_SyncIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_AlertableIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);
static void __stdcall s_OverlappedIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);

static NTSTATUS s_PerformIO(PMW_WAITS_IO_OP pop);
static void __stdcall s_PerformanceCancelledAPC(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved);

static NTSTATUS s_InitIOMetadata(PMW_WAITS_IO_METADATA pmeta);
static NTSTATUS s_UninitIOMetadata(PMW_WAITS_IO_METADATA pmeta);

static NtReadFile_t s_procNtReadFile = NULL;
static NtReadFileScatter_t s_procNtReadFileScatter = NULL;
static NtWriteFile_t s_procNtWriteFile = NULL;
static NtWriteFileGather_t s_procNtWriteFileGather = NULL;
static NtDeviceIoControlFile_t s_procNtDeviceIoControlFile = NULL;
static NtFsControlFile_t s_procNtFsControlFile = NULL;

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
		pop->ReadWrite.pliByteOffset, pop->ReadWrite.pnKey);
}

static NTSTATUS s_ImplReadFileScatter(PMW_WAITS_IO_OP pop) {
	return s_procNtReadFileScatter(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ScatterGather.pSegments,
		pop->ScatterGather.nBytesToRead, pop->ScatterGather.pliByteOffset, pop->ScatterGather.pnKey);
}

static NTSTATUS s_ImplWriteFile(PMW_WAITS_IO_OP pop) {
	return s_procNtWriteFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ReadWrite.pBuffer, pop->ReadWrite.nBytesToRead,
		pop->ReadWrite.pliByteOffset, pop->ReadWrite.pnKey);
}

static NTSTATUS s_ImplWriteFileGather(PMW_WAITS_IO_OP pop) {
	return s_procNtReadFileScatter(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->ScatterGather.pSegments,
		pop->ScatterGather.nBytesToRead, pop->ScatterGather.pliByteOffset, pop->ScatterGather.pnKey);
}

static NTSTATUS s_ImplDeviceIoControlFile(PMW_WAITS_IO_OP pop) {
	return s_procNtDeviceIoControlFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->IOControl.nIOCTL, pop->IOControl.pInBuf,
		pop->IOControl.nInBufLen, pop->IOControl.pOutBuf, pop->IOControl.nOutBufLen);
}

static NTSTATUS s_ImplFsControlFile(PMW_WAITS_IO_OP pop) {
	return s_procNtFsControlFile(pop->hFile, pop->hEvent, pop->pAPCRoutine, pop->pAPCContext, pop->piosb, pop->IOControl.nIOCTL, pop->IOControl.pInBuf,
		pop->IOControl.nInBufLen, pop->IOControl.pOutBuf, pop->IOControl.nOutBufLen);
}

static NTSTATUS __stdcall s_SyncIOThreadProc(PVOID pParams) {
	NTSTATUS status;
	LARGE_INTEGER liTimeout;

	liTimeout.QuadPart = INT64_MAX;

	for (;;) {
		status = NtDelayExecution(TRUE, &liTimeout);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_SyncIOThreadProc] NtDelayExecution returned 0x%08X\r\n", status);
	}
}

static void __stdcall s_SyncIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;

	// runs on synchronous I/O thread
	// responsible for actually performing the I/O and setting hTaskCompleteEvent
	// this thread will be terminated on I/O cancellation

	__try {
		pop->meta.statusTaskResult = pop->procDoActualIO(pop);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[InterceptWaits:s_SyncIOTaskProc] Exception 0x%08X in synchronous I/O request\r\n", GetExceptionCode());
		pop->meta.statusTaskResult = GetExceptionCode();
	}

	status = NtSetEvent(pop->meta.hTaskCompleteEvent, NULL);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_SyncIOTaskProc] Error 0x%08X setting task completion event\r\n", status);
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
		status = NtQueueApcThread(pop->meta.hOriginalThread, s_PerformanceCancelledAPC, pop, piosbIgnored, 0);
		if (CB_NT_FAILED(status))
			DbgPrint("[InterceptWaits:s_AlertableIOTaskProc] Error 0x%08X queuing cancellation APC\r\n", status);
		return;

	default:
		DbgPrint("[InterceptWaits:s_AlertableIOTaskProc] NtWaitForMultipleObjects returned 0x%08X\r\n", status);
	}
}

static void __stdcall s_OverlappedIOTaskProc(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {

}

static NTSTATUS s_PerformIO(PMW_WAITS_IO_OP pop) {
	NTSTATUS status;
	MW_WAITS_FILE_MODE mode;
	PIO_APC_ROUTINE procAPC;
	PMW_WAITS_IO_OP popOriginal = NULL;

	// runs on main thread

	status = s_CheckMode(pop->hFile, &mode);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X querying mode\r\n", status);
		return status;
	}

	switch (mode) {
	case MwWaitsFileMode_Overlapped:
		procAPC = s_OverlappedIOTaskProc;
		popOriginal = pop;
		pop = CbHeapAllocate(sizeof(MW_WAITS_IO_OP), FALSE);
		if (pop == NULL) {
			pop = popOriginal;
			popOriginal = NULL;
			status = STATUS_NO_MEMORY;
			goto L_exit;
		}
		break;

	case MwWaitsFileMode_SyncAlert:
		procAPC = s_AlertableIOTaskProc;
		break;

	case MwWaitsFileMode_Synchronous:
		procAPC = s_SyncIOTaskProc;
		break;

	default:
		DbgPrint("[InterceptWaits:s_PerformIO] Unknown mode %u\r\n", mode);
		status = STATUS_INVALID_PARAMETER;
	}

	status = s_InitIOMetadata(&pop->meta);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptWaits:s_PerformIO] Error 0x%08X initializing I/O metadata\r\n", status);
		return status;
	}

L_exit:
	if (popOriginal != NULL)
		CbHeapFree(pop);
	return status;
}

//	HANDLE hTaskCompleteEvent, hTaskCancelledEvent, hOriginalThread;
//  NTSTATUS statusTaskResult;

static void __stdcall s_PerformanceCancelledAPC(PMW_WAITS_IO_OP pop, PIO_STATUS_BLOCK piosbIgnored, ULONG nReserved) {
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	// runs on main thread
	// used to cancel alertable synchronous I/O, i.e. not overlapped but APCs allowed

	RtlSecureZeroMemory(&iosb, sizeof(iosb));
	status = NtCancelIoFile(pop->hFile, &iosb);
	if (CB_NT_FAILED(status))
		DbgPrint("[InterceptWaits:s_PerformanceCancelledAPC] NtCancelIoFile returned 0x%08X\r\n", status);

}

static NTSTATUS s_InitIOMetadata(PMW_WAITS_IO_METADATA pmeta) {

}

static NTSTATUS s_UninitIOMetadata(PMW_WAITS_IO_METADATA pmeta) {

}
