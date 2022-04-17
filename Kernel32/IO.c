#include <WaysIO.h>
#include <NTDLL.h>
#include <minwinbase.h>

BOOL WINAPI Impl_CancelIo(HANDLE hFile) {
	NTSTATUS status;

	status = MwCancelHandleIO(hFile, CB_CURRENT_THREAD);

	CbLastWinAPIError = RtlNtStatusToDosError(status);
	return !CB_NT_FAILED(status);
}

BOOL WINAPI Impl_CancelIoEx(HANDLE hFile, OPTIONAL LPOVERLAPPED povlToCancel) {
	NTSTATUS status;

	if (povlToCancel)
		status = MwCancelIORequest(povlToCancel); // iosb is "internal" items at start of overlapped struct
	else
		status = MwCancelHandleIO(hFile, NULL);

	CbLastWinAPIError = RtlNtStatusToDosError(status);
	return !CB_NT_FAILED(status);
}

BOOL WINAPI Impl_CancelSynchronousIo(HANDLE hThread) {
	NTSTATUS status;

	status = MwCancelThreadIO(hThread, TRUE);

	CbLastWinAPIError = RtlNtStatusToDosError(status);
	return !CB_NT_FAILED(status);
}
