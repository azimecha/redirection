#include <ImportHelper.h>
#include <NTDLL.h>
#include <minwinbase.h>
#include <winerror.h>

CB_UNDECORATED_EXTERN(HANDLE, CreateSemaphoreW, LPSECURITY_ATTRIBUTES pattr, LONG nInitCount, LONG nMaxCount, LPCWSTR pcwzName);

HANDLE WINAPI Impl_CreateSemaphoreExW(LPSECURITY_ATTRIBUTES pattr, LONG nInitCount, LONG nMaxCount, LPCWSTR pcwzName, DWORD flags, DWORD access) {
	HANDLE hTemp, hFinal;
	NTSTATUS status;

	if (flags != 0) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return NULL;
	}

	hTemp = CB_UNDECORATED_CALL(CreateSemaphoreW, pattr, nInitCount, nMaxCount, pcwzName);
	if (hTemp == NULL)
		return NULL;

	// reopen with desired access

	status = NtDuplicateObject(CB_CURRENT_PROCESS, hTemp, CB_CURRENT_PROCESS, &hFinal, access, FALSE, 0);
	NtClose(hTemp);

	CbLastWinAPIError = RtlNtStatusToDosError(status);
	return CB_NT_FAILED(status) ? NULL : hFinal;
}
