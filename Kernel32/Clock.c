#include <ImportHelper.h>
#include <NTDLL.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define NS_PER_MS 1000000
#define NS_PER_SYSTIME 100
#define SYSTIME_PER_MS (NS_PER_MS / NS_PER_SYSTIME)

// returns time since 1601 instead of time since boot, programs should be able to handle this fine
// some may indicate that the system has been up for several hundred years though
ULONGLONG __stdcall Impl_GetTickCount64(void) {
	LARGE_INTEGER liSystemTime;
	NTSTATUS status;

	status = NtQuerySystemTime(&liSystemTime);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[Kernel32:GetTickCount64] NtQuerySystemTime returned 0x%08X\r\n", status);
		return 0;
	}

	return (ULONGLONG)(liSystemTime.QuadPart / SYSTIME_PER_MS);
}
