#include "NTDLL.h"
#include "ImportHelper.h"
#include <malloc.h>

/*
#define CB_NTDLL_DEFINE(r,n,...)											\
	static const char s_cszFunc ## n [] = #n;								\
	static LPVOID s_pFunc ## n = NULL;										\
	__declspec(naked) r __stdcall n(__VA_ARGS__) {							\
		__asm { MOV EAX, DWORD PTR s_pFunc ## n }							\
		__asm { OR EAX, EAX }												\
		__asm { JNZ L_found }												\
		__asm { PUSH OFFSET s_cszFunc ## n }								\
		__asm { CALL CbGetNTDLLFunction }									\
		__asm { MOV DWORD PTR s_pFunc ## n, EAX}							\
	L_found:																\
		__asm { PUSH EAX }													\
		__asm { RET }														\
	}
*/

#define CB_NTDLL_DEFINE(n,a1,a2)											\
	static NTSTATUS (__stdcall* s_func ## n)a1;								\
	NTSTATUS __stdcall n a1 {												\
		if ((s_func ## n) == NULL)											\
			s_func ## n = CbGetNTDLLFunction(#n);							\
		if ((s_func ## n) == NULL)											\
			return STATUS_ENTRYPOINT_NOT_FOUND;								\
		return s_func ## n a2;												\
	}

LPVOID CbNTDLLBaseAddress = NULL;

LPVOID __stdcall CbGetNTDLLFunction(LPCSTR pcszFuncName) {
	return CbGetSymbolAddress(CbGetNTDLLBaseAddress(), pcszFuncName);
}

CB_NTDLL_DEFINE(NtQueryInformationFile, (HANDLE a, PIO_STATUS_BLOCK b, PVOID c, ULONG d, FILE_INFORMATION_CLASS e), (a, b, c, d, e));
CB_NTDLL_DEFINE(NtQuerySection, (HANDLE a, SECTION_INFORMATION_CLASS b, PVOID c, ULONG d, PULONG e), (a, b, c, d, e));
CB_NTDLL_DEFINE(NtUnmapViewOfSection, (HANDLE a, PVOID b), (a, b));
CB_NTDLL_DEFINE(NtQueryVirtualMemory, (HANDLE a, PVOID b, MEMORY_INFORMATION_CLASS c, PVOID d, ULONG e, PULONG f), (a, b, c, d, e, f));
CB_NTDLL_DEFINE(NtRaiseHardError, (LONG a, ULONG b, ULONG c, PULONG_PTR d, ULONG e, PULONG f), (a, b, c, d, e, f));
CB_NTDLL_DEFINE(NtTerminateProcess, (HANDLE a, NTSTATUS b), (a, b));
CB_NTDLL_DEFINE(NtMapViewOfSection, (HANDLE a, HANDLE b, PVOID* c, ULONG_PTR d, SIZE_T e, PLARGE_INTEGER f, PSIZE_T g, DWORD h,
	ULONG i, ULONG j), (a, b, c, d, e, f, g, h, i, j));
CB_NTDLL_DEFINE(NtSuspendProcess, (HANDLE a), (a));
CB_NTDLL_DEFINE(NtResumeProcess, (HANDLE a), (a));
CB_NTDLL_DEFINE(NtQueryInformationProcess, (HANDLE a, PROCESSINFOCLASS b, PVOID c, ULONG d, PULONG e), (a, b, c, d, e));

CB_NTDLL_DEFINE(RtlAnsiStringToUnicodeString, (PUNICODE_STRING a, PCANSI_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(RtlUnicodeStringToAnsiString, (PANSI_STRING a, PCUNICODE_STRING b, BOOLEAN c), (a, b, c));

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

ULONG __stdcall RtlNtStatusToDosError(NTSTATUS status) {
	static ULONG(__stdcall * procRtlNtStatusToDosError)(NTSTATUS status);

	if (procRtlNtStatusToDosError == NULL)
		procRtlNtStatusToDosError = CbGetNTDLLFunction("RtlNtStatusToDosError");

	if (procRtlNtStatusToDosError == NULL)
		return ~0L;

	return procRtlNtStatusToDosError(status);
}

void __stdcall RtlFreeUnicodeString(PUNICODE_STRING pusFromRtl) {
	static void(__stdcall * procRtlFreeUnicodeString)(PUNICODE_STRING pusFromRtl);

	if (procRtlFreeUnicodeString == NULL)
		procRtlFreeUnicodeString = CbGetNTDLLFunction("RtlFreeUnicodeString");

	if (procRtlFreeUnicodeString == NULL)
		return;

	procRtlFreeUnicodeString(pusFromRtl);
}

#ifndef WINVER
#define WINVER 0x0500
#endif

#define WIN32_LEAN_AND_MEAN
#include <WinUser.h>

static const int s_arrMessageBoxSeverityFlags[] = { 0, MB_ICONINFORMATION, MB_ICONWARNING, MB_ICONERROR };

NTSTATUS CbDisplayMessageUni(PUNICODE_STRING pusTitle, PUNICODE_STRING pusMessage, CbSeverity_t sev) {
	ULONG nResponse;
	ULONG_PTR arrParams[3];

	arrParams[0] = (ULONG_PTR)pusMessage;
	arrParams[1] = (ULONG_PTR)pusTitle;
	arrParams[2] = (ULONG_PTR)s_arrMessageBoxSeverityFlags[(int)sev];

	return NtRaiseHardError(0x50000018, RTL_NUMBER_OF_V2(arrParams), 3, arrParams, 0, &nResponse);
}

NTSTATUS CbDisplayMessageA(LPCSTR pcszTitle, LPCSTR pcszMessage, CbSeverity_t sev) {
	ANSI_STRING asTitle, asMessage;
	UNICODE_STRING usTitle, usMessage;
	NTSTATUS status;

	if (pcszTitle == NULL) pcszTitle = "";
	if (pcszMessage == NULL) pcszMessage = "";

	asTitle.Buffer = (PCHAR)pcszTitle;
	asTitle.Length = (USHORT)strlen(pcszTitle);
	asTitle.MaximumLength = asTitle.Length;

	asMessage.Buffer = (PCHAR)pcszMessage;
	asMessage.Length = (USHORT)strlen(pcszMessage);
	asMessage.MaximumLength = asMessage.Length;

	status = RtlAnsiStringToUnicodeString(&usTitle, &asTitle, TRUE);
	if (status != 0) goto L_exit;

	status = RtlAnsiStringToUnicodeString(&usMessage, &asMessage, TRUE);
	if (status != 0) goto L_exit_freetitle;

	status = CbDisplayMessageUni(&usTitle, &usMessage, sev);

	RtlFreeUnicodeString(&usMessage);
L_exit_freetitle:
	RtlFreeUnicodeString(&usTitle);
L_exit:
	return status;
}

NTSTATUS CbDisplayMessageW(LPCWSTR pcwzTitle, LPCWSTR pcwzMessage, CbSeverity_t sev) {
	UNICODE_STRING usTitle, usMessage;

	usTitle.Buffer = (PWCHAR)pcwzTitle;
	usTitle.Length = (USHORT)(wcslen(pcwzTitle) * sizeof(WCHAR));
	usTitle.MaximumLength = usTitle.Length;

	usMessage.Buffer = (PWCHAR)pcwzMessage;
	usMessage.Length = (USHORT)(wcslen(pcwzMessage) * sizeof(WCHAR));
	usMessage.MaximumLength = usMessage.Length;

	return CbDisplayMessageUni(&usTitle, &usMessage, sev);
}

LPVOID __stdcall CbGetNTDLLBaseAddress(void) {
	PLDR_DATA_TABLE_ENTRY_FULL pentNTDLL;

	if (CbNTDLLBaseAddress == NULL) {
		// cannot use CbGetLoadedImageByString because it calls NT funcs
		pentNTDLL = CbGetLoadedImageByIndex(1);
		if (pentNTDLL == NULL)
			return NULL;

		CbNTDLLBaseAddress = pentNTDLL->DllBase;
	}

	return CbNTDLLBaseAddress;
}
