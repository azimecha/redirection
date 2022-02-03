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

#define CB_NTDLL_DEFINE_ALT(r,n,a1,a2)										\
	static r (__stdcall* s_func ## n)a1;									\
	r __stdcall n a1 {														\
		if ((s_func ## n) == NULL)											\
			s_func ## n = CbGetNTDLLFunction(#n);							\
		if ((s_func ## n) == NULL)											\
			return (r)0;													\
		return s_func ## n a2;												\
	}

#define CB_NTDLL_DEFINE_VOID(n,a1,a2)										\
	static void (__stdcall* s_func ## n)a1;									\
	void __stdcall n a1 {													\
		if ((s_func ## n) == NULL)											\
			s_func ## n = CbGetNTDLLFunction(#n);							\
		if ((s_func ## n) != NULL)											\
			s_func ## n a2;													\
	}		

LPVOID CbNTDLLBaseAddress = NULL;

LPVOID CbGetNTDLLFunction(LPCSTR pcszFuncName) {
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
CB_NTDLL_DEFINE(NtFlushInstructionCache, (HANDLE a, PVOID b, ULONG c), (a, b, c));
CB_NTDLL_DEFINE(NtProtectVirtualMemory, (HANDLE a, PVOID* b, PULONG c, ULONG d, PULONG e), (a, b, c, d, e));
CB_NTDLL_DEFINE(NtCreateFile, (PHANDLE a, ACCESS_MASK b, POBJECT_ATTRIBUTES c, PIO_STATUS_BLOCK d, PLARGE_INTEGER e, ULONG f, ULONG g,
	ULONG h, ULONG i, PVOID j, ULONG k), (a, b, c, d, e, f, g, h, i, j, k));
CB_NTDLL_DEFINE(NtCreateSection, (PHANDLE a, ULONG b, OPTIONAL POBJECT_ATTRIBUTES c, OPTIONAL PLARGE_INTEGER d, ULONG e, ULONG f, 
	OPTIONAL HANDLE g), (a, b, c, d, e, f, g));
CB_NTDLL_DEFINE(NtClose, (HANDLE a), (a));
CB_NTDLL_DEFINE(NtAllocateVirtualMemory, (HANDLE a, OUT PVOID* b, ULONG c, OUT PULONG d, ULONG e, ULONG f), (a, b, c, d, e, f));
CB_NTDLL_DEFINE(NtFreeVirtualMemory, (HANDLE a, PVOID* b, IN OUT PULONG c, ULONG d), (a, b, c, d));

CB_NTDLL_DEFINE_ALT(PVOID, RtlCreateHeap, (ULONG a, OPTIONAL PVOID b, OPTIONAL SIZE_T c, OPTIONAL SIZE_T d, OPTIONAL PVOID e,
	OPTIONAL PVOID f), (a, b, c, d, e, f));
CB_NTDLL_DEFINE_ALT(PVOID, RtlAllocateHeap, (PVOID a, OPTIONAL ULONG b, SIZE_T c), (a, b, c));
CB_NTDLL_DEFINE_ALT(BOOL, RtlFreeHeap, (PVOID a, OPTIONAL ULONG b, PVOID c), (a, b, c));
CB_NTDLL_DEFINE_ALT(PVOID, RtlDestroyHeap, (PVOID a), (a));

CB_NTDLL_DEFINE_VOID(RtlAcquirePebLock, (), ());
CB_NTDLL_DEFINE_VOID(RtlReleasePebLock, (), ());

CB_NTDLL_DEFINE(RtlAnsiStringToUnicodeString, (PUNICODE_STRING a, PCANSI_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(RtlUnicodeStringToAnsiString, (PANSI_STRING a, PCUNICODE_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(LdrLoadDll, (OPTIONAL PWCHAR a, ULONG b, PUNICODE_STRING c, OUT PHANDLE d), (a, b, c, d));

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

LPVOID CbGetNTDLLBaseAddress(void) {
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

static NTSTATUS __cdecl s_DummyDebugPrint(LPCSTR pcszFormat, ...) {
	return STATUS_ENTRYPOINT_NOT_FOUND;
}

DbgPrint_t CbGetDebugPrintFunction(void) {
	static DbgPrint_t procDbgPrint = NULL;

	if (procDbgPrint == NULL)
		procDbgPrint = CbGetNTDLLFunction("DbgPrint");

	return (procDbgPrint == NULL) ? s_DummyDebugPrint : procDbgPrint;
}

ULONG __stdcall RtlGetCurrentDirectory_U(ULONG nMaxLen, OUT PWSTR pwzBuffer) {
	static RtlGetCurrentDirectory_U_t procRtlGetCurrentDirectory_U = NULL;

	if (procRtlGetCurrentDirectory_U == NULL)
		procRtlGetCurrentDirectory_U = CbGetNTDLLFunction("RtlGetCurrentDirectory_U");

	return procRtlGetCurrentDirectory_U(nMaxLen, pwzBuffer);
}

BOOLEAN __stdcall RtlDoesFileExists_U(PCWSTR pcwzPath) {
	static RtlDoesFileExists_U_t procRtlDoesFileExists_U = NULL;

	if (procRtlDoesFileExists_U == NULL)
		procRtlDoesFileExists_U = CbGetNTDLLFunction("RtlDoesFileExists_U");

	return procRtlDoesFileExists_U(pcwzPath);
}

ULONG __stdcall RtlGetFullPathName_U(PCWSTR pcwzFileName, ULONG nBufSize, OUT PWSTR pwzBuffer, OPTIONAL OUT PWSTR pwzShortName) {
	static RtlGetFullPathName_U_t procRtlGetFullPathName_U = NULL;

	if (procRtlGetFullPathName_U == NULL)
		procRtlGetFullPathName_U = CbGetNTDLLFunction("RtlGetFullPathName_U");

	return procRtlGetFullPathName_U(pcwzFileName, nBufSize, pwzBuffer, pwzShortName);
}

static const WCHAR s_cwzPrefix[] = L"\\??\\";

NTSTATUS CbCreateFileNT(LPCSTR pcszPath, ACCESS_MASK access, ULONG nShareMode, ULONG nCreateDisposition, ULONG options, OUT PHANDLE phFile) {
	ANSI_STRING asOrigPath;
	UNICODE_STRING usOrigPath, usFullPath;
	NTSTATUS status;
	WCHAR wzOrigPath[MAX_PATH + 1];
	WCHAR wzFullPath[MAX_PATH * 2];
	OBJECT_ATTRIBUTES attrs;
	IO_STATUS_BLOCK iosb;

	asOrigPath.Buffer = (PCHAR)pcszPath;
	asOrigPath.Length = (USHORT)strlen(pcszPath);
	asOrigPath.MaximumLength = asOrigPath.Length;

	usOrigPath.Buffer = wzOrigPath;
	usOrigPath.Length = 0;
	usOrigPath.MaximumLength = sizeof(wzOrigPath);

	status = RtlAnsiStringToUnicodeString(&usOrigPath, &asOrigPath, FALSE);
	if (status != 0) return status;

	RtlGetFullPathName_U(wzOrigPath, sizeof(wzFullPath), wzFullPath, NULL);

	usFullPath.Buffer = wzFullPath;
	usFullPath.Length = (USHORT)(wcslen(wzFullPath) * sizeof(WCHAR));
	usFullPath.MaximumLength = (USHORT)sizeof(wzFullPath);

	if (wzFullPath[0] != '\\') {
		if ((usFullPath.Length + sizeof(s_cwzPrefix)) > usFullPath.MaximumLength)
			return STATUS_BUFFER_TOO_SMALL;
		memmove((BYTE*)wzFullPath + sizeof(s_cwzPrefix) - sizeof(WCHAR), wzFullPath, usFullPath.Length + 1);
		memcpy(wzFullPath, s_cwzPrefix, sizeof(s_cwzPrefix) - sizeof(WCHAR));
		usFullPath.Length += sizeof(s_cwzPrefix) - sizeof(WCHAR);
	}

	DbgPrint("[CbCreateFileNT] Opening %wZ\r\n", &usFullPath);

	RtlSecureZeroMemory(&attrs, sizeof(attrs));
	attrs.Length = sizeof(attrs);
	attrs.ObjectName = &usFullPath;
	attrs.Attributes = OBJ_CASE_INSENSITIVE;
	RtlSecureZeroMemory(&iosb, sizeof(iosb));

	status = NtCreateFile(phFile, access, &attrs, &iosb, NULL, 0, nShareMode, nCreateDisposition, options, NULL, 0);
	return status;
}

NTSTATUS CbGetSectionName(HANDLE hProcess, LPVOID pMemoryArea, LPSTR pszNameBuf, SIZE_T nBufSize) {
	BYTE arrNameUniBuffer[MAX_PATH * 3];
	PUNICODE_STRING pusModuleName;
	ANSI_STRING asModuleName;
	NTSTATUS status;
	ULONG nResultSize;

	nResultSize = sizeof(arrNameUniBuffer);
	status = NtQueryVirtualMemory(hProcess, pMemoryArea, MemorySectionName, arrNameUniBuffer, sizeof(arrNameUniBuffer), &nResultSize);
	if (status != 0) return status;

	pusModuleName = (PUNICODE_STRING)&arrNameUniBuffer[0];
	asModuleName.Buffer = pszNameBuf;
	asModuleName.Length = 0;
	asModuleName.MaximumLength = (USHORT)nBufSize;

	status = RtlUnicodeStringToAnsiString(&asModuleName, pusModuleName, FALSE);
	if (status != 0) return status;

	return 0;
}

NTSTATUS CbGetCurrentDirectoryNT(LPSTR pszBuffer, SIZE_T nBufSize) {
	ANSI_STRING asOutput;
	NTSTATUS status;

	asOutput.Buffer = pszBuffer;
	asOutput.Length = 0;
	asOutput.MaximumLength = (USHORT)nBufSize;

	RtlAcquirePebLock();
	status = RtlUnicodeStringToAnsiString(&asOutput, &((PPEB_FULL)CbGetPEB())->ProcessParameters->CurrentDirectoryPath, FALSE);
	RtlReleasePebLock();

	return status;
}

#pragma warning(disable:28112)

static volatile PVOID s_pDefaultHeap = NULL;

PVOID CbHeapAllocate(SIZE_T nBytes, BOOL bZeroInit) {
	PVOID pNewHeap;

	if (s_pDefaultHeap == NULL) {
		pNewHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
		if (pNewHeap == NULL) return NULL;

		if (InterlockedCompareExchangePointer(&s_pDefaultHeap, pNewHeap, NULL) != NULL)
			RtlDestroyHeap(pNewHeap);
	}

	return RtlAllocateHeap(s_pDefaultHeap, bZeroInit ? HEAP_ZERO_MEMORY : 0, nBytes);
}

void CbHeapFree(PVOID pBlock) {
	if (s_pDefaultHeap && pBlock)
		RtlFreeHeap(s_pDefaultHeap, 0, pBlock);
}
