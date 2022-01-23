#include "Intercept.h"
#include <HookFunction.h>
#include <NTDLL.h>
#include <PartialStdio.h>
#include <FilePaths.h>
#include <ConfigReading.h>
#include <RewriteImports.h>
#include <CommandLineToArgv.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

//#define WAYS_INTERCEPT_SECTION
#define WAYS_INTERCEPT_MAPPING

typedef struct _struct_RewriteDataBag {
	char szRedirDLLName[MAX_PATH + 1];
} RewriteDataBag_t, *RewriteDataBag_p;

static NTSTATUS __stdcall s_InterceptedCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile);
static NTSTATUS __stdcall s_InterceptedImageCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile);

static NTSTATUS __stdcall s_InterceptedMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection);
static NTSTATUS __stdcall s_InterceptedImageMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection, PSECTION_IMAGE_INFORMATION pinfImageSection);

static BOOL s_RewriteReadMemory(EXTERNAL_PTR pSrcBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData);
static BOOL s_RewriteWriteMemory(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData);
static LPCSTR s_RewriteGetDLLReplacement(LPCSTR pcszName, RewriteDataBag_p pUserData);
static void s_RewriteDisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...);

static NtCreateSection_t s_procRealCreateSection;
static NtMapViewOfSection_t s_procRealMapViewOfSection;
static char s_szConfigPath[MAX_PATH];
static char s_mszExcludePaths[4096];

BOOL ApplyLoadingHooks(void) {
	NtCreateSection_t procCreateSection;
	NtMapViewOfSection_t procMapViewOfSection;
	LPSTR pszExcludePath;
	
	// would prefer not to do this while holding the loader lock...
	if (!PaFindConfigFileDirect("shims.ini", GetCurrentProcess(), s_szConfigPath, sizeof(s_szConfigPath))) {
		dprintf("[ApplyLoadingHooks] PaFindConfigFileDirect failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}

	if (GetPrivateProfileSectionA("Exclude", s_mszExcludePaths, sizeof(s_mszExcludePaths), s_szConfigPath) >= (sizeof(s_mszExcludePaths) - 2)) {
		dprintf("[ApplyLoadingHooks] Too many exclude paths!\r\n");
		return FALSE;
	}

	CB_FOREACH_MULTISZ(pszExcludePath, s_mszExcludePaths)
		CbStringToLowerA(pszExcludePath);

	// ... but it's important for this part

#ifdef WAYS_INTERCEPT_SECTION
	procCreateSection = CbGetNTDLLFunction("NtCreateSection");
	if (procCreateSection == NULL) {
		dprintf("[ApplyLoadingHooks] NtCreateSection not found!\r\n");
		return FALSE;
	}

	s_procRealCreateSection = PaHookSimpleFunction(procCreateSection, 16, s_InterceptedCreateSection);
	if (s_procRealCreateSection == NULL) {
		dprintf("[ApplyLoadingHooks] PaHookSimpleFunction for NtCreateSection failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}
#endif

#ifdef WAYS_INTERCEPT_MAPPING
	procMapViewOfSection = CbGetNTDLLFunction("NtMapViewOfSection");
	if (procMapViewOfSection == NULL) {
		dprintf("[ApplyLoadingHooks] NtMapViewOfSection not found!\r\n");
		return FALSE;
	}

	s_procRealMapViewOfSection = PaHookSimpleFunction(procMapViewOfSection, 16, s_InterceptedMapViewOfSection);
	if (s_procRealMapViewOfSection == NULL) {
		dprintf("[ApplyLoadingHooks] PaHookSimpleFunction for NtMapViewOfSection failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}
#endif

	(void)procCreateSection;
	(void)procMapViewOfSection;

	return TRUE;
}

static NTSTATUS __stdcall s_InterceptedCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile)
{
	if (nAllocAttribs & SEC_IMAGE)
		return s_InterceptedImageCreateSection(phSection, access, attrib, pnMaxSize, nProtection, nAllocAttribs, hFile);

	return s_procRealCreateSection(phSection, access, attrib, pnMaxSize, nProtection, nAllocAttribs, hFile);
}

static NTSTATUS __stdcall s_InterceptedImageCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	BYTE arrFileNameInfo[sizeof(FILE_NAME_INFORMATION) + MAX_PATH * 4];
	PFILE_NAME_INFORMATION pinfName;
	UNICODE_STRING usFilePath;
	char szFilePath[MAX_PATH * 2];
	ANSI_STRING asFilePath;
	LPSTR pszFileName;
	char szReplacementName[MAX_PATH];
	char szReplacementPath[MAX_PATH];
	BOOL bDidOpenFile;

	bDidOpenFile = FALSE;

	status = NtQueryInformationFile(hFile, &iosb, arrFileNameInfo, sizeof(arrFileNameInfo), FileNameInformation);
	if (status != 0) {
		dprintf("[InterceptedCreateSection] NtQueryInformationFile on 0x%08X returned 0x%08X\r\n", (uintptr_t)hFile, status);
		return status;
	}

	pinfName = (PFILE_NAME_INFORMATION)arrFileNameInfo;
	usFilePath.Buffer = pinfName->FileName;
	usFilePath.Length = (USHORT)pinfName->FileNameLength;
	usFilePath.MaximumLength = sizeof(arrFileNameInfo) - sizeof(FILE_NAME_INFORMATION);

	szFilePath[0] = 0;
	asFilePath.Buffer = szFilePath;
	asFilePath.Length = 0;
	asFilePath.MaximumLength = sizeof(szFilePath) - 1;

	status = RtlUnicodeStringToAnsiString(&asFilePath, &usFilePath, FALSE);
	if (status != 0) {
		dprintf("[InterceptedCreateSection] RtlUnicodeStringToAnsiString for file 0x%08X returned 0x%08X\r\n", (uintptr_t)hFile, status);
		return status;
	}

	szFilePath[asFilePath.Length] = 0;
	dprintf("[InterceptedCreateSection] Requested to map image %s\r\n", szFilePath);
	pszFileName = CbNormalizeModuleName(szFilePath);
	dprintf("[InterceptedCreateSection] Normalized module name is %s\r\n", pszFileName);

	if (GetPrivateProfileStringA("RedirectDLLs", pszFileName, "", szReplacementName, sizeof(szReplacementName), s_szConfigPath) != 0) {
		dprintf("[InterceptedCreateSection] Replacement with %s requested\r\n", szReplacementName);

		if (!PaFindModulePath(szReplacementName, szReplacementPath, sizeof(szReplacementPath))) {
			dprintf("[InterceptedCreateSection] Module could not be located!\r\n");
			return STATUS_DLL_NOT_FOUND;
		}

		dprintf("[InterceptedCreateSection] Module located at %s\r\n", szReplacementPath);

		hFile = CreateFileA(szReplacementPath, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			dprintf("[InterceptedCreateSection] Error 0x%08X opening module file\r\n", GetLastError());
			return 0xC0000136; // STATUS_OPEN_FAILED, yeah i know, we just need *something* that's an error code
		}

		bDidOpenFile = TRUE;
	}

	dprintf("[InterceptedCreateSection] Calling NtCreateSection\r\n");
	status = s_procRealCreateSection(phSection, access, attrib, pnMaxSize, nProtection, nAllocAttribs, hFile);
	dprintf("[InterceptedCreateSection] NtCreateSection returned 0x%08X\r\n", status);

	// don't worry, creating a section keeps it open as long as the section exists
	if (bDidOpenFile) CloseHandle(hFile);

	return status;
}

static NTSTATUS __stdcall s_InterceptedMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection)
{
	NTSTATUS status;
	SECTION_IMAGE_INFORMATION infImageSection;

	if (GetProcessId(hProcess) == GetCurrentProcessId()) {
		status = NtQuerySection(hSection, SectionImageInformation, &infImageSection, sizeof(infImageSection), NULL);
		if (status == 0)
			return s_InterceptedImageMapViewOfSection(hSection, hProcess, ppBaseAddress, nZeroBits, nCommitSize, pnSectionOffset,
				pnViewSize, nInheritDisposition, nAllocationType, nWin32Protection, &infImageSection);
		else
			dprintf("[InterceptedMapViewOfSection] NtQuerySection returned 0x%08X, assuming non-image section\r\n", status);
	}

	return s_procRealMapViewOfSection(hSection, hProcess, ppBaseAddress, nZeroBits, nCommitSize, pnSectionOffset, pnViewSize,
		nInheritDisposition, nAllocationType, nWin32Protection);
}

static NTSTATUS __stdcall s_InterceptedImageMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection, PSECTION_IMAGE_INFORMATION pinfImageSection)
{
	NTSTATUS status, statusAbort;
	RewriteDataBag_t data;
	BYTE arrNameUniBuffer[MAX_PATH * 3];
	PUNICODE_STRING pusModuleName;
	CHAR szNameAscBuffer[MAX_PATH + 1];
	ANSI_STRING asModuleName;
	ULONG nResultSize;
	LPSTR pszExcludePath;
	int* pnNoRedirectMarker;

	RtlSecureZeroMemory(&data, sizeof(data));

	status = s_procRealMapViewOfSection(hSection, hProcess, ppBaseAddress, nZeroBits, nCommitSize, pnSectionOffset, pnViewSize,
		nInheritDisposition, nAllocationType, nWin32Protection);
	if (status != 0) {
		dprintf("[InterceptedMapViewOfSection] RealMapViewOfSection returned 0x%08X\r\n", status);
		return status;
	}

	pnNoRedirectMarker = CbGetSymbolAddress(*ppBaseAddress, "NoRedirectImports");
	if ((pnNoRedirectMarker != NULL) && (*pnNoRedirectMarker == 1)) {
		dprintf("[InterceptedMapViewOfSection] Module excluded from import table rewrite (NoRedirectImports=1)\r\n");
		return 0;
	}

	status = NtQueryVirtualMemory(hProcess, *ppBaseAddress, MemorySectionName, arrNameUniBuffer, sizeof(arrNameUniBuffer), &nResultSize);
	if (status != 0) {
		dprintf("[InterceptedMapViewOfSection] NtQueryVirtualMemory returned 0x%08X\r\n", status);
		goto L_abort;
	}

	pusModuleName = (PUNICODE_STRING)&arrNameUniBuffer[0];
	asModuleName.Buffer = szNameAscBuffer;
	asModuleName.Length = 0;
	asModuleName.MaximumLength = sizeof(szNameAscBuffer) - 1;

	status = RtlUnicodeStringToAnsiString(&asModuleName, pusModuleName, FALSE);
	if (status != 0) {
		dprintf("[InterceptedMapViewOfSection] RtlUnicodeStringToAnsiString returned 0x%08X\r\n", status);
		goto L_abort;
	}

	szNameAscBuffer[asModuleName.Length] = 0;
	CbStringToLowerA(szNameAscBuffer);
	dprintf("[InterceptedMapViewOfSection] Module path: %s\r\m", szNameAscBuffer);

	CB_FOREACH_MULTISZ(pszExcludePath, s_mszExcludePaths) {
		if (strstr(szNameAscBuffer, pszExcludePath) != NULL) {
			dprintf("[InterceptedMapViewOfSection] Module excluded from import table rewrite by rule: %s\r\n", pszExcludePath);
			return 0;
		}
	}
	
	if (!PaRewriteImports(*ppBaseAddress, s_RewriteReadMemory, s_RewriteWriteMemory, s_RewriteGetDLLReplacement, s_RewriteDisplayMessage,
		s_RewriteDisplayMessage, &data))
	{
		dprintf("[InterceptedMapViewOfSection] PaRewriteImports failed with error 0x%08X\r\n", CbGetTEB()->LastErrorValue);
		status = STATUS_DLL_INIT_FAILED; // again, we just need some kind of error code
		goto L_abort;
	}

	return 0;

L_abort:
	statusAbort = NtUnmapViewOfSection(hProcess, *ppBaseAddress);
	if (statusAbort != 0)
		dprintf("[InterceptedMapViewOfSection] NtUnmapViewOfSection returned 0x%08X\r\n", status);
	return status;
}

static BOOL s_RewriteReadMemory(EXTERNAL_PTR pSrcBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData) {
	memcpy(pDestBuffer, pSrcBase, nSize);
	return TRUE;
}

static BOOL s_RewriteWriteMemory(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData) {
	DWORD nOldProt;

	if (!VirtualProtect(pDestBase, nSize, PAGE_EXECUTE_READWRITE, &nOldProt))
		return FALSE;

	memcpy(pDestBase, pSrcBuffer, nSize);
	return TRUE;
}

static LPCSTR s_RewriteGetDLLReplacement(LPCSTR pcszName, RewriteDataBag_p pUserData) {
	return GetPrivateProfileStringA("RedirectDLLs", pcszName, "", pUserData->szRedirDLLName, sizeof(pUserData->szRedirDLLName) - 1,
		s_szConfigPath) ? pUserData->szRedirDLLName : NULL;
}

static void s_RewriteDisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...) {
	va_list va;
	va_start(va, pcszFormat);
	dprintf("[InterceptedMapViewOfSection] [PaRewriteImports] ");
	vdprintf(pcszFormat, va);
	va_end(va);
}
