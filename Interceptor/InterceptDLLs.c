#include "InterceptDLLs.h"
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
static BOOL s_MinimalFindDLL(LPCSTR pcszName, LPSTR pszPathBuf, SIZE_T nPathBufSize);

char ConfigFilePath[MAX_PATH] = { 0 };

static NtCreateSection_t s_procRealCreateSection;
static NtMapViewOfSection_t s_procRealMapViewOfSection;
static char s_mszExcludePaths[4096];
static PaINIHandle s_hINI;

// may be called before kernel32 is loaded, can't call any kernel32 functions
BOOL ApplyLibraryLoadHooks(void) {
	NtCreateSection_t procCreateSection;
	NtMapViewOfSection_t procMapViewOfSection;
	LPSTR pszExcludePath;
	NTSTATUS status;

	if (ConfigFilePath[0] == 0) {
		// this is the only part that is not no-Kernel32 safe
		if (!PaFindConfigFileDirect("shims.ini", GetCurrentProcess(), ConfigFilePath, sizeof(ConfigFilePath))) {
			dprintf("[ApplyLibraryLoadHooks] PaFindConfigFileDirect failed with error 0x%08X\r\n", GetLastError());
			return TRUE; // no shims? ok. just don't do anything then
		}
	}

	DbgPrint("[ApplyLibraryLoadHooks] Reading config file %s\r\n", ConfigFilePath);

	status = PaINIOpen(ConfigFilePath, &s_hINI);
	if (status != 0) {
		DbgPrint("[ApplyLibraryLoadHooks] Error 0x%08X opening config file\r\n", status);
		return FALSE;
	}

	status = PaINIGetSection(s_hINI, "Exclude", s_mszExcludePaths, sizeof(s_mszExcludePaths));
	PaINIClose(s_hINI);

	if (status != 0) {
		DbgPrint("[ApplyLibraryLoadHooks] Error 0x%08X reading exclude paths\r\n", status);
		return FALSE;
	}

	CB_FOREACH_MULTISZ(pszExcludePath, s_mszExcludePaths)
		CbStringToLowerA(pszExcludePath);

#ifdef WAYS_INTERCEPT_SECTION
	procCreateSection = CbGetNTDLLFunction("NtCreateSection");
	if (procCreateSection == NULL) {
		DbgPrint("[ApplyLibraryLoadHooks] NtCreateSection not found!\r\n");
		return FALSE;
	}

	s_procRealCreateSection = PaHookSimpleFunction(procCreateSection, 16, s_InterceptedCreateSection);
	if (s_procRealCreateSection == NULL) {
		DbgPrint("[ApplyLibraryLoadHooks] PaHookSimpleFunction for NtCreateSection failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}
#endif

#ifdef WAYS_INTERCEPT_MAPPING
	procMapViewOfSection = CbGetNTDLLFunction("NtMapViewOfSection");
	if (procMapViewOfSection == NULL) {
		DbgPrint("[ApplyLibraryLoadHooks] NtMapViewOfSection not found!\r\n");
		return FALSE;
	}

	s_procRealMapViewOfSection = PaHookSimpleFunction(procMapViewOfSection, 16, s_InterceptedMapViewOfSection);
	if (s_procRealMapViewOfSection == NULL) {
		DbgPrint("[ApplyLibraryLoadHooks] PaHookSimpleFunction for NtMapViewOfSection failed with error 0x%08X\r\n", GetLastError());
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
		DbgPrint("[InterceptedCreateSection] NtQueryInformationFile on 0x%08X returned 0x%08X\r\n", (uintptr_t)hFile, status);
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
		DbgPrint("[InterceptedCreateSection] RtlUnicodeStringToAnsiString for file 0x%08X returned 0x%08X\r\n", (uintptr_t)hFile, status);
		return status;
	}

	szFilePath[asFilePath.Length] = 0;
	DbgPrint("[InterceptedCreateSection] Requested to map image %s\r\n", szFilePath);
	pszFileName = CbNormalizeModuleName(szFilePath);
	DbgPrint("[InterceptedCreateSection] Normalized module name is %s\r\n", pszFileName);

	status = PaINIGetValue(s_hINI, "RedirectDLLs", pszFileName, szReplacementName, sizeof(szReplacementName));
	if (status == 0) {
		DbgPrint("[InterceptedCreateSection] Replacement with %s requested\r\n", szReplacementName);

		if (!s_MinimalFindDLL(szReplacementName, szReplacementPath, sizeof(szReplacementPath))) {
			DbgPrint("[InterceptedCreateSection] Could not find DLL!\r\n");
			return STATUS_NO_SUCH_FILE;
		}

		status = CbCreateFileNT(szReplacementPath, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, OPEN_EXISTING, 0, &hFile);
		if (status != 0) {
			DbgPrint("[InterceptedCreateSection] Error 0x%08X opening module file\r\n", status);
			return status;
		}

		bDidOpenFile = TRUE;
	} else if (status != STATUS_NOT_FOUND)
		DbgPrint("[InterceptedCreateSection] PaINIGetValue returned status 0x%08X\r\n", status);

	DbgPrint("[InterceptedCreateSection] Calling NtCreateSection\r\n");
	status = s_procRealCreateSection(phSection, access, attrib, pnMaxSize, nProtection, nAllocAttribs, hFile);
	DbgPrint("[InterceptedCreateSection] NtCreateSection returned 0x%08X\r\n", status);

	// don't worry, creating a section keeps it open as long as the section exists
	if (bDidOpenFile) NtClose(hFile);

	return status;
}

static NTSTATUS __stdcall s_InterceptedMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection)
{
	NTSTATUS status;
	SECTION_IMAGE_INFORMATION infImageSection;

	DbgPrint("[InterceptedMapViewOfSection] Requested to map section 0x%08X in process 0x%08X\r\n", hSection, hProcess);

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
	ULONG nResultSize;
	LPSTR pszExcludePath;
	int* pnNoRedirectMarker;
	CHAR szNameAscBuffer[MAX_PATH + 1];

	RtlSecureZeroMemory(&data, sizeof(data));

	status = s_procRealMapViewOfSection(hSection, hProcess, ppBaseAddress, nZeroBits, nCommitSize, pnSectionOffset, pnViewSize,
		nInheritDisposition, nAllocationType, nWin32Protection);
	if (CB_NT_FAILED(status)) {
		DbgPrint("[InterceptedMapViewOfSection] RealMapViewOfSection returned 0x%08X\r\n", status);
		return status;
	}

	DbgPrint("[InterceptedMapViewOfSection] Section mapped at 0x%08X\r\n", *ppBaseAddress);

	pnNoRedirectMarker = CbGetSymbolAddress(*ppBaseAddress, "NoRedirectImports");
	if ((pnNoRedirectMarker != NULL) && (*pnNoRedirectMarker == 1)) {
		DbgPrint("[InterceptedMapViewOfSection] Module excluded from import table rewrite (NoRedirectImports=1)\r\n");
		return 0;
	}

	status = CbGetSectionName(hProcess, *ppBaseAddress, szNameAscBuffer, sizeof(szNameAscBuffer));
	if (status != 0) {
		DbgPrint("[InterceptedMapViewOfSection] CbGetSectionName returned 0x%08X\r\n", status);
		return status;
	}

	CbStringToLowerA(szNameAscBuffer);
	DbgPrint("[InterceptedMapViewOfSection] Module path: %s\r\n", szNameAscBuffer);

	CB_FOREACH_MULTISZ(pszExcludePath, s_mszExcludePaths) {
		if (strstr(szNameAscBuffer, pszExcludePath) != NULL) {
			DbgPrint("[InterceptedMapViewOfSection] Module excluded from import table rewrite by rule: %s\r\n", pszExcludePath);
			return 0;
		}
	}
	
	if (!PaRewriteImports(*ppBaseAddress, s_RewriteReadMemory, s_RewriteWriteMemory, s_RewriteGetDLLReplacement, s_RewriteDisplayMessage,
		s_RewriteDisplayMessage, &data))
	{
		DbgPrint("[InterceptedMapViewOfSection] PaRewriteImports failed with error 0x%08X\r\n", CbGetTEB()->LastErrorValue);
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
	NTSTATUS status;
	PVOID pProtectBase;
	SIZE_T nToProtect;
	ULONG nOldProtection;

	pProtectBase = pDestBase; nToProtect = nSize; nOldProtection = 0;
	status = NtProtectVirtualMemory(CB_CURRENT_PROCESS, &pProtectBase, &nToProtect, PAGE_EXECUTE_READWRITE, &nOldProtection);
	if (status != 0) {
		DbgPrint("[RewriteVirtualMemory] NtProtectVirtualMemory returned status 0x%08X setting %u bytes at 0x%08X to RWX\r\n",
			status, pDestBase, nSize);
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	memcpy(pDestBase, pSrcBuffer, nSize);
	return TRUE;
}

static LPCSTR s_RewriteGetDLLReplacement(LPCSTR pcszName, RewriteDataBag_p pUserData) {
	NTSTATUS status;

	status = PaINIGetValue(s_hINI, "RedirectDLLs", pcszName, pUserData->szRedirDLLName, sizeof(pUserData->szRedirDLLName));

	switch (status) {
	case 0:
		return pUserData->szRedirDLLName;

	case STATUS_NOT_FOUND:
		return NULL;

	default:
		DbgPrint("[RewriteGetDLLReplacement] PaINIGetValue returned status 0x%08X\r\n", status);
		return NULL;
	}	
}

static void s_RewriteDisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...) {
	va_list va;
	va_start(va, pcszFormat);
	DbgPrint("[InterceptedMapViewOfSection] [PaRewriteImports] ");
	vdprintf(pcszFormat, va);
	va_end(va);
}

static BOOL s_AppendAndCheck(LPCSTR pcszName, LPSTR pszPathBuf, SIZE_T nPathBufSize) {
	size_t nPathLen;

	nPathLen = strlen(pszPathBuf);
	if ((nPathLen + strlen(pcszName) + 1) >= nPathBufSize)
		return FALSE;

	if (pszPathBuf[nPathLen - 1] != '\\')
		strcat(pszPathBuf, "\\");
	strcat(pszPathBuf, pcszName);

	return PaDoesFileExist(pszPathBuf);
}

static BOOL s_MinimalFindDLL(LPCSTR pcszName, LPSTR pszPathBuf, SIZE_T nPathBufSize) {
	NTSTATUS status;
	SECTION_IMAGE_INFORMATION infSection;
	LPSTR pszFileName;

	// executable directory
	do {
		status = CbGetSectionName(CB_CURRENT_PROCESS, ((PPEB_FULL)CbGetPEB())->ImageBaseAddress, pszPathBuf, nPathBufSize);
		if (status != 0) break;

		if (s_AppendAndCheck(pcszName, pszPathBuf, nPathBufSize))
			return TRUE;
	} while (0);

	// current directory
	do {
		status = CbGetCurrentDirectoryNT(pszPathBuf, nPathBufSize);
		if (status != 0) break;

		if (s_AppendAndCheck(pcszName, pszPathBuf, nPathBufSize))
			return TRUE;
	} while (0);

	// config file directory
	do {
		if (strlen(ConfigFilePath) >= nPathBufSize) break;
		strcpy(pszPathBuf, ConfigFilePath);

		pszFileName = CbPathGetFilenameA(pszPathBuf);
		if (pszFileName == NULL) break;
		*pszFileName = 0;

		if (s_AppendAndCheck(pcszName, pszPathBuf, nPathBufSize))
			return TRUE;
	} while (0);

	return FALSE;
}
