#include "Intercept.h"
#include <HookFunction.h>
#include <NTDLL.h>
#include <PartialStdio.h>
#include <FilePaths.h>
#include <ConfigReading.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static NTSTATUS __stdcall s_InterceptedCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile);
static NTSTATUS __stdcall s_InterceptedImageCreateSection(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile);

static NtCreateSection_t s_procRealCreateSection;
static char s_szConfigPath[MAX_PATH];

BOOL ApplyLoadingHooks(void) {
	NtCreateSection_t procCreateSection;

	// would prefer not to do this while holding the loader lock...
	if (!PaFindConfigFileDirect("shims.ini", GetCurrentProcess(), s_szConfigPath, sizeof(s_szConfigPath))) {
		dprintf("[ApplyLoadingHooks] PaFindConfigFileDirect failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}

	// ... but it's important for this part
	procCreateSection = CbGetNTDLLFunction("NtCreateSection");
	if (procCreateSection == NULL) {
		dprintf("[ApplyLoadingHooks] NtCreateSection not found!\r\n");
		return FALSE;
	}

	s_procRealCreateSection = PaHookSimpleFunction(procCreateSection, 16, s_InterceptedCreateSection);
	if (s_procRealCreateSection == NULL) {
		dprintf("[ApplyLoadingHooks] PaHookSimpleFunction failed with error 0x%08X\r\n", GetLastError());
		return FALSE;
	}

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

	pszFileName = (char*)CbPathGetFilenameA(szFilePath);
	CbPathRemoveExtensionA(pszFileName);
	CbStringToLowerA(pszFileName);
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
	}

	dprintf("[InterceptedCreateSection] Calling NtCreateSection\r\n");
	status = s_procRealCreateSection(phSection, access, attrib, pnMaxSize, nProtection, nAllocAttribs, hFile);
	dprintf("[InterceptedCreateSection] NtCreateSection returned 0x%08X\r\n", status);

	// don't worry, creating a section keeps it open as long as the section exists
	if (bDidOpenFile) CloseHandle(hFile);
	return status;
}