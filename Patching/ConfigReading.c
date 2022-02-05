#include "ConfigReading.h"
#include "FilePaths.h"
#include "ImportHelper.h"
#include <NTDLL.h>
#include <PartialStdio.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>

static void* s_INIAllocate(void* pUnused, size_t nSize);
static void s_INIFree(void* pUnused, void* pBlock);

#define INI_MALLOC(c,s) s_INIAllocate((c), (s))
#define INI_FREE(c,p) s_INIFree((c), (p))
#define INI_IMPLEMENTATION
#include "ini.h"

static LPVOID s_pINIHeap = NULL;

BOOL PaFindConfigFile(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize) {
	return PaFindConfigFileDirect(pcszFileName, hTargetProcess, pszPathBuffer, nBufSize)
		|| PaFindConfigFileDirect(pcszFileName, GetCurrentProcess(), pszPathBuffer, nBufSize);
}

BOOL PaFindConfigFileDirect(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize) {
	HANDLE hINIFile;
	LPSTR pszFilenameStart;

	if (!PaGetProcessExecutablePath(hTargetProcess, pszPathBuffer, nBufSize - strlen(pcszFileName)))
		return FALSE;

	pszFilenameStart = (LPSTR)CbPathGetFilenameA(pszPathBuffer);
	if (pszFilenameStart == NULL)
		return FALSE;
	*pszFilenameStart = 0;

	strcat(pszPathBuffer, pcszFileName);
	return PaDoesFileExist(pszPathBuffer);
}

#define CB_CONFIGREADING_NTDEVICE "\\Device\\"

BOOL PaGetProcessExecutablePath(HANDLE hProcess, char* pszPathBuffer, size_t nBufSize) {
	char szNTPath[MAX_PATH * 2];
	LPSTR pszPathPart;

	// get the raw NT path
	if (!GetProcessImageFileNameA(hProcess, szNTPath, sizeof(szNTPath)))
		return FALSE;

	// make sure it looks like it should (starts with \Device\)
	if (!CbStringStartsWithIA(szNTPath, CB_CONFIGREADING_NTDEVICE)) {
		SetLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}

	// find the start of the actual file path: the next slash after \Device\HarddiskPartitionX
	// this will have issues if Windows gives us something like \Device\HarddiskY\PartitionZ but that hasn't been observed
	pszPathPart = strchr(szNTPath + sizeof(CB_CONFIGREADING_NTDEVICE), '\\');
	if (pszPathPart == NULL) {
		SetLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}

	// replace the \ after the \Device\HarddiskPartitionX part with a null
	// before that is the volume NT path, after that is the file path sans slash
	*pszPathPart = 0; pszPathPart++;

	// get the Win32 ("DOS") path for \Device\HarddiskPartitionX
	if (!PaGetVolumeWin32Path(szNTPath, pszPathBuffer, nBufSize))
		return FALSE;

	// stick the file path back on
	if (!strccat(pszPathBuffer, nBufSize, "\\") || !strccat(pszPathBuffer, nBufSize, pszPathPart)) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	return TRUE;
}

static BOOL s_FMPTryAppDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize);
static BOOL s_FMPTryCurDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize);
static BOOL s_FMPTrySys32Dir(const char* pcszName, char* pszPathBuffer, size_t nBufSize);
static BOOL s_FMPTrySys16Dir(const char* pcszName, char* pszPathBuffer, size_t nBufSize);
static BOOL s_FMPTryWinDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize);
static BOOL s_FMPTryPathDirs(const char* pcszName, char* pszPathBuffer, size_t nBufSize);

static void s_RemoveFilename(char* pszBuffer);
static BOOL s_FMPAddFilenameAndTry(const char* pcszName, char* pszPathBuffer);

BOOL PaFindModulePath(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	// if it can't even fit we're not going to ever "find" it
	if (strlen(pcszName) >= nBufSize)
		return FALSE;

	// exact path
	if (PaDoesFileExist(pcszName)) {
		strcpy(pszPathBuffer, pcszName);
		return TRUE;
	}

	// The directory from which the application loaded.
	if (s_FMPTryAppDir(pcszName, pszPathBuffer, nBufSize)) return TRUE;

	// The current directory.
	if (s_FMPTryCurDir(pcszName, pszPathBuffer, nBufSize)) return TRUE;

	// The system directory.
	if (s_FMPTrySys32Dir(pcszName, pszPathBuffer, nBufSize)) return TRUE;

	// The 16-bit system directory.
	if (s_FMPTrySys16Dir(pcszName, pszPathBuffer, nBufSize)) return TRUE;

	// The Windows directory.
	if (s_FMPTryWinDir(pcszName, pszPathBuffer, nBufSize)) return TRUE;

	// The directories that are listed in the PATH environment variable.
	return s_FMPTryPathDirs(pcszName, pszPathBuffer, nBufSize);
}

static BOOL s_FMPTryAppDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	if (!PaGetProcessExecutablePath(GetCurrentProcess(), pszPathBuffer, nBufSize - strlen(pcszName)))
		return FALSE;

	s_RemoveFilename(pszPathBuffer);
	return s_FMPAddFilenameAndTry(pcszName, pszPathBuffer);
}

static BOOL s_FMPTryCurDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	if (!GetCurrentDirectoryA(nBufSize - (strlen(pcszName) + 1), pszPathBuffer))
		return FALSE;

	return s_FMPAddFilenameAndTry(pcszName, pszPathBuffer);
}

static BOOL s_FMPTrySys32Dir(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	if (!GetSystemDirectoryA(pszPathBuffer, nBufSize - (strlen(pcszName) + 1)))
		return FALSE;

	return s_FMPAddFilenameAndTry(pcszName, pszPathBuffer);
}

static const char s_cszSysDirName[] = "\\SYSTEM";

static BOOL s_FMPTrySys16Dir(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	if (!GetWindowsDirectoryA(pszPathBuffer, nBufSize - (strlen(pcszName) + sizeof(s_cszSysDirName))))
		return FALSE;

	strcat(pszPathBuffer, s_cszSysDirName);
	return s_FMPAddFilenameAndTry(pcszName, pszPathBuffer);
}

static BOOL s_FMPTryWinDir(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	if (!GetWindowsDirectoryA(pszPathBuffer, nBufSize - (strlen(pcszName) + 1)))
		return FALSE;

	return s_FMPAddFilenameAndTry(pcszName, pszPathBuffer);
}

static BOOL s_FMPTryPathDirs(const char* pcszName, char* pszPathBuffer, size_t nBufSize) {
	return FALSE; // TODO
}

static void s_RemoveFilename(char* pszBuffer) {
	char* pszFilenamePart;
	pszFilenamePart = (char*)CbPathGetFilenameA(pszBuffer);
	if (!pszFilenamePart) return;
	pszFilenamePart[-1] = 0;
}

static BOOL s_FMPAddFilenameAndTry(const char* pcszName, char* pszPathBuffer) {
	strcat(pszPathBuffer, "\\");
	strcat(pszPathBuffer, pcszName);
	return PaDoesFileExist(pszPathBuffer);
}

// no kernel32 calls
BOOL PaDoesFileExist(const char* pcszFilePath) {
	WCHAR wzFilePath[MAX_PATH + 1];

	if (mbstowcs(wzFilePath, pcszFilePath, RTL_NUMBER_OF_V2(wzFilePath)) == -1) {
		CbLastWinAPIError = ERROR_INSUFFICIENT_BUFFER;
		return FALSE;
	}

	return RtlDoesFileExists_U(wzFilePath);
}

#pragma warning(disable:28112)

typedef HRESULT(__stdcall* FilterGetDosName_t)(LPCWSTR pcwzVolumeName, LPWSTR pwzDOSNameOUT, DWORD nBufSize);

BOOL PaGetVolumeWin32Path(const char* pcszNTName, char* pszPathBuffer, size_t nBufSize) {
	static volatile HMODULE hFilterLib;
	static FilterGetDosName_t procFilterGetDosName;
	HMODULE hNewFilterLib;
	WCHAR wzNTName[MAX_PATH + 1];
	WCHAR wzDOSName[MAX_PATH + 1];
	UNICODE_STRING usNTName, usDOSName;
	ANSI_STRING asNTName, asDOSName;
	NTSTATUS status;
	HRESULT hr;

	if (nBufSize > UINT16_MAX)
		nBufSize = UINT16_MAX;

	// convert NT name to unicode

	asNTName.Buffer = (char*)pcszNTName;
	asNTName.Length = (USHORT)strlen(pcszNTName);
	asNTName.MaximumLength = asNTName.Length;

	usNTName.Buffer = wzNTName;
	usNTName.Length = 0;
	usNTName.MaximumLength = sizeof(wzNTName) - sizeof(WCHAR);

	status = RtlAnsiStringToUnicodeString(&usNTName, &asNTName, FALSE);
	if (status != 0) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}

	// find and call function

	if (hFilterLib == NULL) {
		hNewFilterLib = LoadLibraryA("fltlib.dll");
		if (hNewFilterLib == NULL) return FALSE;

		if (InterlockedCompareExchangePointer(&hFilterLib, hNewFilterLib, NULL) != NULL)
			FreeLibrary(hNewFilterLib);
	}

	if (procFilterGetDosName == NULL) {
		procFilterGetDosName = (FilterGetDosName_t)GetProcAddress(hFilterLib, "FilterGetDosName");
		if (procFilterGetDosName == NULL) return FALSE;
	}

	hr = procFilterGetDosName(wzNTName, wzDOSName, RTL_NUMBER_OF_V2(wzDOSName));
	if (FAILED(hr)) {
		SetLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}

	// convert DOS name to ansi

	usDOSName.Buffer = wzDOSName;
	usDOSName.Length = lstrlenW(wzDOSName) * sizeof(WCHAR);
	usDOSName.MaximumLength = sizeof(wzDOSName) - sizeof(WCHAR);

	asDOSName.Buffer = pszPathBuffer;
	asDOSName.Length = (USHORT)nBufSize;
	asDOSName.MaximumLength = (USHORT)nBufSize;

	status = RtlUnicodeStringToAnsiString(&asDOSName, &usDOSName, FALSE);
	if (status != 0) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}

	return TRUE;
}

// no kernel32 calls
DWORD PaINIOpen(LPCSTR pcszPath, OUT PaINIHandle* phINI) {
	HANDLE hFile = NULL, hSection = NULL;
	NTSTATUS status = 0;
	SIZE_T nFileSize = 0;
	LPSTR psINIData = NULL;
	LPVOID pNewINIHeap = NULL;
	LPSTR pszCurData = NULL;

	if (pcszPath == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (phINI == NULL)
		return STATUS_INVALID_PARAMETER_2;

	if (s_pINIHeap == NULL) {
		pNewINIHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
		if ((pNewINIHeap == NULL) && s_pINIHeap == NULL)
			return STATUS_NO_MEMORY;

		if (InterlockedCompareExchangePointer(&s_pINIHeap, pNewINIHeap, NULL) != NULL)
			RtlDestroyHeap(pNewINIHeap);
	}

	status = CbCreateFileNT(pcszPath, GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, &hFile);
	if (status > 0x0FFFFFFF) goto L_exit;

	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_COMMIT, hFile);
	if (status != 0) goto L_exit;

	status = NtMapViewOfSection(hSection, CB_CURRENT_PROCESS, (PVOID*)&psINIData, 0, 0, NULL, &nFileSize, ViewUnmap, 0, PAGE_WRITECOPY);
	if (status != 0) goto L_exit;
	
	// ensure null terminated - file must end with a null or a newline
	if (psINIData[nFileSize - 1] == '\0')
		; // ok
	else if (psINIData[nFileSize - 2] == '\r' && psINIData[nFileSize - 1] == '\n')
		psINIData[nFileSize - 2] = '\0'; // also ok, replace newline with null
	else if (psINIData[nFileSize - 1] == '\n')
		psINIData[nFileSize - 1] = '\0'; // same but LF
	else {
		status = STATUS_FILE_CORRUPT_ERROR;
		goto L_exit;
	}

	// make LF-only - extra blank lines won't be an issue
	for (pszCurData = psINIData; *pszCurData; pszCurData++)
		if (*pszCurData == '\r')
			*pszCurData = '\n';

	// parse
	*phINI = (PaINIHandle)ini_load(psINIData, NULL);
	if (*phINI == NULL) {
		status = STATUS_FILE_CORRUPT_ERROR;
		goto L_exit;
	}

	status = 0;

L_exit:
	if (psINIData != NULL) 
		NtUnmapViewOfSection(CB_CURRENT_PROCESS, psINIData);
	if (hFile != NULL)
		NtClose(hFile);
	if (hSection != NULL)
		NtClose(hSection);
	return status;
}

// no kernel32 calls
DWORD PaINIGetSection(PaINIHandle hINI, LPCSTR pcszSectionName, OUT LPSTR pszSectionBuf, size_t nBufSize) {
	LPCSTR pcszPropName, pcszPropValue;
	int nSection, nProperties, nProperty;

	if (hINI == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (pcszSectionName == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pszSectionBuf == NULL)
		return STATUS_INVALID_PARAMETER_3;

	nSection = ini_find_section((ini_t*)hINI, pcszSectionName, strlen(pcszSectionName));
	if (nSection == INI_NOT_FOUND)
		return STATUS_NOT_FOUND;

	// loop through properties (KVPs) in section
	nProperties = ini_property_count((ini_t*)hINI, nSection);
	for (nProperty = 0; nProperty < nProperties; nProperty++) {
		// read key & value
		pcszPropName = ini_property_name((ini_t*)hINI, nSection, nProperty);
		pcszPropValue = ini_property_value((ini_t*)hINI, nSection, nProperty);

		// append key
		if ((pcszPropName != NULL) && (pcszPropName[0] != '\0')) {
			if (!CbTryAppendToBufferA(&pszSectionBuf, &nBufSize, pcszPropName))
				return STATUS_BUFFER_TOO_SMALL;
			if (!CbTryAppendToBufferA(&pszSectionBuf, &nBufSize, "="))
				return STATUS_BUFFER_TOO_SMALL;
		}

		// append value
		if (pcszPropValue != NULL)
			if (!CbTryAppendToBufferA(&pszSectionBuf, &nBufSize, pcszPropValue))
				return STATUS_BUFFER_TOO_SMALL;

		// null terminator
		if ((pcszPropName != NULL) || (pcszPropValue != NULL)) {
			if (nBufSize == 0)
				return STATUS_BUFFER_TOO_SMALL;
			*pszSectionBuf = '\0';
			pszSectionBuf++; nBufSize--;
		}
	}

	// double null terminate
	if (nBufSize == 0)
		return STATUS_BUFFER_TOO_SMALL;
	*pszSectionBuf = '\0';
	pszSectionBuf++; nBufSize--;

	return 0;
}

// no kernel32 calls
DWORD PaINIGetValue(PaINIHandle hINI, LPCSTR pcszSectionName, LPCSTR pcszValueName, OUT LPSTR pszValueBuf, size_t nBufSize) {
	LPCSTR pcszPropValue;
	int nSection, nProperty;

	if (hINI == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (pcszSectionName == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pszValueBuf == NULL)
		return STATUS_INVALID_PARAMETER_3;

	nSection = ini_find_section((ini_t*)hINI, pcszSectionName, strlen(pcszSectionName));
	if (nSection == INI_NOT_FOUND)
		return STATUS_NOT_FOUND;

	nProperty = ini_find_property((ini_t*)hINI, nSection, pcszValueName, strlen(pcszValueName));
	if (nProperty == INI_NOT_FOUND)
		return STATUS_NOT_FOUND;

	pcszPropValue = ini_property_value((ini_t*)hINI, nSection, nProperty);
	if (!CbTryAppendToBufferA(&pszValueBuf, &nBufSize, pcszPropValue))
		return STATUS_BUFFER_TOO_SMALL;

	return 0;
}

// no kernel32 calls
void PaINIClose(PaINIHandle hINI) {
	if (hINI != NULL)
		ini_destroy((ini_t*)hINI);
}

// no kernel32 calls
static void* s_INIAllocate(void* pUnused, size_t nSize) {
	return RtlAllocateHeap(s_pINIHeap, 0, nSize);
}

// no kernel32 calls
static void s_INIFree(void* pUnused, void* pBlock) {
	RtlFreeHeap(s_pINIHeap, 0, pBlock);
}
