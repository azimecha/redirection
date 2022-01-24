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

	hINIFile = CreateFileA(pszPathBuffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	CloseHandle(hINIFile);

	return hINIFile != INVALID_HANDLE_VALUE;
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

BOOL PaDoesFileExist(const char* pcszFilePath) {
	HANDLE hFile;

	hFile = CreateFileA(pcszFilePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	CloseHandle(hFile);

	return hFile != INVALID_HANDLE_VALUE;
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
