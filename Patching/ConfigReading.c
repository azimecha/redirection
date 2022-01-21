#include "ConfigReading.h"
#include "FilePaths.h"
#include "ImportHelper.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

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

#define CB_CONFIGREADING_NTPREFIX "\\\\.\\"
#define CB_CONFIGREADING_NTREMOVE "\\Device\\"

BOOL PaGetProcessExecutablePath(HANDLE hProcess, char* pszPathBuffer, size_t nBufSize) {
	if (nBufSize < sizeof(CB_CONFIGREADING_NTPREFIX))
		return FALSE;

	strcpy(pszPathBuffer, CB_CONFIGREADING_NTPREFIX);

	if (!GetProcessImageFileNameA(hProcess, pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, nBufSize - (sizeof(CB_CONFIGREADING_NTPREFIX) - 1)))
		return FALSE;

	if (memcmp(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, CB_CONFIGREADING_NTREMOVE, sizeof(CB_CONFIGREADING_NTREMOVE) - 1) != 0)
		return FALSE;

	memmove(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) + sizeof(CB_CONFIGREADING_NTREMOVE) - 2,
		strlen(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) + sizeof(CB_CONFIGREADING_NTREMOVE) - 2) + 1);

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
