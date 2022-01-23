#pragma once

#ifndef HEADER_CONFIGREADING
#define HEADER_CONFIGREADING

#define _X86_
#include <minwindef.h>

// check next to target (if not null) and next to self
BOOL PaFindConfigFile(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize);

// check next to target only (target may be self)
BOOL PaFindConfigFileDirect(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize);

BOOL PaGetProcessExecutablePath(HANDLE hProcess, char* pszPathBuffer, size_t nBufSize);

// using DLL search order, finds a path that CreateFile works on
BOOL PaFindModulePath(const char* pcszName, char* pszPathBuffer, size_t nBufSize);

BOOL PaDoesFileExist(const char* pcszFilePath);

// gets the preferred Win32 path for a volume (usually a drive letter)
BOOL PaGetVolumeWin32Path(const char* pcszNTName, char* pszPathBuffer, size_t nBufSize);

#endif
