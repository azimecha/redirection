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

#if 0
// file must exist for this function to work
BOOL CbNtPathToWinPath(const char* pcszNTPath, char* pszWinPath, size_t nBufSize);
#endif

#endif
