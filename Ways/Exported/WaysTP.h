#pragma once

#ifndef HEADER_WAYSTP
#define HEADER_WAYSTP

#ifndef MAGICWAYS_EXPORTED
#ifdef MAGICWAYS_BUILD
#define MAGICWAYS_EXPORTED __declspec(dllexport) __stdcall
#else
#define MAGICWAYS_EXPORTED __declspec(dllimport) __stdcall
#endif
#endif

#define _X86_
#include <minwindef.h>

HANDLE MAGICWAYS_EXPORTED MwGetPoolThread(void);
void MAGICWAYS_EXPORTED MwReturnPoolThread(HANDLE hThread);

DWORD MAGICWAYS_EXPORTED MwAPCProcessingThreadProc(PVOID pParams);

#endif
