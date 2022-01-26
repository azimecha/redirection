#pragma once

#ifndef HEADER_INJECTDLL
#define HEADER_INJECTDLL

#include "RewriteImports.h"

typedef struct _struct_PaModule* PaModuleHandle;

// Provides the ability to examine DLLs without loading (unless already loaded)
PaModuleHandle PaModuleOpen(LPCSTR pcszDLLName, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError, LPVOID pUserData);
LPVOID PaModuleGetBaseAddress(PaModuleHandle hModule);
LPCSTR PaModuleGetFilePath(PaModuleHandle hModule);
void PaModuleClose(PaModuleHandle hModule);

EXTERNAL_PTR PaInjectWithoutLoad(PaModuleHandle hModule, HANDLE hTargetProcess);
EXTERNAL_PTR PaGetRemoteSymbol(PaModuleHandle hModule, EXTERNAL_PTR pBaseAddress, LPCSTR pcszSymbolName);

#endif
