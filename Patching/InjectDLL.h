#pragma once

#ifndef HEADER_INJECTDLL
#define HEADER_INJECTDLL

#include "RewriteImports.h"

typedef struct _struct_PaModule* PaModuleHandle;
typedef EXTERNAL_PTR* PEXTERNAL_PTR;
typedef EXTERNAL_PTR** PPEXTERNAL_PTR;
typedef struct _PEB* PPEB;

// Provides the ability to examine DLLs without loading (unless already loaded)
PaModuleHandle PaModuleOpen(LPCSTR pcszDLLName, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError, LPVOID pUserData);
LPVOID PaModuleGetBaseAddress(PaModuleHandle hModule);
LPCSTR PaModuleGetFilePath(PaModuleHandle hModule);
PIMAGE_NT_HEADERS PaModuleGetNTHeaders(PaModuleHandle hModule);
void PaModuleClose(PaModuleHandle hModule);

EXTERNAL_PTR PaInjectWithoutLoad(PaModuleHandle hModule, HANDLE hTargetProcess, BOOL bRegisterAsLoaded);
EXTERNAL_PTR PaGetRemoteSymbol(PaModuleHandle hModule, EXTERNAL_PTR pBaseAddress, LPCSTR pcszSymbolName);
BOOL PaGetProcessEnvBlock(HANDLE hTargetProcess, PPEB ppeb);

// returns heap allocated buffer
LPVOID PaReadListItems(SIZE_T nItemSize, SIZE_T nListEntryOffset, EXTERNAL_PTR xpAnyItem, PaReadMemoryProc procReadMemory, LPVOID pUserData,
	PSIZE_T pnItemCount, OPTIONAL EXTERNAL_PTR** ppxpItemAddresses /* if nonzero, will be set to another heap alloc'd buffer */);
void PaFreeListItems(LPVOID pListItems);

#endif
