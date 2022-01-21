#pragma once

#ifndef HEADER_REWRITEIMPORTS
#define HEADER_REWRITEIMPORTS

#define _X86_
#include <minwindef.h>

// designates pointer possibly in another process
typedef void* EXTERNAL_PTR;

typedef BOOL(*PaReadMemoryProc)(EXTERNAL_PTR pSrcBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData);
typedef BOOL(*PaWriteMemoryProc)(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData);
typedef LPCSTR(*PaGetReplacementProc)(LPCSTR pcszName, LPVOID pUserData);
typedef void(*PaDisplayMessageProc)(LPVOID pUserData, LPCSTR pcszFormat, ...);

BOOL PaRewriteImports(EXTERNAL_PTR xpImageBase, PaReadMemoryProc procReadMemory, PaWriteMemoryProc procWriteMemory,
	PaGetReplacementProc procGetDLLReplacement, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError,
	LPVOID pUserData);

#endif
