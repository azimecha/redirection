#include "HookFunction.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string.h>
#include <NTDLL.h>

static HANDLE s_GetCodeHeap(void);

LPVOID PaHookSimpleFunction(LPVOID pFunction, SIZE_T nSize, LPVOID pHook) {
	LPVOID pCopy;
	HANDLE hCodeHeap;
	BOOL bSucceded;
	DWORD nError;

	bSucceded = FALSE;

	if (nSize < sizeof(PaHookCode_t))
		return FALSE;

	// create duplicate of original code
	hCodeHeap = s_GetCodeHeap();
	if (hCodeHeap == NULL) return FALSE;
	
	pCopy = HeapAlloc(hCodeHeap, 0, nSize);
	if (pCopy == NULL) return FALSE;

	memcpy(pCopy, pFunction, nSize);

	// replace function
	bSucceded = PaReplaceFunction(pFunction, pHook);

	if (!bSucceded) {
		nError = GetLastError();
		HeapFree(hCodeHeap, 0, pCopy);
		SetLastError(nError);
	}
	return bSucceded ? pCopy : NULL;
}

BOOL PaReplaceFunction(LPVOID pFunction, LPVOID pNewFunction) {
	PaHookCode_p pHookCode;
	DWORD nOldProt;
	NTSTATUS status;

	// put hook at original location
	if (!VirtualProtect(pFunction, sizeof(PaHookCode_t), PAGE_EXECUTE_READWRITE, &nOldProt))
		return FALSE;

	pHookCode = (PaHookCode_p)pFunction;
	pHookCode->instrPush = PA_HOOK_INSTR_PUSH;
	pHookCode->pJumpAddr = pNewFunction;
	pHookCode->instrRet = PA_HOOK_INSTR_RET;

	status = NtFlushInstructionCache(GetCurrentProcess(), pHookCode, sizeof(PaHookCode_t));
	if (status != 0) {
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

	return TRUE;
}

BOOL PaReplaceFunctionEx(HANDLE hProcess, EXTERNAL_PTR pFunction, EXTERNAL_PTR pNewFunction, OUT OPTIONAL LPVOID pRemovedCodeBuf) {
	DWORD nOldProt, nBytesRW;
	PaHookCode_t hook;

	if (!VirtualProtectEx(hProcess, pFunction, PA_REPLACEFUNC_CODESIZE, PAGE_EXECUTE_READWRITE, &nOldProt))
		return FALSE;

	if (pRemovedCodeBuf != NULL) {
		if (!ReadProcessMemory(hProcess, pFunction, pRemovedCodeBuf, PA_REPLACEFUNC_CODESIZE, &nBytesRW))
			return FALSE;
	}

	hook.instrPush = PA_HOOK_INSTR_PUSH;
	hook.pJumpAddr = pNewFunction;
	hook.instrRet = PA_HOOK_INSTR_RET;

	if (!WriteProcessMemory(hProcess, pFunction, &hook, PA_REPLACEFUNC_CODESIZE, &nBytesRW))
		return FALSE;

	if (!FlushInstructionCache(hProcess, pFunction, PA_REPLACEFUNC_CODESIZE))
		return FALSE;

	return TRUE;
}

// generated for every use... only an issue if you RMW wrong
#pragma warning(disable:28112)

static HANDLE s_GetCodeHeap(void) {
	static volatile HANDLE hHeap = NULL;
	HANDLE hNewHeap;

	if (hHeap == NULL) {
		hNewHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
		if (hNewHeap == NULL)
			return hHeap;

		if (InterlockedCompareExchangePointer(&hHeap, hNewHeap, NULL) != NULL)
			HeapDestroy(hNewHeap);
	}

	return hHeap;
}
