#include "HookFunction.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string.h>
#include <NTDLL.h>

static HANDLE s_GetCodeHeap(void);

// does not require kernel32
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
	
	pCopy = RtlAllocateHeap(hCodeHeap, 0, nSize);
	if (pCopy == NULL) return FALSE;

	memcpy(pCopy, pFunction, nSize);

	// replace function
	bSucceded = PaReplaceFunction(pFunction, pHook);

	if (!bSucceded) {
		nError = CbLastWinAPIError;
		RtlFreeHeap(hCodeHeap, 0, pCopy);
		CbLastWinAPIError = nError;
	}

	return bSucceded ? pCopy : NULL;
}

// does not require kernel32
BOOL PaReplaceFunction(LPVOID pFunction, LPVOID pNewFunction) {
	PaHookCode_p pHookCode;
	NTSTATUS status;
	PVOID pToProtect;
	SIZE_T nToProtect;
	ULONG nOldProtect;

	// put hook at original location
	/*if (!VirtualProtect(pFunction, sizeof(PaHookCode_t), PAGE_EXECUTE_READWRITE, &nOldProt))
		return FALSE;*/
	
	pToProtect = pFunction; nToProtect = sizeof(PaHookCode_t);
	status = NtProtectVirtualMemory(CB_CURRENT_PROCESS, &pToProtect, &nToProtect, PAGE_EXECUTE_READWRITE, &nOldProtect);
	if (status != 0) {
		CbLastWinAPIError = RtlNtStatusToDosError(status);
		return FALSE;
	}

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

// requires kernel32
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

// does not require kernel32
static HANDLE s_GetCodeHeap(void) {
	static volatile HANDLE hHeap = NULL;
	HANDLE hNewHeap;
	PVOID pCodeArea;
	ULONG nCodeAreaSize;
	NTSTATUS status;

	if (hHeap == NULL) {
		pCodeArea = NULL;
		nCodeAreaSize = 0xFFFF;
		status = NtAllocateVirtualMemory(CB_CURRENT_PROCESS, &pCodeArea, 0, &nCodeAreaSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (status != 0) {
			CbLastWinAPIError = RtlNtStatusToDosError(status);
			return hHeap;
		}

		hNewHeap = RtlCreateHeap(0, pCodeArea, nCodeAreaSize, 0, NULL, NULL);
		if (hNewHeap == NULL) {
			CbLastWinAPIError = ERROR_GEN_FAILURE;
			return hHeap;
		}

		if (InterlockedCompareExchangePointer(&hHeap, hNewHeap, NULL) != NULL) {
			RtlDestroyHeap(hNewHeap);
			nCodeAreaSize = 0;
			NtFreeVirtualMemory(CB_CURRENT_PROCESS, &pCodeArea, &nCodeAreaSize, MEM_RELEASE);
		}
	}

	return hHeap;
}
