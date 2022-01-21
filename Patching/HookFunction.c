#include "HookFunction.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string.h>

#define PA_HOOK_INSTR_CALL 0xE8
#define PA_HOOK_INSTR_JMP 0xE9
#define PA_HOOK_INSTR_PUSH 0x68
#define PA_HOOK_INSTR_RET 0xC3

#pragma pack(1)
typedef struct _struct_PaHookCode {
	BYTE instrPush;
	LPVOID pJumpAddr;
	BYTE instrRet;
} PaHookCode_t, *PaHookCode_p;
#pragma pack()

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

	// put hook at original location
	if (!VirtualProtect(pFunction, sizeof(PaHookCode_t), PAGE_EXECUTE_READWRITE, &nOldProt))
		return FALSE;

	pHookCode = (PaHookCode_p)pFunction;
	pHookCode->instrPush = PA_HOOK_INSTR_PUSH;
	pHookCode->pJumpAddr = pNewFunction;
	pHookCode->instrRet = PA_HOOK_INSTR_RET;

	if (!FlushInstructionCache(GetCurrentProcess(), pHookCode, sizeof(PaHookCode_t)))
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
