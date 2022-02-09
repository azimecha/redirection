#include <WaysTLS.h>
#include <ImportHelper.h>
#include <NTDLL.h>
#include <intrin.h>

#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <winerror.h>

// this function is utterly useless anyway as the thread can be pre-empted right after it
DWORD __stdcall Impl_GetCurrentProcessorNumber(void) {
	return 0;
}

// if we want to implement GetCurrentProcessorNumber "better"...
// https://groups.google.com/g/microsoft.public.win32.programmer.kernel/c/IM54OPzvRgY
#if 0 // untested
static __declspec(naked) DWORD __stdcall s_GetAPICID(void) {
	__asm {
		PUSH EBX
		PUSH EDX
		MOV EAX, 1
		CPUID
		SHR EBX, 24
		MOV AL, BL
		POP EDX
		POP EBX
		RET
	}
}
#endif

// just as pointless
void __stdcall Impl_GetCurrentProcessorNumberEx(PPROCESSOR_NUMBER pNumber) {
	if (pNumber != NULL)
		memset(pNumber, 0, sizeof(PROCESSOR_NUMBER));
}

// less useless but still not really necessary
BOOL __stdcall Impl_GetThreadIdealProcessorEx(HANDLE hThread, PPROCESSOR_NUMBER pNumber) {
	if (pNumber == NULL) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	memset(pNumber, 0, sizeof(PROCESSOR_NUMBER));
	return TRUE;
}

DWORD __stdcall Impl_SetThreadIdealProcessor(HANDLE hThread, DWORD nProcessor) {
	return 0;
}

BOOL __stdcall Impl_SetThreadIdealProcessorEx(HANDLE hThread, PPROCESSOR_NUMBER pNumber, PPROCESSOR_NUMBER pPrevious) {
	if (pNumber == NULL) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (pPrevious != NULL)
		memset(pPrevious, 0, sizeof(PROCESSOR_NUMBER));

	return TRUE;
}

// actually important
#define XSTATE_FEATURE_FPU (1 << 0)
#define XSTATE_FEATURE_SSE (1 << 1)

DWORD64 __stdcall Impl_GetEnabledXStateFeatures(void) {
	DWORD64 nResult = 0;
	int arrRegs[4];

	__cpuid(arrRegs, 1); // CPUID with EAX = 1

	if (arrRegs[3] & (1 << 0)) // EDX bit 0
		nResult |= XSTATE_FEATURE_FPU; // FPU present

	if (arrRegs[3] & (1 << 25)) // EDX bit 25
		nResult |= XSTATE_FEATURE_SSE; // SSE present

	return nResult;
}

BOOL __stdcall Impl_SetXStateFeaturesMask(PCONTEXT pctx, DWORD64 mask) {
	if (pctx == NULL) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (mask & XSTATE_FEATURE_FPU)
		pctx->ContextFlags |= CONTEXT_FLOATING_POINT;

	if (mask & XSTATE_FEATURE_SSE)
		pctx->ContextFlags |= CONTEXT_EXTENDED_REGISTERS;

	return TRUE;
}

WORD __stdcall Impl_GetActiveProcessorGroupCount(void) {
	return 1;
}

SIZE_T __stdcall Impl_GetLargePageMinimum(void) {
	return 0; // indicates not supported by processor
}

BOOL __stdcall Impl_GetNumaProcessorNodeEx(PPROCESSOR_NUMBER pProcessorNumber, PUSHORT pnNumaNode) {
	if ((pProcessorNumber == NULL) || (pnNumaNode == NULL)) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	*pnNumaNode = 0;
	return TRUE;
}

CB_UNDECORATED_EXTERN(LPVOID, VirtualAllocEx, HANDLE hProcess, LPVOID pAddress, SIZE_T nSize, DWORD nAllocType, DWORD nProtType);

LPVOID __stdcall Impl_VirtualAllocExNuma(HANDLE hProcess, LPVOID pAddress, SIZE_T nSize, DWORD nAllocType, DWORD nProtType, DWORD nNumaNode) {
	return CB_UNDECORATED_CALL(VirtualAllocEx, hProcess, pAddress, nSize, nAllocType, nProtType);
}
