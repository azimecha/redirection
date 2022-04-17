#include <WaysTLS.h>
#include <ImportHelper.h>
#include <NTDLL.h>
#include <intrin.h>

#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <winerror.h>

#define K32R_CONTEXT_ALIGNMENT 16	// 16-byte aligned CONTEXT, is this ok?

BOOL __stdcall Impl_CopyContext(IN OUT PCONTEXT pctxDest, DWORD flags, PCONTEXT pctxSource);

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

BOOL __stdcall Impl_SetThreadGroupAffinity(HANDLE hThread, PGROUP_AFFINITY pAffinity, OPTIONAL PGROUP_AFFINITY pPrevAffinity) {
	if (!CbAccessCheck(hThread, THREAD_SET_INFORMATION)) {
		CbLastWinAPIError = ERROR_ACCESS_DENIED;
		return FALSE;
	}

	if (pAffinity == NULL) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (pPrevAffinity)
		memcpy(pPrevAffinity, pAffinity, sizeof(GROUP_AFFINITY));

	return TRUE;
}

void __stdcall Impl_FlushProcessWriteBuffers(void) {
	NTSTATUS status;

	// flush the current processor's write buffer
	status = NtFlushWriteBuffer();
	if (CB_NT_FAILED(status))
		DbgPrint("[Kernel32:FlushProcessWriteBuffers] NtFlushWriteBuffer returned status 0x%08X\r\n", status);

	// flush the instruction cache overall
	status = NtFlushInstructionCache(CB_CURRENT_PROCESS, NULL, 0);
	if (CB_NT_FAILED(status))
		DbgPrint("[Kernel32:FlushProcessWriteBuffers] NtFlushInstructionCache returned status 0x%08X\r\n", status);

	// note: this doesn't exactly match what the function should do, but it's the best we can get
}

BOOL __stdcall Impl_InitializeContext(PVOID pBuffer, DWORD flags, OPTIONAL OUT PCONTEXT* ppctx, IN OUT PDWORD pnLength) {
	UINT_PTR nDistToAlignedPos, nReqSize;
	PCONTEXT pctx;
	CONTEXT ctxBlank;

	if ((pBuffer == NULL) || (pnLength == NULL)) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	// align

	nDistToAlignedPos = K32R_CONTEXT_ALIGNMENT - (UINT_PTR)pBuffer % K32R_CONTEXT_ALIGNMENT;
	if (nDistToAlignedPos == K32R_CONTEXT_ALIGNMENT) nDistToAlignedPos = 0;

	nReqSize = sizeof(CONTEXT) + nDistToAlignedPos;
	if (nReqSize > *pnLength) {
		CbLastWinAPIError = ERROR_INSUFFICIENT_BUFFER;
		*pnLength = nReqSize;
		return FALSE;
	}
	
	pctx = (PCONTEXT)((PBYTE)pBuffer + nDistToAlignedPos);
	*pnLength = nReqSize;
	if (ppctx) *ppctx = pctx;

	// fill

	RtlInitializeContext(NULL, &ctxBlank, NULL, NULL, NULL);
	if (!Impl_CopyContext(pctx, flags, &ctxBlank))
		return FALSE;
	pctx->ContextFlags = flags;

	return TRUE;
}

BOOL __stdcall Impl_CopyContext(IN OUT PCONTEXT pctxDest, DWORD flags, PCONTEXT pctxSource) {
	if ((pctxDest == NULL) || (pctxSource == NULL)) {
		CbLastWinAPIError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (flags & pctxSource->ContextFlags & CONTEXT_CONTROL) {
		pctxDest->SegSs = pctxSource->SegSs;
		pctxDest->Esp = pctxSource->Esp;
		pctxDest->SegCs = pctxSource->SegCs;
		pctxDest->Eip = pctxSource->Eip;
		pctxDest->EFlags = pctxSource->EFlags;
		pctxDest->Ebp = pctxSource->Ebp;
	}

	if (flags & pctxSource->ContextFlags & CONTEXT_INTEGER) {
		pctxDest->Eax = pctxSource->Eax;
		pctxDest->Ebx = pctxSource->Ebx;
		pctxDest->Ecx = pctxSource->Ecx;
		pctxDest->Edx = pctxSource->Edx;
		pctxDest->Esi = pctxSource->Esi;
		pctxDest->Edi = pctxSource->Edi;
	}

	if (flags & pctxSource->ContextFlags & CONTEXT_SEGMENTS) {
		pctxDest->SegDs = pctxSource->SegDs;
		pctxDest->SegEs = pctxSource->SegEs;
		pctxDest->SegFs = pctxSource->SegFs;
		pctxDest->SegGs = pctxSource->SegGs;
	}

	if (flags & pctxSource->ContextFlags & CONTEXT_FLOATING_POINT)
		pctxDest->FloatSave = pctxSource->FloatSave;

	if (flags & pctxSource->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
		pctxDest->Dr0 = pctxSource->Dr0;
		pctxDest->Dr1 = pctxSource->Dr1;
		pctxDest->Dr2 = pctxSource->Dr2;
		pctxDest->Dr3 = pctxSource->Dr3;
		pctxDest->Dr6 = pctxSource->Dr6;
		pctxDest->Dr7 = pctxSource->Dr7;
	}

	if (flags & pctxSource->ContextFlags & CONTEXT_EXTENDED_REGISTERS)
		memcpy(pctxDest->ExtendedRegisters, pctxSource->ExtendedRegisters, sizeof(pctxDest->ExtendedRegisters));

	return TRUE;
}
