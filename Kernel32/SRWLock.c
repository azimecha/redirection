#include <NTDLL.h>

#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0501
#define _WIN32_WINNT 0x0501
#include <minwindef.h>

typedef NTSTATUS(__stdcall* DbgPrint_t)(LPCSTR pcszFormat, ...);
extern DbgPrint_t CbGetDebugPrintFunction(void);

#define K32R_SRWLOCK_VAL_UNLOCKED ((PVOID)0)
#define K32R_SRWLOCK_VAL_XLOCKED ((PVOID)~(UINT_PTR)0)

#define SRWLOCK_INIT {K32R_SRWLOCK_VAL_UNLOCKED}

typedef struct _SRWLOCK {
	volatile PVOID nValue;
} SRWLOCK, *PSRWLOCK;

BOOLEAN __stdcall Impl_TryAcquireSRWLockExclusive(PSRWLOCK plock);
BOOLEAN __stdcall Impl_TryAcquireSRWLockShared(PSRWLOCK plock);

typedef DWORD(__stdcall* NtYieldExecution_t)(void);

static void s_Yield(void) {
	static NtYieldExecution_t procYieldExecution = NULL;

	if (procYieldExecution == NULL)
		procYieldExecution = CbGetNTDLLFunction("NtYieldExecution");

	if (procYieldExecution == NULL)
		CbGetDebugPrintFunction()("[SRWLock:Yield] NtYieldExecution not found!");
	else
		procYieldExecution();
}

void __stdcall Impl_InitializeSRWLock(PSRWLOCK plock) {
	plock->nValue = 0;
}

void __stdcall Impl_AcquireSRWLockExclusive(PSRWLOCK plock) {
	while (!Impl_TryAcquireSRWLockExclusive(plock))
		s_Yield();
}

void __stdcall Impl_AcquireSRWLockShared(PSRWLOCK plock) {
	while (!Impl_TryAcquireSRWLockShared(plock))
		s_Yield();
}

void __stdcall Impl_ReleaseSRWLockExclusive(PSRWLOCK plock) {
	plock->nValue = K32R_SRWLOCK_VAL_UNLOCKED;
}

void __stdcall Impl_ReleaseSRWLockShared(PSRWLOCK plock) {
	PVOID nCurVal, nNewVal;

	for (;;) {
		nCurVal = plock->nValue;
		nNewVal = (PVOID)((UINT_PTR)nCurVal - 1);
		if (InterlockedCompareExchangePointer(&plock->nValue, nNewVal, nCurVal) == nCurVal)
			return;
	}
}

BOOLEAN __stdcall Impl_TryAcquireSRWLockExclusive(PSRWLOCK plock) {
	return InterlockedCompareExchangePointer(&plock->nValue, K32R_SRWLOCK_VAL_XLOCKED, K32R_SRWLOCK_VAL_UNLOCKED) == K32R_SRWLOCK_VAL_UNLOCKED;
}

BOOLEAN __stdcall Impl_TryAcquireSRWLockShared(PSRWLOCK plock) {
	PVOID nCurVal, nNewVal;

	nCurVal = plock->nValue;
	if (nCurVal == K32R_SRWLOCK_VAL_XLOCKED)
		return FALSE;

	nNewVal = (PVOID)((UINT_PTR)nCurVal + 1);
	return InterlockedCompareExchangePointer(&plock->nValue, nNewVal, nCurVal) == nCurVal;
}
