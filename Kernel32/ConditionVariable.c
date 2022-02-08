#include <ImportHelper.h>
#include <inttypes.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL 0xC0000001
#endif

struct SDL_cond;
typedef struct SDL_cond SDL_cond;

typedef struct _SDL_mutex {
    int (* procLock)(PVOID pObject, DWORD nTimeout);
    int (* procUnlock)(PVOID pObject);
    PVOID pObject;
} SDL_mutex;

typedef void SDL_sem;
typedef DWORD Uint32;
#define SDL_MUTEX_MAXWAIT (~(DWORD)0)
#define SDL_MUTEX_TIMEDOUT 1
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x102
#define WAIT_ABANDONED 0x80

typedef DWORD(__stdcall* DbgPrint_t)(LPCSTR pcszFormat, ...);
extern DbgPrint_t CbGetDebugPrintFunction(void);
extern PVOID CbHeapAllocate(SIZE_T nBytes, BOOL bZeroInit);
extern void CbHeapFree(PVOID pBlock);
extern BOOLEAN __stdcall Impl_TryAcquireSRWLockExclusive(PVOID plock);
extern BOOLEAN __stdcall Impl_TryAcquireSRWLockShared(PVOID plock);
extern void SRWYield(void);
extern void __stdcall Impl_ReleaseSRWLockExclusive(PSRWLOCK plock);
extern void __stdcall Impl_ReleaseSRWLockShared(PSRWLOCK plock);

+CB_UNDECORATED_EXTERN(HANDLE, CreateMutexA, PVOID pAttribs, BOOL bInitOwned, LPCSTR pcszName);
CB_UNDECORATED_EXTERN(HANDLE, CreateSemaphoreA, PVOID pAttribs, LONG nInitCount, LONG nMaxCount, LPCSTR pcszName);
CB_UNDECORATED_EXTERN(void, RaiseException, DWORD nCode, DWORD flags, DWORD nArgs, const uintptr_t* pArgs);
CB_UNDECORATED_EXTERN(BOOL, CloseHandle, HANDLE h);
CB_UNDECORATED_EXTERN(DWORD, WaitForSingleObject, HANDLE hObject, DWORD nMillis);
CB_UNDECORATED_EXTERN(BOOL, ReleaseMutex, HANDLE hMutex);
CB_UNDECORATED_EXTERN(BOOL, ReleaseSemaphore, HANDLE hSemaphore, LONG nRelCount, OPTIONAL LPLONG pnPrevCount);

static int s_LockSystemMutex(PVOID pObject, DWORD nTimeout);
static int s_UnlockSystemMutex(PVOID pObject);
static int s_WrappedWaitForObject(HANDLE hObject, DWORD nTimeout);
static int s_LockCriticalSection(PVOID pObject, DWORD nTimeout);
static int s_UnlockCriticalSection(PVOID pObject);
static int s_LockSRWLock(PVOID pObject, DWORD nTimeout, BOOLEAN (__stdcall* procTryLock)(PVOID pObject));
static int s_LockSRWLockExclusive(PVOID pObject, DWORD nTimeout);
static int s_LockSRWLockShared(PVOID pObject, DWORD nTimeout);
static int s_UnlockSRWLockExclusive(PVOID pObject);
static int s_UnlockSRWLockShared(PVOID pObject);
static BOOL s_WrappedCondWaitTimeout(PCONDITION_VARIABLE pcond, SDL_mutex* pMutex, DWORD nMillis);

static SDL_mutex* SDL_CreateMutex(void) {
    SDL_mutex* pMutex;

    pMutex = CbHeapAllocate(sizeof(SDL_mutex), TRUE);
    if (pMutex == NULL) return pMutex;

    pMutex->procLock = s_LockSystemMutex;
    pMutex->procUnlock = s_UnlockSystemMutex;
    pMutex->pObject = (PVOID)CB_UNDECORATED_CALL(CreateMutexA, NULL, FALSE, NULL);
    if (pMutex->pObject == NULL) {
        CbHeapFree(pMutex);
        return NULL;
    }

    return pMutex;
}

static SDL_sem* SDL_CreateSemaphore(Uint32 nInitVal) {
    return (SDL_sem*)CB_UNDECORATED_CALL(CreateSemaphoreA, NULL, nInitVal, MAXLONG, NULL);
}

static void SDL_OutOfMemory(void) {
    CB_UNDECORATED_CALL(RaiseException, STATUS_NO_MEMORY, 0, 0, NULL);
}

static void SDL_DestroySemaphore(SDL_sem* pSemaphore) {
    CB_UNDECORATED_CALL(CloseHandle, (HANDLE)pSemaphore);
}

static void SDL_DestroyMutex(SDL_mutex* pMutex) {
    CB_UNDECORATED_CALL(CloseHandle, (HANDLE)pMutex);
}

static void* SDL_malloc(size_t nBytes) {
    return CbHeapAllocate(nBytes, FALSE);
}

static void SDL_free(void* pBlock) {
    CbHeapFree(pBlock);
}

static int SDL_SetError(const char* pcszError) {
    CbGetDebugPrintFunction()("[ConditionVariable] SDL error: %s\r\n", pcszError);
    return -1;
}

static int SDL_LockMutex(SDL_mutex* pMutex) {
    return pMutex->procLock(pMutex->pObject, SDL_MUTEX_MAXWAIT);
}

static int SDL_UnlockMutex(SDL_mutex* pMutex) {
    return pMutex->procUnlock(pMutex->pObject);
}

static int SDL_SemPost(SDL_sem* pSem) {
    return CB_UNDECORATED_CALL(ReleaseSemaphore, (HANDLE)pSem, 1, NULL) ? 0 : -1;
}

static int SDL_SemWait(SDL_sem* pSem) {
    return s_WrappedWaitForObject((HANDLE)pSem, SDL_MUTEX_MAXWAIT);
}

static int SDL_SemWaitTimeout(SDL_sem* pSem, Uint32 nMillis) {
    return s_WrappedWaitForObject((HANDLE)pSem, nMillis);
}

static int s_WrappedWaitForObject(HANDLE hObject, DWORD nTimeout) {
    switch (CB_UNDECORATED_CALL(WaitForSingleObject, hObject, nTimeout)) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return 0;

    case WAIT_TIMEOUT:
        return SDL_MUTEX_TIMEDOUT;

    default:
        return -1;
    }
}

static int s_LockSystemMutex(PVOID pMutex, DWORD nTimeout) {
    return s_WrappedWaitForObject((HANDLE)pMutex, nTimeout);
}

static int s_UnlockSystemMutex(PVOID pObject) {
    return CB_UNDECORATED_CALL(ReleaseMutex, (HANDLE)pObject) ? 0 : -1;
}

static int s_LockCriticalSection(PVOID pObject, DWORD nTimeout) {
    __try {
        EnterCriticalSection((PCRITICAL_SECTION)pObject);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    return 0;
}

static int s_UnlockCriticalSection(PVOID pObject) {
    __try {
        LeaveCriticalSection((PCRITICAL_SECTION)pObject);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }

    return 0;
}

static int s_LockSRWLock(PVOID pObject, DWORD nTimeout, BOOLEAN (__stdcall* procTryLock)(PVOID pObject)) {
    uint64_t nEndTime;

    nEndTime = (uint64_t)GetTickCount() + nTimeout;
    do {
        if (procTryLock(pObject))
            return 0;
        SRWYield();
    } while (GetTickCount() < nEndTime);

    return SDL_MUTEX_TIMEDOUT;
}

static int s_LockSRWLockExclusive(PVOID pObject, DWORD nTimeout) {
    return s_LockSRWLock(pObject, nTimeout, Impl_TryAcquireSRWLockExclusive);
}

static int s_LockSRWLockShared(PVOID pObject, DWORD nTimeout) {
    return s_LockSRWLock(pObject, nTimeout, Impl_TryAcquireSRWLockShared);
}

static int s_UnlockSRWLockExclusive(PVOID pObject) {
    Impl_ReleaseSRWLockExclusive(pObject);
    return 0;
}

static int s_UnlockSRWLockShared(PVOID pObject) {
    Impl_ReleaseSRWLockShared(pObject);
    return 0;
}

////////////////////////////// BEGIN SDL CODE //////////////////////////////

/*
  Simple DirectMedia Layer
  Copyright (C) 1997-2021 Sam Lantinga <slouken@libsdl.org>

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

/* An implementation of condition variables using semaphores and mutexes */
/*
   This implementation borrows heavily from the BeOS condition variable
   implementation, written by Christopher Tate and Owen Smith.  Thanks!
 */

 /* If two implementations are to be compiled into SDL (the active one
  * will be chosen at runtime), the function names need to be
  * suffixed
  */
#if !SDL_THREAD_GENERIC_COND_SUFFIX
#define SDL_CreateCond_generic      SDL_CreateCond
#define SDL_DestroyCond_generic     SDL_DestroyCond
#define SDL_CondSignal_generic      SDL_CondSignal
#define SDL_CondBroadcast_generic   SDL_CondBroadcast
#define SDL_CondWait_generic        SDL_CondWait
#define SDL_CondWaitTimeout_generic SDL_CondWaitTimeout
#endif

typedef struct SDL_cond_generic
{
    SDL_mutex* lock;
    int waiting;
    int signals;
    SDL_sem* wait_sem;
    SDL_sem* wait_done;
} SDL_cond_generic;

SDL_cond* SDL_CreateCond_generic(void);
void SDL_DestroyCond_generic(SDL_cond* _cond);
int SDL_CondSignal_generic(SDL_cond* _cond);
int SDL_CondBroadcast_generic(SDL_cond* _cond);
int SDL_CondWaitTimeout_generic(SDL_cond* _cond, SDL_mutex* mutex, Uint32 ms);
int SDL_CondWait_generic(SDL_cond* cond, SDL_mutex* mutex);

/* Create a condition variable */
SDL_cond*
SDL_CreateCond_generic(void)
{
    SDL_cond_generic* cond;

    cond = (SDL_cond_generic*)SDL_malloc(sizeof(SDL_cond_generic));
    if (cond) {
        cond->lock = SDL_CreateMutex();
        cond->wait_sem = SDL_CreateSemaphore(0);
        cond->wait_done = SDL_CreateSemaphore(0);
        cond->waiting = cond->signals = 0;
        if (!cond->lock || !cond->wait_sem || !cond->wait_done) {
            SDL_DestroyCond_generic((SDL_cond*)cond);
            cond = NULL;
        }
    }
    else {
        SDL_OutOfMemory();
    }
    return (SDL_cond*)cond;
}

/* Destroy a condition variable */
void
SDL_DestroyCond_generic(SDL_cond* _cond)
{
    SDL_cond_generic* cond = (SDL_cond_generic*)_cond;
    if (cond) {
        if (cond->wait_sem) {
            SDL_DestroySemaphore(cond->wait_sem);
        }
        if (cond->wait_done) {
            SDL_DestroySemaphore(cond->wait_done);
        }
        if (cond->lock) {
            SDL_DestroyMutex(cond->lock);
        }
        SDL_free(cond);
    }
}

/* Restart one of the threads that are waiting on the condition variable */
int
SDL_CondSignal_generic(SDL_cond* _cond)
{
    SDL_cond_generic* cond = (SDL_cond_generic*)_cond;
    if (!cond) {
        return SDL_SetError("Passed a NULL condition variable");
    }

    /* If there are waiting threads not already signalled, then
       signal the condition and wait for the thread to respond.
     */
    SDL_LockMutex(cond->lock);
    if (cond->waiting > cond->signals) {
        ++cond->signals;
        SDL_SemPost(cond->wait_sem);
        SDL_UnlockMutex(cond->lock);
        SDL_SemWait(cond->wait_done);
    }
    else {
        SDL_UnlockMutex(cond->lock);
    }

    return 0;
}

/* Restart all threads that are waiting on the condition variable */
int
SDL_CondBroadcast_generic(SDL_cond* _cond)
{
    SDL_cond_generic* cond = (SDL_cond_generic*)_cond;
    if (!cond) {
        return SDL_SetError("Passed a NULL condition variable");
    }

    /* If there are waiting threads not already signalled, then
       signal the condition and wait for the thread to respond.
     */
    SDL_LockMutex(cond->lock);
    if (cond->waiting > cond->signals) {
        int i, num_waiting;

        num_waiting = (cond->waiting - cond->signals);
        cond->signals = cond->waiting;
        for (i = 0; i < num_waiting; ++i) {
            SDL_SemPost(cond->wait_sem);
        }
        /* Now all released threads are blocked here, waiting for us.
           Collect them all (and win fabulous prizes!) :-)
         */
        SDL_UnlockMutex(cond->lock);
        for (i = 0; i < num_waiting; ++i) {
            SDL_SemWait(cond->wait_done);
        }
    }
    else {
        SDL_UnlockMutex(cond->lock);
    }

    return 0;
}

/* Wait on the condition variable for at most 'ms' milliseconds.
   The mutex must be locked before entering this function!
   The mutex is unlocked during the wait, and locked again after the wait.

Typical use:

Thread A:
    SDL_LockMutex(lock);
    while ( ! condition ) {
        SDL_CondWait(cond, lock);
    }
    SDL_UnlockMutex(lock);

Thread B:
    SDL_LockMutex(lock);
    ...
    condition = true;
    ...
    SDL_CondSignal(cond);
    SDL_UnlockMutex(lock);
 */
int
SDL_CondWaitTimeout_generic(SDL_cond* _cond, SDL_mutex* mutex, Uint32 ms)
{
    SDL_cond_generic* cond = (SDL_cond_generic*)_cond;
    int retval;

    if (!cond) {
        return SDL_SetError("Passed a NULL condition variable");
    }

    /* Obtain the protection mutex, and increment the number of waiters.
       This allows the signal mechanism to only perform a signal if there
       are waiting threads.
     */
    SDL_LockMutex(cond->lock);
    ++cond->waiting;
    SDL_UnlockMutex(cond->lock);

    /* Unlock the mutex, as is required by condition variable semantics */
    SDL_UnlockMutex(mutex);

    /* Wait for a signal */
    if (ms == SDL_MUTEX_MAXWAIT) {
        retval = SDL_SemWait(cond->wait_sem);
    }
    else {
        retval = SDL_SemWaitTimeout(cond->wait_sem, ms);
    }

    /* Let the signaler know we have completed the wait, otherwise
       the signaler can race ahead and get the condition semaphore
       if we are stopped between the mutex unlock and semaphore wait,
       giving a deadlock.  See the following URL for details:
       http://web.archive.org/web/20010914175514/http://www-classic.be.com/aboutbe/benewsletter/volume_III/Issue40.html#Workshop
     */
    SDL_LockMutex(cond->lock);
    if (cond->signals > 0) {
        /* If we timed out, we need to eat a condition signal */
        if (retval > 0) {
            SDL_SemWait(cond->wait_sem);
        }
        /* We always notify the signal thread that we are done */
        SDL_SemPost(cond->wait_done);

        /* Signal handshake complete */
        --cond->signals;
    }
    --cond->waiting;
    SDL_UnlockMutex(cond->lock);

    /* Lock the mutex, as is required by condition variable semantics */
    SDL_LockMutex(mutex);

    return retval;
}

/* Wait on the condition variable forever */
int
SDL_CondWait_generic(SDL_cond* cond, SDL_mutex* mutex)
{
    return SDL_CondWaitTimeout_generic(cond, mutex, SDL_MUTEX_MAXWAIT);
}

/* vi: set ts=4 sw=4 expandtab: */

////////////////////////////// END SDL CODE //////////////////////////////

typedef SDL_cond** PCONDITION_VARIABLE;

void __stdcall Impl_InitializeConditionVariable(PCONDITION_VARIABLE pcond) {
    *pcond = SDL_CreateCond();
    if (*pcond == NULL)
        CB_UNDECORATED_CALL(RaiseException, STATUS_UNSUCCESSFUL, 0, 0, NULL);
}

static BOOL s_WrappedCondWaitTimeout(PCONDITION_VARIABLE pcond, SDL_mutex* pMutex, DWORD nMillis) {
    switch (SDL_CondWaitTimeout(*pcond, pMutex, (Uint32)nMillis)) {
    case 0:
        return TRUE;

    case SDL_MUTEX_TIMEDOUT:
        CbLastWinAPIError = ERROR_TIMEOUT;
        return FALSE;

    default:
        return FALSE;
    }
}

BOOL __stdcall Impl_SleepConditionVariableCS(PCONDITION_VARIABLE pcond, PCRITICAL_SECTION pcs, DWORD nMillis) {
    SDL_mutex mtx;
    mtx.procLock = s_LockCriticalSection;
    mtx.procUnlock = s_UnlockCriticalSection;
    mtx.pObject = pcs;

    return s_WrappedCondWaitTimeout(pcond, &mtx, nMillis);
}

BOOL __stdcall Impl_SleepConditionVariableSRW(PCONDITION_VARIABLE pcond, PSRWLOCK pLock, DWORD nMillis, ULONG flags) {
    SDL_mutex mtx;
    mtx.procLock = (flags & CONDITION_VARIABLE_LOCKMODE_SHARED) ? s_LockSRWLockShared : s_LockSRWLockExclusive;
    mtx.procUnlock = (flags & CONDITION_VARIABLE_LOCKMODE_SHARED) ? s_UnlockSRWLockShared : s_UnlockSRWLockExclusive;
    mtx.pObject = pLock;

    return s_WrappedCondWaitTimeout(pcond, &mtx, nMillis);
}

void __stdcall Impl_WakeAllConditionVariable(PCONDITION_VARIABLE pcond) {
    SDL_CondBroadcast(*pcond);
}

void __stdcall Impl_WakeConditionVariable(PCONDITION_VARIABLE pcond) {
    SDL_CondSignal(*pcond);
}
