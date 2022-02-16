#include "InterceptDLLs.h"
#include "InterceptEXEs.h"
#include "InterceptIO.h"
#include "ThreadLocal.h"
#include <NTDLL.h>

#define _X86_
#include <minwindef.h>

static LONG s_bDidApplyHooks = 0;

BOOL WINAPI ENTRY_POINT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        if (!TLSInitProcess()) {
            CbDisplayMessageW(L"Magic Ways", L"Process-level TLS initialization failed!", CbSeverityError);
            return FALSE;
        }
        if (InterlockedCompareExchange(&s_bDidApplyHooks, 1, 0) == 0) {
            CbDisplayMessageW(L"Magic Ways", L"DLL loaded, press OK when attached.", CbSeverityInfo);
            return ApplyLibraryLoadHooks() && ApplyProcessCreationHooks() && ApplyIOHooks();
        }
        break;

    case DLL_THREAD_ATTACH:
        if (!TLSInitThread()) {
            CbDisplayMessageW(L"Magic Ways", L"Thread-level TLS initialization failed!", CbSeverityError);
            return FALSE;
        }
        break;

    case DLL_THREAD_DETACH:
        if (!TLSUninitThread()) {
            CbDisplayMessageW(L"Magic Ways", L"Thread-level TLS uninitialization failed!", CbSeverityError);
            return FALSE;
        }
        break;

    case DLL_PROCESS_DETACH:
        if (!TLSUninitProcess()) {
            CbDisplayMessageW(L"Magic Ways", L"Process-level TLS uninitialization failed!", CbSeverityError);
            return FALSE;
        }
        break;
    }

    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

int WaysDummy = 0xB0B;
int NoRedirectImports = 1;
