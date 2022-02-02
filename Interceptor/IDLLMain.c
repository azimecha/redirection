#include "InterceptDLLs.h"
#include "InterceptEXEs.h"
#include <NTDLL.h>

#define _X86_
#include <minwindef.h>

static LONG s_bDidApplyHooks = 0;

BOOL WINAPI ENTRY_POINT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        if (InterlockedCompareExchange(&s_bDidApplyHooks, 1, 0) == 0) {
            CbDisplayMessageW(L"Magic Ways", L"DLL loaded, press OK when attached.", CbSeverityInfo);
            return ApplyLibraryLoadHooks() && ApplyProcessCreationHooks();
        }
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

int WaysDummy = 0xB0B;
int NoRedirectImports = 1;
