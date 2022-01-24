#include "InterceptDLLs.h"
#include "InterceptEXEs.h"

#define _X86_
#include <minwindef.h>

BOOL WINAPI ENTRY_POINT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        return ApplyLibraryLoadHooks() && ApplyProcessCreationHooks();

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
