#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL WINAPI ENTRY_POINT(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

// forces ways.dll reference
__declspec(dllimport) extern int WaysDummy;
__declspec(dllexport) int __stdcall Dummy(void) { return WaysDummy; }

// tells ways.dll not to mess with us
__declspec(dllexport) int NoRedirectImports = 1;
