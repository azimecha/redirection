// WARNING: This DLL does NOT get its imports resolved. Use only NTDLL functions directly.
//          All other functions must be found through GetLoadedImageByName/GetSymbolAddress.

#include <NTDLL.h>
#include <processthreadsapi.h>

#define MORNINGGLORY_ERROR_ON_WRONGFUL_LOAD

typedef void(__stdcall* BaseProcessStartThunk_t)(LPVOID pStartAddr, LPVOID pParam);
typedef HMODULE(__stdcall* LoadLibraryA_t)(LPCSTR pcszLibrary);

DECLSPEC_NORETURN static void s_Die(void);

// shimmer will set this value to the original entry point
BaseProcessStartThunk_t ProcessStartThunk = NULL;

// tells ways.dll not to mess with us
int NoRedirectImports = 1;

// this will be called instead
void __stdcall ProcessEntryPoint(LPVOID pStartAddr, LPVOID pParam) {
    PLDR_DATA_TABLE_ENTRY_FULL pentKernel32;
    LoadLibraryA_t procLoadLibrary;
    HMODULE hWaysModule;

    pentKernel32 = CbGetLoadedImageByName("kernel32.dll");
    if (pentKernel32 == NULL) {
        CbDisplayMessageW(L"Error", L"Kernel32.dll not found in loaded modules list.", CbSeverityError);
        s_Die();
    }

    //dprintf("[ProcessEntryPoint] Found kernel32 at 0x%08X\r\n", (UINT_PTR)pentKernel32->DllBase);

    procLoadLibrary = CbGetSymbolAddress(pentKernel32->DllBase, "LoadLibraryA");
    if (procLoadLibrary == NULL) {
        CbDisplayMessageW(L"Error", L"LoadLibraryA not found in kernel32.dll.", CbSeverityError);
        s_Die();
    }

    //dprintf("[ProcessEntryPoint] Found LoadLibraryA at 0x%08X\r\n", (UINT_PTR)procLoadLibrary);

    hWaysModule = procLoadLibrary("ways.dll");
    if (hWaysModule == NULL) {
        CbDisplayMessageW(L"Error", L"Ways.dll could not be loaded.", CbSeverityError);
        s_Die();
    }

    //dprintf("[ProcessEntryPoint] Loaded ways at 0x%08X\r\n", (UINT_PTR)hWaysModule);

    if (ProcessStartThunk == NULL) {
        CbDisplayMessageW(L"Error", L"Shimmer did not set ProcessStartThunk.", CbSeverityError);
        s_Die();
    }

    //dprintf("[ProcessEntryPoint] Calling ProcessStartThunk at 0x%08X\r\n", ProcessStartThunk);

    ProcessStartThunk(pStartAddr, pParam);

    CbDisplayMessageW(L"Warning", L"ProcessStartThunk returned - this should not happen.", CbSeverityWarning);
    s_Die();
}

// required DLL entry point - may be called sometimes, but NOT when we load into the target
BOOL WINAPI ENTRY_POINT(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

#ifdef MORNINGGLORY_ERROR_ON_WRONGFUL_LOAD
    CbDisplayMessageW(L"Error", L"Morning.dll cannot be loaded in this way.", CbSeverityError);
    return FALSE;
#endif

    return TRUE;
}

// if something goes totally wrong
DECLSPEC_NORETURN static void s_Die(void) {
    NtTerminateProcess(0, (NTSTATUS)-1);
    NtTerminateProcess((HANDLE)-1, (NTSTATUS)-1);
    __asm INT 3;
}
