// WARNING: This DLL does NOT get its imports resolved. Use only NTDLL functions directly.
//          All other functions must be found through GetLoadedImageByName/GetSymbolAddress.

#include <NTDLL.h>
#include <processthreadsapi.h>
#include "../Patching/HookFunction.h"
#include <malloc.h>

#ifndef DECLSPEC_NAKED
#define DECLSPEC_NAKED __declspec(naked)
#endif

#define MG_ERROR_ON_WRONGFUL_LOAD
#define MG_CURRENT_PROCESS (HANDLE)(-1)

typedef HMODULE(__stdcall* LoadLibraryA_t)(LPCSTR pcszLibrary);
typedef void(__stdcall* LdrInitializeThunk_t)(LPVOID p1, LPVOID p2, LPVOID p3);
typedef NTSTATUS(__stdcall* BaseProcessInitPostImport_t)(void);

static NTSTATUS __stdcall s_GetProcedureAddress(HMODULE hModule, OPTIONAL PANSI_STRING pasFuncName, OPTIONAL WORD nOrdinal,
    OUT PVOID* ppAddressOUT);
static void s_OnKernel32Loaded(PLDR_DATA_TABLE_ENTRY_FULL pentKernel32);
DECLSPEC_NORETURN void __stdcall ProcessEntryPointThunk(void);
DECLSPEC_NORETURN static void __stdcall s_CallOriginalThunk(LPVOID pStartAddr, LPVOID pParam);
DECLSPEC_NORETURN void __stdcall ProcessEntryPoint(LPVOID pStartAddr, LPVOID pParam);
DECLSPEC_NORETURN static void s_Die(void);

// shimmer will set this value to the original entry point
LPVOID ProcessStartThunk = NULL;

// tells ways.dll not to mess with us
int NoRedirectImports = 1;

// shimmer will store the overwritten LdrInitializeThunk code here
// default to INT3, 0x01 indicates not overwritten by shimmer
BYTE InitThunkCode[PA_REPLACEFUNC_CODESIZE] = { 0xCC, 0x01 };

// this will be called instead of LdrInitializeThunk
DECLSPEC_NORETURN void __stdcall ProcessInitThunk(LPVOID p1, LPVOID p2, LPVOID p3) {
    LdrInitializeThunk_t procLdrInitializeThunk;
    LdrGetProcedureAddress_t procLdrGetProcedureAddress;
    PaHookCode_p phook;
    NTSTATUS status;
    ULONG nOldProt, nBytesToProt;
    PVOID pToProt;

    // remove LdrInitializeThunk hook

    procLdrInitializeThunk = CbGetNTDLLFunction("LdrInitializeThunk");
    if (procLdrInitializeThunk == NULL) {
        CbDisplayMessageW(L"Error", L"Unable to find LdrInitializeThunk in NTDLL.", CbSeverityError);
        s_Die();
    }

    memcpy(procLdrInitializeThunk, InitThunkCode, sizeof(InitThunkCode));
    status = NtFlushInstructionCache(MG_CURRENT_PROCESS, procLdrInitializeThunk, sizeof(InitThunkCode));
    if (status != 0)
        CbDisplayMessageW(L"Warning", L"Error flushing instruction cache (1).\r\nLdrInitializeThunk may not work.", CbSeverityWarning);

    // replace LdrGetProcedureAddress

    procLdrGetProcedureAddress = CbGetNTDLLFunction("LdrGetProcedureAddress");
    if (procLdrGetProcedureAddress == NULL) {
        CbDisplayMessageW(L"Error", L"Unable to find LdrGetProcedureAddress in NTDLL.", CbSeverityError);
        s_Die();
    }

    nBytesToProt = sizeof(*phook);
    pToProt = procLdrGetProcedureAddress;
    status = NtProtectVirtualMemory(MG_CURRENT_PROCESS, &pToProt, &nBytesToProt, PAGE_EXECUTE_READWRITE, &nOldProt);
    if (status != 0) {
        CbDisplayMessageW(L"Error", L"Unable to make LdrGetProcedureAddress writable.", CbSeverityError);
        s_Die();
    }

    phook = (PaHookCode_p)procLdrGetProcedureAddress;
    phook->instrPush = PA_HOOK_INSTR_PUSH;
    phook->pJumpAddr = (LPVOID)s_GetProcedureAddress;
    phook->instrRet = PA_HOOK_INSTR_RET;

    status = NtFlushInstructionCache(MG_CURRENT_PROCESS, phook, sizeof(*phook));
    if (status != 0)
        CbDisplayMessageW(L"Warning", L"Error flushing instruction cache (3).\r\nNtCreateFile may not work.", CbSeverityWarning);

    // call original LdrInitializeThunk

    procLdrInitializeThunk(p1, p2, p3);

    CbDisplayMessageW(L"Warning", L"LdrInitializeThunk returned - this should not happen.", CbSeverityWarning);
    s_Die();
}

#pragma warning(disable:28112)
#pragma warning(disable:6255)

// this will be called instead of LdrGetProcedureAddress
static NTSTATUS __stdcall s_GetProcedureAddress(HMODULE hModule, OPTIONAL PANSI_STRING pasFuncName, OPTIONAL WORD nOrdinal,
    OUT PVOID* ppAddressOUT)
{
    static volatile LONG s_bKernel32Loaded = 0;
    PLDR_DATA_TABLE_ENTRY_FULL pentKernel32;
    char szFuncName[256];
    NTSTATUS status;

    DbgPrint("[GetProcedureAddress] Module: 0x%08X, name ptr: 0x%08X, ordinal: 0x%08X, K32 loaded: %d\r\n", (UINT_PTR)hModule, 
        (UINT_PTR)pasFuncName, (UINT_PTR)nOrdinal, s_bKernel32Loaded);

    // check if kernel32 has just been loaded
    if (s_bKernel32Loaded == 0) {
        pentKernel32 = CbGetLoadedImageByName("kernel32.dll");
        if (pentKernel32 != NULL) {
            if (InterlockedCompareExchange(&s_bKernel32Loaded, 1, 0) == 0) {
                DbgPrint("[GetProcedureAddress] Kernel32 was just loaded!\r\n");
                s_OnKernel32Loaded(pentKernel32);
            }
        }
    }

    // check output addr
    if (ppAddressOUT == NULL) {
        DbgPrint("[GetProcedureAddress] Exiting early (invalid output address)\r\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    // ensure function name is null terminated
    if ((pasFuncName != NULL) && (pasFuncName->Buffer != NULL)) {
        if (pasFuncName->Length >= sizeof(szFuncName)) {
            DbgPrint("[GetProcedureAddress] Symbol name is too long at %u bytes\r\n", pasFuncName->Length);
            return STATUS_INVALID_PARAMETER_2;
        }

        memcpy(szFuncName, pasFuncName->Buffer, pasFuncName->Length);
        szFuncName[pasFuncName->Length] = 0;

        DbgPrint("[GetProcedureAddress] Name: %s\r\n", szFuncName);
    }

    // try to find the symbol
    status = CbGetSymbolAddressEx((LPVOID)hModule, szFuncName, nOrdinal, ppAddressOUT);
    DbgPrint("[GetProcedureAddress] Status: 0x%08X, symbol addr: 0x%08X\r\n", status, (UINT_PTR)*ppAddressOUT);

    return status;
}

static void s_OnKernel32Loaded(PLDR_DATA_TABLE_ENTRY_FULL pentKernel32) {
    BaseProcessInitPostImport_t procBaseProcessInitPostImport;
    LoadLibraryA_t procLoadLibrary;
    HMODULE hWaysModule;
    NTSTATUS status;
    PVOID pBase;
    ULONG nBytes, nOldProt;

    CbDisplayMessageW(L"Info", L"Kernel32 has been loaded.\r\n", CbSeverityInfo);

    procBaseProcessInitPostImport = CbGetSymbolAddress(pentKernel32->DllBase, "BaseProcessInitPostImport");
    if (procBaseProcessInitPostImport == NULL)
        DbgPrint("[OnKernel32Loaded] BaseProcessInitPostImport not found, assuming not necessary.\r\n");
    else {
        // call kernel32 init function
        DbgPrint("[OnKernel32Loaded] Calling BaseProcessInitPostImport\r\n");
        status = procBaseProcessInitPostImport();
        DbgPrint("[OnKernel32Loaded] BaseProcessInitPostImport returned 0x%08X\r\n", status);
        if (status != 0) {
            CbDisplayMessageW(L"Error", L"BaseProcessInitPostImport failed.\r\n", CbSeverityError);
            s_Die();
        }

        // prevent anyone else from doing so by replacing it with a single ret
        pBase = procBaseProcessInitPostImport;
        nBytes = 1;
        status = NtProtectVirtualMemory(MG_CURRENT_PROCESS, &pBase, &nBytes, PAGE_EXECUTE_READWRITE, &nOldProt);
        if (status == 0) {
            *(BYTE*)procBaseProcessInitPostImport = PA_HOOK_INSTR_RET;
            DbgPrint("[OnKernel32Loaded] BaseProcessInitPostImport replaced with RET\r\n");
        } else {
            CbDisplayMessageW(L"Warning",
                L"Error changing memory protection.\r\nUnable to prevent BaseProcessInitPostImport from being called again.",
                CbSeverityWarning);
        }
    }

    CbDisplayMessageW(L"Info", L"Loading MagicWays.\r\n", CbSeverityInfo);

    procLoadLibrary = CbGetSymbolAddress(pentKernel32->DllBase, "LoadLibraryA");
    if (procLoadLibrary == NULL) {
        CbDisplayMessageW(L"Error", L"LoadLibraryA not found in kernel32.dll.", CbSeverityError);
        s_Die();
    }

    hWaysModule = procLoadLibrary("ways.dll");
    if (hWaysModule == NULL) {
        CbDisplayMessageW(L"Error", L"Ways.dll could not be loaded.", CbSeverityError);
        s_Die();
    }

    DbgPrint("[OnKernel32Loaded] Loaded MagicWays\r\n");
}

// this will be called instead of the function pointed to by ProcessStartThunk
DECLSPEC_NORETURN DECLSPEC_NAKED void __stdcall ProcessEntryPointThunk(void) {
    __asm {
        PUSH EBX
        PUSH EAX
        CALL ProcessEntryPoint
    }
}

// to call the original entry point, use this function
DECLSPEC_NORETURN DECLSPEC_NAKED static void __stdcall s_CallOriginalThunk(LPVOID pStartAddr, LPVOID pParam) {
    __asm {
        MOV EAX, [ESP + 4]
        MOV EBX, [ESP + 8]
        CALL ProcessStartThunk
    }
}

// once ProcessEntryPointThunk puts the values onto the stack, this function gets called
DECLSPEC_NORETURN void __stdcall ProcessEntryPoint(LPVOID pStartAddr, LPVOID pParam) {
    CbDisplayMessageA("Magic Ways", "MorningGlory has loaded", CbSeverityInfo);

    if (ProcessStartThunk == NULL) {
        CbDisplayMessageW(L"Error", L"Shimmer did not set ProcessStartThunk.", CbSeverityError);
        s_Die();
    }

    s_CallOriginalThunk(pStartAddr, pParam);

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

#ifdef MG_ERROR_ON_WRONGFUL_LOAD
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
