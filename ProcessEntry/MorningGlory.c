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
#define MG_CURRENT_PROCESS CB_CURRENT_PROCESS

typedef HMODULE(__stdcall* LoadLibraryA_t)(LPCSTR pcszLibrary);
typedef void(__stdcall* LdrInitializeThunk_t)(LPVOID p1, LPVOID p2, LPVOID p3);
typedef NTSTATUS(__stdcall* BaseProcessInitPostImport_t)(void);
typedef BOOL(__stdcall* DLLMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

static NTSTATUS __stdcall s_GetProcedureAddress(HMODULE hModule, OPTIONAL PANSI_STRING pasFuncName, OPTIONAL WORD nOrdinal,
    OUT PVOID* ppAddressOUT);
static void s_OnKernel32Loaded(PLDR_DATA_TABLE_ENTRY_FULL pentKernel32);
DECLSPEC_NORETURN void __stdcall ProcessEntryPointThunk(void);
DECLSPEC_NORETURN static void __stdcall s_CallOriginalThunk(LPVOID pStartAddr, LPVOID pParam);
DECLSPEC_NORETURN void __stdcall ProcessEntryPoint(LPVOID pStartAddr, LPVOID pParam);
DECLSPEC_NORETURN static void s_Die(void);

#if 0
static BOOL s_MiniFindDLL(LPCWSTR pcwzName, OUT PUNICODE_STRING pusFullPath);
static BOOL s_ConcatUniW(PUNICODE_STRING pusTarget, LPCWSTR pcwzToConcat);
static void s_RemoveFilenameUni(PUNICODE_STRING pusTarget);
#endif

// shimmer will set this value to the original entry point
LPVOID ProcessStartThunk = NULL;

// tells ways.dll not to mess with us
int NoRedirectImports = 1;

// shimmer will store the overwritten LdrInitializeThunk code here
// default to INT3, 0x01 indicates not overwritten by shimmer
BYTE InitThunkCode[PA_REPLACEFUNC_CODESIZE] = { 0xCC, 0x01 };

// shimmer will store path to ways.dll here
WCHAR MagicWaysPath[MAX_PATH + 1] = { 0 };

// shimmer will store path to config file here
WCHAR ConfigFilePath[MAX_PATH + 1] = { 0 };

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
    HMODULE hWaysModule;
    NTSTATUS status;
    UNICODE_STRING usWays;
    DLLMain_t procWaysDLLMain;
    LPSTR pszConfigFilePathBuffer;

    CbDisplayMessageW(L"Info", L"Kernel32 has been loaded.\r\n", CbSeverityInfo);

    usWays.Buffer = MagicWaysPath;
    usWays.Length = (USHORT)(wcslen(MagicWaysPath) * sizeof(WCHAR));
    usWays.MaximumLength = usWays.Length;

    DbgPrint("[OnKernel32Loaded] Loading ways.dll from %wZ\r\n", &usWays);

    status = LdrLoadDll(NULL, 0, &usWays, &hWaysModule);
    if (status != 0) {
        DbgPrint("[OnKernel32Loaded] LdrLoadDll on ways.dll returned 0x%08X\r\n", status);
        CbDisplayMessageW(L"Error", L"Error loading MagicWays DLL", CbSeverityError);
        s_Die();
    }

    DbgPrint("[OnKernel32Loaded] Loaded ways.dll\r\n");

    pszConfigFilePathBuffer = CbGetSymbolAddress(hWaysModule, "ConfigFilePath");
    if (pszConfigFilePathBuffer == NULL) {
        CbDisplayMessageW(L"Error", L"Could not find config file path buffer in MagicWays DLL", CbSeverityError);
        s_Die();
    }

    DbgPrint("[OnKernel32Loaded] ConfigFilePath buffer found in ways.dll at 0x%08X\r\n", pszConfigFilePathBuffer);
    DbgPrint("[OnKernel32Loaded] Config file path: %s\r\n", ConfigFilePath);

    memcpy(pszConfigFilePathBuffer, ConfigFilePath, MAX_PATH);

    DbgPrint("[OnKernel32Loaded] Config file path copied to ways.dll\r\n");

    procWaysDLLMain = CbGetImageEntryPoint(hWaysModule);
    if (procWaysDLLMain == NULL) {
        CbDisplayMessageW(L"Error", L"Could not find entry point of MagicWays DLL", CbSeverityError);
        s_Die();
    }

    DbgPrint("[OnKernel32Loaded] Ways.dll entry point at 0x%08X\r\n", procWaysDLLMain);

    if (!procWaysDLLMain(hWaysModule, DLL_PROCESS_ATTACH, NULL)) {
        DbgPrint("[OnKernel32Loaded] Ways.dll main function returned FALSE! Last WinAPI error: 0x%08X\r\n", CbLastWinAPIError);
        CbDisplayMessageW(L"Error", L"MagicWays DLL was unable to start", CbSeverityError);
        s_Die();
    }

    DbgPrint("[OnKernel32Loaded] MagicWays loaded successfully\r\n");
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
    NtTerminateProcess((HANDLE)-1, (NTSTATUS)-1);
    NtTerminateProcess(0, (NTSTATUS)-1);
    __asm INT 3;
}

#if 0

// searches only current dir, app dir, and this dll's dir
// will null terminate path
static BOOL s_MiniFindDLL(LPCWSTR pcwzName, OUT PUNICODE_STRING pusFullPath) {
    NTSTATUS status;
    PVOID pImageBase;
    BYTE arrSectionNameBuffer[MAX_PATH * 3];
    ULONG nBytes;

    DbgPrint("[MiniFindDLL] Searching for %ws\r\n", pcwzName);

    // current dir
    do {
        pusFullPath->Length = RtlGetCurrentDirectory_U(pusFullPath->MaximumLength, pusFullPath->Buffer);
        if (pusFullPath->Length == 0) break;

        DbgPrint("[MiniFindDLL] Current dir: %wZ\r\n", pusFullPath);

        if (pusFullPath->Buffer[pusFullPath->Length - 1] != '\\')
            if (!s_ConcatUniW(pusFullPath, L"\\")) break;
        if (!s_ConcatUniW(pusFullPath, pcwzName)) break;

        if (RtlDoesFileExists_U(pusFullPath->Buffer))
            goto L_found;

        DbgPrint("[MiniFindDLL] Not found at %wZ\r\n", pusFullPath);
    } while (0);


    // process executable dir
    do {
        pImageBase = ((PPEB_FULL)CbGetTEB())->ImageBaseAddress;
        DbgPrint("[MiniFindDLL] Process image base at 0x%08X\r\n", (UINT_PTR)pImageBase);
        if (pImageBase == NULL) break;

        status = NtQueryVirtualMemory(MG_CURRENT_PROCESS, pImageBase, MemorySectionName, arrSectionNameBuffer, sizeof(arrSectionNameBuffer),
            &nBytes);
        if (status != 0) {
            DbgPrint("[MiniFindDLL] NtQueryVirtualMemory on 0x%08X returned 0x%08X\r\n", (UINT_PTR)pImageBase, status);
            break;
        }


    } while (0);

L_found:
    DbgPrint("[MiniFindDLL] Found at: %wZ\r\n", pusFullPath);
    return TRUE;
}

// returns false if string can't fit
// will null terminate string
static BOOL s_ConcatUniW(PUNICODE_STRING pusTarget, LPCWSTR pcwzToConcat) {
    int nChars;

    nChars = wcslen(pcwzToConcat);
    if (nChars >= (pusTarget->MaximumLength - pusTarget->MaximumLength))
        return FALSE;

    memcpy(&pusTarget->Buffer[pusTarget->Length], pcwzToConcat, nChars * sizeof(WCHAR));
    return TRUE;
}

// will null terminate string unless final character is a backslash
static void s_RemoveFilenameUni(PUNICODE_STRING pusTarget) {
    LPWSTR pwzCur;

    for (pwzCur = pusTarget->Buffer + pusTarget->Length; pwzCur >= pusTarget->Buffer; pwzCur--) {
        if (*pwzCur == '\\')
            return;
        *pwzCur = 0;
    }
}

#endif
