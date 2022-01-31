#include <CommandLineToArgv.h>
#include <FilePaths.h>
#include <ConfigReading.h>
#include <RewriteImports.h>
#include <InjectDLL.h>
#include <HookFunction.h>

//#define SHIMMER_WAIT_BEFORE_BEGIN
#define SHIMMER_WAIT_BEFORE_RESUME

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <winternl.h> // PEB
#include <Psapi.h>

#define CB_NTDLL_NO_TYPES
#define CB_NTDLL_NO_FUNCS
#include <NTDLL.h>

static BOOL s_ReadMemory(EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData);
static BOOL s_WriteMemory(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData);
static LPCSTR s_GetDLLReplacement(LPCSTR pcszName, LPVOID pUserData);
static void s_DisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...);

// considering ENTRY_POINT isn't supposed to really be a function, it doesn't need to be reentrant
static STARTUPINFOA s_infStartup = { 0 };
static PROCESS_INFORMATION s_infProcess = { 0 };
static LPSTR s_pszCommandLine;
static CONTEXT s_ctxThreadZero;
static EXTERNAL_PTR s_xpPEB, s_xpImageBase, s_xpMorningBase, s_xpNewEntryPoint, s_xpOldEntryPointStorage, s_xpOldEntryPoint,
	s_xpMorningNTDLLAddrVar, s_xpLdrInitializeThunk, s_xpNewInitThunk, s_xpMorningOldInitThunkVar;
static PEB s_peb;
static SIZE_T s_nBytesRead;
static char s_szINIPath[MAX_PATH + 1] = { 0 };
static char s_szRedirDLLName[MAX_PATH + 1] = { 0 };
static PaModuleHandle s_hMorningGlory, s_hNTDLL;
static PLDR_DATA_TABLE_ENTRY_FULL s_pentMyModule;
static DWORD s_nOldNTDLLAddrVarProt;
static BYTE s_arrOldInitThunkCode[PA_REPLACEFUNC_CODESIZE] = { 0xCC, 0x02 }; // default to INT3, 0x02 indicates written by shimmer

void ENTRY_POINT(void) {
	// the rest of the command line after our own executable's name gets passed on directly
	s_pszCommandLine = (LPSTR)CbGetNextArgument(GetCommandLineA(), '^');

#ifdef SHIMMER_WAIT_BEFORE_BEGIN
	printf("Press any key to start...\r\n");
	(void)getchar();
#endif

	s_infStartup.cb = sizeof(s_infStartup);
	if (!CreateProcessA(NULL, s_pszCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &s_infStartup, &s_infProcess)) {
		printf("Error %08X running command: %s\r\n", GetLastError(), s_pszCommandLine);
		ExitProcess(1);
	}

	printf("Process ID: %d\r\n", GetProcessId(s_infProcess.hProcess));

	// we need the process to find the config file if it's next to the process
	if (!PaFindConfigFile("shims.ini", s_infProcess.hProcess, s_szINIPath, sizeof(s_szINIPath))) {
		printf("Error: Could not find config file next to target executable or shimmer executable\r\n");
		goto L_errorexit;
	}

	printf("Using config file: %s\r\n", s_szINIPath);

	// http://www.rohitab.com/discuss/topic/40262-dynamic-forking-process-hollowing/
	// "The eax register is the entry point of the process's executable, and the ebx register is the address of the process's PEB."
	// (The "entry point" in that quote isn't the base thunk, it's the "real" entry point)
	s_ctxThreadZero.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(s_infProcess.hThread, &s_ctxThreadZero)) {
		printf("Error 0x%08X querying thread context\r\n", GetLastError());
		goto L_errorexit;
	}

	s_xpPEB = (EXTERNAL_PTR)s_ctxThreadZero.Ebx;
	s_xpOldEntryPoint = (EXTERNAL_PTR)s_ctxThreadZero.Eip;
	printf("Process environment block at: 0x%08X\r\n", (uintptr_t)s_xpPEB);

	if (!ReadProcessMemory(s_infProcess.hProcess, s_xpPEB, &s_peb, sizeof(s_peb), &s_nBytesRead)) {
		printf("Error 0x%08X reading process environment block\r\n", GetLastError());
		goto L_errorexit;
	}

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
	// offset 0x08 (0x10 on 64-bit) is PVOID ImageBaseAddress; on all Windows versions
	s_xpImageBase = s_peb.Reserved3[1];
	printf("Image base at: 0x%08X\r\n", (uintptr_t)s_xpImageBase);

	// replace the imports
	if (!PaRewriteImports(s_xpImageBase, s_ReadMemory, s_WriteMemory, s_GetDLLReplacement, s_DisplayMessage, s_DisplayMessage, NULL)) {
		puts("Import replacement failed");
		goto L_errorexit;
	}

	// open pre-load dll
	s_hMorningGlory = PaModuleOpen("morning.dll", s_DisplayMessage, s_DisplayMessage, NULL);
	if (s_hMorningGlory == NULL) {
		printf("Error 0x%08X loading morning.dll\r\n", GetLastError());
		goto L_errorexit;
	}

	printf("MorningGlory DLL: %s\r\n", PaModuleGetFilePath(s_hMorningGlory));

	// inject into process
	s_xpMorningBase = PaInjectWithoutLoad(s_hMorningGlory, s_infProcess.hProcess, FALSE);
	if (s_xpMorningBase == NULL) {
		printf("Error 0x%08X injecting morning.dll\r\n", GetLastError());
		goto L_errorexit;
	}

	printf("Injected into process at address 0x%08X\r\n", (UINT_PTR)s_xpMorningBase);

	// give morning glory the NTDLL base addr so it can call functions
	s_xpMorningNTDLLAddrVar = PaGetRemoteSymbol(s_hMorningGlory, s_xpMorningBase, "NTDLLBaseAddress");
	printf("Remote: NTDLL base var at 0x%08X\r\n", (UINT_PTR)s_xpMorningNTDLLAddrVar);
	printf("Global: NTDLL base at 0x%08X\r\n", (UINT_PTR)CbGetNTDLLBaseAddress());

	/*if (!VirtualProtectEx(s_infProcess.hProcess, s_xpMorningNTDLLAddrVar, sizeof(CbNTDLLBaseAddress), PAGE_READWRITE, &s_nOldNTDLLAddrVarProt)) {
		printf("Error 0x%08X making remote variable of size %u at location 0x%08X writable\r\n", GetLastError(),
			sizeof(CbNTDLLBaseAddress), (UINT_PTR)s_xpMorningNTDLLAddrVar);
		goto L_errorexit;
	}*/

	if (!WriteProcessMemory(s_infProcess.hProcess, s_xpMorningNTDLLAddrVar, &CbNTDLLBaseAddress, sizeof(CbNTDLLBaseAddress), &s_nBytesRead)) {
		printf("Error 0x%08X writing NTDLL base address to remote variable of size %u at location 0x%08X\r\n", GetLastError(),
			sizeof(CbNTDLLBaseAddress), (UINT_PTR)s_xpMorningNTDLLAddrVar);
		goto L_errorexit;
	}

	// store old entry point
	s_xpOldEntryPointStorage = PaGetRemoteSymbol(s_hMorningGlory, s_xpMorningBase, "ProcessStartThunk");
	if (s_xpOldEntryPointStorage == NULL) {
		printf("Could not find ProcessStartThunk symbol in morning.dll (error 0x%08X)\r\n", GetLastError());
		goto L_errorexit;
	}

	printf("Storing old entry point 0x%08X at address 0x%08X\r\n", (UINT_PTR)s_xpOldEntryPoint, (UINT_PTR)s_xpOldEntryPointStorage);
	
	if (!s_WriteMemory(&s_xpOldEntryPoint, s_xpOldEntryPointStorage, sizeof(s_xpOldEntryPoint), NULL)) {
		printf("Error 0x%08X writing old entry point to address 0x%08X\r\n", GetLastError(), (UINT_PTR)s_xpOldEntryPointStorage);
		goto L_errorexit;
	}

	// find new entry point
	s_xpNewEntryPoint = PaGetRemoteSymbol(s_hMorningGlory, s_xpMorningBase, "ProcessEntryPoint");
	if (s_xpNewEntryPoint == NULL) {
		printf("Could not find ProcessEntryPoint symbol in morning.dll (error 0x%08X)\r\n", GetLastError());
		goto L_errorexit;
	}

	// replace instruction pointer
	s_ctxThreadZero.Eip = (DWORD)s_xpNewEntryPoint;
	s_ctxThreadZero.ContextFlags = CONTEXT_CONTROL;
	if (!SetThreadContext(s_infProcess.hThread, &s_ctxThreadZero)) {
		printf("Error 0x%08X setting context of thread %u\r\n", GetLastError(), s_infProcess.dwThreadId);
		goto L_errorexit;
	}

	// replace LdrInitializeThunk
	s_hNTDLL = PaModuleOpen("ntdll.dll", s_DisplayMessage, s_DisplayMessage, NULL);
	if (s_hNTDLL == NULL) {
		printf("Error 0x%08X opening NTDLL as module\r\n", GetLastError());
		goto L_errorexit;
	}

	s_xpNewInitThunk = PaGetRemoteSymbol(s_hMorningGlory, s_xpMorningBase, "ProcessInitThunk");
	if (s_xpNewInitThunk == NULL) {
		printf("Error 0x%08X determining remote address of ProcessInitThunk\r\n", GetLastError());
		goto L_errorexit;
	}

	s_xpLdrInitializeThunk = PaGetRemoteSymbol(s_hNTDLL, PaModuleGetBaseAddress(s_hNTDLL), "LdrInitializeThunk");
	if (!PaReplaceFunctionEx(s_infProcess.hProcess, s_xpLdrInitializeThunk, s_xpNewInitThunk, s_arrOldInitThunkCode)) {
		printf("Error 0x%08X replacing LdrInitializeThunk at 0x%08X with new initialization thunk at 0x%08X\r\n", GetLastError(),
			(UINT_PTR)s_xpLdrInitializeThunk, (UINT_PTR)s_xpNewInitThunk);
		goto L_errorexit;
	}

	// save old init thunk code
	s_xpMorningOldInitThunkVar = PaGetRemoteSymbol(s_hMorningGlory, s_xpMorningBase, "InitThunkCode");
	if (s_xpMorningOldInitThunkVar == NULL) {
		printf("Error 0x%08X determining remote address of InitThunkCode\r\n", GetLastError());
		goto L_errorexit;
	}

	if (!WriteProcessMemory(s_infProcess.hProcess, s_xpMorningOldInitThunkVar, s_arrOldInitThunkCode, PA_REPLACEFUNC_CODESIZE, &s_nBytesRead)) {
		printf("Error 0x%08X writing old initialization thunk code (%u bytes) to remote address 0x%08X\r\n", GetLastError(),
			PA_REPLACEFUNC_CODESIZE, (UINT_PTR)s_xpMorningOldInitThunkVar);
		goto L_errorexit;
	}


#ifdef SHIMMER_WAIT_BEFORE_RESUME
	printf("Press any key to allow process to run.\r\n");
	(void)getchar();
#endif

	// let it run
	if (ResumeThread(s_infProcess.hThread) == -1) {
		printf("Error 0x%08X running process\r\n", GetLastError());
		goto L_errorexit;
	}

	puts("Done, process is running.");
	ExitProcess(0);

L_errorexit:
	puts("Aborting.");
	TerminateProcess(s_infProcess.hProcess, (UINT)-1);
	ExitProcess(1);
}

static BOOL s_ReadMemory(EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData) {
	return ReadProcessMemory(s_infProcess.hProcess, pDestBase, pDestBuffer, nSize, &s_nBytesRead);
}

static BOOL s_WriteMemory(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData) {
	DWORD nOldProt, nError;

	if (!VirtualProtectEx(s_infProcess.hProcess, pDestBase, nSize, PAGE_READWRITE, &nOldProt)) {
		nError = GetLastError();
		printf("[WriteMemory] VirtualProtectEx (PAGE_READWRITE) on %u bytes at 0x%08X returned error 0x%08X", nSize, (uintptr_t)pDestBase, nError);
		SetLastError(nError);
		return FALSE;
	}

	if (!WriteProcessMemory(s_infProcess.hProcess, pDestBase, pSrcBuffer, nSize, &s_nBytesRead)) {
		nError = GetLastError();
		printf("[WriteMemory] WriteProcessMemory on %u bytes at 0x%08X returned error 0x%08X", nSize, (uintptr_t)pDestBase, nError);
		SetLastError(nError);
		return FALSE;
	}

	if (!VirtualProtectEx(s_infProcess.hProcess, pDestBase, nSize, nOldProt, &nOldProt)) {
		nError = GetLastError();
		printf("[WriteMemory] VirtualProtectEx (0x%08X) on %u bytes at 0x%08X returned error 0x%08X", nOldProt, nSize, (uintptr_t)pDestBase, nError);
		SetLastError(nError);
		return FALSE;
	}

	return TRUE;
}

static LPCSTR s_GetDLLReplacement(LPCSTR pcszName, LPVOID pUserData) {
	return GetPrivateProfileStringA("RedirectDLLs", pcszName, "", s_szRedirDLLName, sizeof(s_szRedirDLLName) - 1, s_szINIPath)
		? s_szRedirDLLName : NULL;
}

static void s_DisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...) {
	va_list va;
	va_start(va, pcszFormat);
	vprintf(pcszFormat, va);
	va_end(va);
}

// for ways.dll
__declspec(dllexport) int NoRedirectImports = 1;
__declspec(dllimport) extern int WaysDummy;
__declspec(dllexport) int __stdcall Dummy(void) { return WaysDummy; }
