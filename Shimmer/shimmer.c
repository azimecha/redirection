#include <CommandLineToArgv.h>
#include <FilePaths.h>
#include <ConfigReading.h>
#include <RewriteImports.h>

//#define SHIMMER_WAIT_BEFORE_BEGIN
#define SHIMMER_WAIT_BEFORE_RESUME

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <winternl.h> // PEB
#include <Psapi.h>

static BOOL s_ReadMemory(EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData);
static BOOL s_WriteMemory(LPCVOID pSrcBuffer, EXTERNAL_PTR pDestBase, SIZE_T nSize, LPVOID pUserData);
static LPCSTR s_GetDLLReplacement(LPCSTR pcszName, LPVOID pUserData);
static void s_DisplayMessage(LPVOID pUserData, LPCSTR pcszFormat, ...);

// considering ENTRY_POINT isn't supposed to really be a function, it doesn't need to be reentrant
static STARTUPINFOA s_infStartup = { 0 };
static PROCESS_INFORMATION s_infProcess = { 0 };
static LPSTR s_pszCommandLine;
static CONTEXT s_ctxThreadZero;
static EXTERNAL_PTR s_xpPEB, s_xpImageBase;
static PEB s_peb;
static SIZE_T s_nBytesRead;
static char s_szINIPath[MAX_PATH + 1] = { 0 };
static char s_szRedirDLLName[MAX_PATH + 1] = { 0 };

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
	s_ctxThreadZero.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(s_infProcess.hThread, &s_ctxThreadZero)) {
		printf("Error 0x%08X querying thread context\r\n", GetLastError());
		goto L_errorexit;
	}

	s_xpPEB = (EXTERNAL_PTR)s_ctxThreadZero.Ebx;
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

#ifdef SHIMMER_WAIT_BEFORE_RESUME
	printf("Imports have been replaced. Press any key to allow process to run.\r\n");
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
