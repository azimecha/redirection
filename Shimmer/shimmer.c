#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <winternl.h> // PEB
#include <Vfw.h> // fourcc
#include <Psapi.h>

#include <CommandLineToArgv.h>
#include <FilePaths.h>
#include <ConfigReading.h>

// designates pointer in another process
typedef void* EXTERNAL_PTR;

void ENTRY_POINT(void) {
	static STARTUPINFOA infStartup;
	static PROCESS_INFORMATION infProcess;
	static LPSTR pszCommandLine;
	static CONTEXT ctxThreadZero;
	static EXTERNAL_PTR xpPEB, xpImageBase, xpNTHeaders, xpImports, xpImportDLLName;
	static PEB peb;
	static SIZE_T nBytesRead;
	static IMAGE_DOS_HEADER hdrDOS;
	static IMAGE_NT_HEADERS hdrNT;
	static PIMAGE_IMPORT_DESCRIPTOR pdescImports, pdescCurImport;
	static DWORD nSizeImports;
	static char szImportDLLName[MAX_PATH + 1];
	static char szNormalizedImportDLLName[MAX_PATH + 1];
	static char szRedirDLLName[MAX_PATH + 1];
	static char szINIPath[MAX_PATH + 1];

	RtlSecureZeroMemory(&infStartup, sizeof(infStartup));
	RtlSecureZeroMemory(&infProcess, sizeof(infProcess));
	RtlSecureZeroMemory(&ctxThreadZero, sizeof(ctxThreadZero));
	RtlSecureZeroMemory(szImportDLLName, sizeof(szImportDLLName));
	
	// the rest of the command line after our own executable's name gets passed on directly
	pszCommandLine = (LPSTR)CbGetNextArgument(GetCommandLineA(), '^');

	infStartup.cb = sizeof(infStartup);
	if (!CreateProcessA(NULL, pszCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &infStartup, &infProcess)) {
		printf("Error %08X running command: %s\r\n", GetLastError(), pszCommandLine);
		ExitProcess(1);
	}

	printf("Process ID: %d\r\n", GetProcessId(infProcess.hProcess));

	// we need the process to find the config file if it's next to the process
	if (!CbFindConfigFile("shims.ini", infProcess.hProcess, szINIPath, sizeof(szINIPath))) {
		printf("Error: Could not find config file next to target executable or shimmer executable\r\n");
		goto L_errorexit;
	}

	printf("Using config file: %s\r\n", szINIPath);

	// http://www.rohitab.com/discuss/topic/40262-dynamic-forking-process-hollowing/
	// "The eax register is the entry point of the process's executable, and the ebx register is the address of the process's PEB."
	ctxThreadZero.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(infProcess.hThread, &ctxThreadZero)) {
		printf("Error 0x%08X querying thread context\r\n", GetLastError());
		goto L_errorexit;
	}

	xpPEB = (EXTERNAL_PTR)ctxThreadZero.Ebx;
	printf("Process environment block at: 0x%08X\r\n", (uintptr_t)xpPEB);

	if (!ReadProcessMemory(infProcess.hProcess, xpPEB, &peb, sizeof(peb), &nBytesRead)) {
		printf("Error 0x%08X reading process environment block\r\n", GetLastError());
		goto L_errorexit;
	}

	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
	// offset 0x08 (0x10 on 64-bit) is PVOID ImageBaseAddress; on all Windows versions
	xpImageBase = peb.Reserved3[1];
	printf("Image base at: 0x%08X\r\n", (uintptr_t)xpImageBase);

	// read the DOS header and find the NT header
	if (!ReadProcessMemory(infProcess.hProcess, xpImageBase, &hdrDOS, sizeof(hdrDOS), &nBytesRead)) {
		printf("Error 0x%08X reading image DOS header\r\n", GetLastError());
		goto L_errorexit;
	}

	if (hdrDOS.e_magic != MAKEWORD('M', 'Z')) {
		puts("Image DOS header does not start with MZ");
		goto L_errorexit;
	}

	xpNTHeaders = (LPBYTE)xpImageBase + hdrDOS.e_lfanew;
	printf("NT headers at: 0x%08X\r\n", (uintptr_t)xpNTHeaders);

	// read the NT header and find the import directory
	if (!ReadProcessMemory(infProcess.hProcess, xpNTHeaders, &hdrNT, sizeof(hdrNT), &nBytesRead)) {
		printf("Error 0x%08X reading image NT headers\r\n", GetLastError());
		goto L_errorexit;
	}

	if (hdrNT.Signature != mmioFOURCC('P', 'E', 0, 0)) {
		puts("Image NT header does not start with PE");
		goto L_errorexit;
	}

	if (hdrNT.OptionalHeader.NumberOfRvaAndSizes < 2) {
		printf("Image has no import directory (directory count is %u)\r\n", hdrNT.OptionalHeader.NumberOfRvaAndSizes);
		goto L_errorexit;
	}

	xpImports = (LPBYTE)xpImageBase + hdrNT.OptionalHeader.DataDirectory[1].VirtualAddress;
	nSizeImports = hdrNT.OptionalHeader.DataDirectory[1].Size;
	printf("Import directory: location 0x%08X, size %u\r\n", (uintptr_t)xpImports, (uintptr_t)nSizeImports);

	// read the import directory
	pdescImports = HeapAlloc(GetProcessHeap(), 0, nSizeImports);
	if (pdescImports == NULL) {
		printf("Error 0x%08X allocating memory for import directory table\r\n", GetLastError());
		goto L_errorexit;
	}

	if (!ReadProcessMemory(infProcess.hProcess, xpImports, pdescImports, nSizeImports, &nBytesRead)) {
		printf("Error 0x%08X reading import directory table\r\n", GetLastError());
		goto L_errorexit;
	}

	// iterate through the imports
	for (pdescCurImport = pdescImports; pdescCurImport->Name != 0; pdescCurImport++) {
		xpImportDLLName = (BYTE*)xpImageBase + pdescCurImport->Name;
		printf("Import: name at 0x%08X -> ", (uintptr_t)xpImportDLLName);

		// read and normalize the import dll name
		if (!ReadProcessMemory(infProcess.hProcess, xpImportDLLName, szImportDLLName, sizeof(szImportDLLName) - 1, &nBytesRead)) {
			printf("\tError 0x%08X reading imported DLL name\r\n", GetLastError());
			goto L_errorexit;
		}

		strcpy(szNormalizedImportDLLName, szImportDLLName);
		CbPathRemoveExtensionA(szNormalizedImportDLLName);
		CbStringToLowerA(szNormalizedImportDLLName);
		printf("%s (%s)\r\n", szImportDLLName, szNormalizedImportDLLName);

		// check if it's in the list
		if (GetPrivateProfileStringA("RedirectDLLs", szNormalizedImportDLLName, "", szRedirDLLName, sizeof(szRedirDLLName) - 1, szINIPath) == 0)
			continue; // nope, let it be

		// replace it
		if (strlen(szRedirDLLName) > strlen(szImportDLLName)) {
			printf("\tError: Cannot replace \"%s\" with \"%s\" because the replacement name is longer than the original name",
				szImportDLLName, szRedirDLLName);
			goto L_errorexit;
		}

		if (!WriteProcessMemory(infProcess.hProcess, xpImportDLLName, szRedirDLLName, strlen(szRedirDLLName) + 1, &nBytesRead)) {
			printf("\tError 0x%08X writing new DLL name \"%s\"\r\n", GetLastError(), szRedirDLLName);
			goto L_errorexit;
		}

		printf("\tReplaced with %s\r\n", szRedirDLLName);
	}

	// let it run
	if (ResumeThread(infProcess.hThread) == -1) {
		printf("Error 0x%08X running process\r\n", GetLastError());
		goto L_errorexit;
	}

	puts("Done, process is running.");
	ExitProcess(0);

L_errorexit:
	puts("Aborting.");
	TerminateProcess(infProcess.hProcess, (UINT)-1);
	ExitProcess(1);
}
