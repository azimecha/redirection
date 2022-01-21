#include "RewriteImports.h"
#include <FilePaths.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h> // FOURCC

BOOL PaRewriteImports(EXTERNAL_PTR xpImageBase, PaReadMemoryProc procReadMemory, PaWriteMemoryProc procWriteMemory,
	PaGetReplacementProc procGetDLLReplacement, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError,
	LPVOID pUserData)
{
	LPVOID xpNTHeaders, xpImports, xpImportDLLName;
	IMAGE_DOS_HEADER hdrDOS;
	IMAGE_NT_HEADERS hdrNT;
	PIMAGE_IMPORT_DESCRIPTOR pdescImports, pdescCurImport;
	DWORD nSizeImports;
	char szImportDLLName[MAX_PATH + 1];
	char szNormalizedImportDLLName[MAX_PATH + 1];
	BOOL bSucceeded;
	LPCSTR pcszReplacementDLL;

	bSucceeded = FALSE;

	// read the DOS header and find the NT header
	if (!procReadMemory(xpImageBase, sizeof(hdrDOS), &hdrDOS, pUserData)) {
		procDisplayError(pUserData, "Error 0x%08X reading image DOS header\r\n", GetLastError());
		return FALSE;
	}

	if (hdrDOS.e_magic != MAKEWORD('M', 'Z')) {
		procDisplayError(pUserData, "Image DOS header does not start with MZ");
		return FALSE;
	}

	xpNTHeaders = (LPBYTE)xpImageBase + hdrDOS.e_lfanew;
	procDisplayInfo(pUserData, "NT headers at: 0x%08X\r\n", (uintptr_t)xpNTHeaders);

	// read the NT header and find the import directory
	if (!procReadMemory(xpNTHeaders, sizeof(hdrNT), &hdrNT, pUserData)) {
		procDisplayError(pUserData, "Error 0x%08X reading image NT headers\r\n", GetLastError());
		return FALSE;
	}

	if (hdrNT.Signature != mmioFOURCC('P', 'E', 0, 0)) {
		procDisplayError(pUserData, "Image NT header does not start with PE\r\n");
		return FALSE;
	}

	if (hdrNT.OptionalHeader.NumberOfRvaAndSizes < 2) {
		procDisplayError(pUserData, "Image has no import directory (directory count is %u)\r\n", hdrNT.OptionalHeader.NumberOfRvaAndSizes);
		return FALSE;
	}

	xpImports = (LPBYTE)xpImageBase + hdrNT.OptionalHeader.DataDirectory[1].VirtualAddress;
	nSizeImports = hdrNT.OptionalHeader.DataDirectory[1].Size;
	procDisplayInfo(pUserData, "Import directory: location 0x%08X, size %u\r\n", (uintptr_t)xpImports, (uintptr_t)nSizeImports);

	// read the import directory
	pdescImports = HeapAlloc(GetProcessHeap(), 0, nSizeImports);
	if (pdescImports == NULL) {
		procDisplayError(pUserData, "Error 0x%08X allocating memory for import directory table\r\n", GetLastError());
		goto L_exit;
	}

	if (!procReadMemory(xpImports, nSizeImports, pdescImports, pUserData)) {
		procDisplayError(pUserData, "Error 0x%08X reading import directory table\r\n", GetLastError());
		goto L_exit;
	}

	// iterate through the imports
	for (pdescCurImport = pdescImports; pdescCurImport->Name != 0; pdescCurImport++) {
		xpImportDLLName = (BYTE*)xpImageBase + pdescCurImport->Name;
		procDisplayInfo(pUserData, "Import: name at 0x%08X -> ", (uintptr_t)xpImportDLLName);

		// read and normalize the import dll name
		if (!procReadMemory(xpImportDLLName, sizeof(szImportDLLName) - 1, szImportDLLName, pUserData)) {
			procDisplayError(pUserData, "\tError 0x%08X reading imported DLL name\r\n", GetLastError());
			goto L_exit;
		}

		strcpy(szNormalizedImportDLLName, szImportDLLName);
		CbPathRemoveExtensionA(szNormalizedImportDLLName);
		CbStringToLowerA(szNormalizedImportDLLName);
		procDisplayInfo(pUserData, "%s (%s)\r\n", szImportDLLName, szNormalizedImportDLLName);

		// check if it's in the list
		pcszReplacementDLL = procGetDLLReplacement(szNormalizedImportDLLName, pUserData);
		if (pcszReplacementDLL == NULL)
			continue; // nope, let it be

		// replace it
		if (strlen(pcszReplacementDLL) > strlen(szImportDLLName)) {
			procDisplayError(pUserData, "\tError: Cannot replace \"%s\" with \"%s\" because the replacement name is longer than the original name",
				szImportDLLName, pcszReplacementDLL);
			goto L_exit;
		}

		//if (!WriteProcessMemory(infProcess.hProcess, xpImportDLLName, szRedirDLLName, strlen(szRedirDLLName) + 1, &nBytesRead)) {
		if (!procWriteMemory(pcszReplacementDLL, xpImportDLLName, strlen(pcszReplacementDLL) + 1, pUserData)) {
			procDisplayError(pUserData, "\tError 0x%08X writing new DLL name \"%s\"\r\n", GetLastError(), pcszReplacementDLL);
			goto L_exit;
		}

		procDisplayInfo(pUserData, "\tReplaced with %s\r\n", pcszReplacementDLL);
	}

	bSucceeded = TRUE;

L_exit:
	HeapFree(GetProcessHeap(), 0, pdescImports);
	return bSucceeded;
}
