#include "RewriteImports.h"
#include <FilePaths.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h> // FOURCC

typedef struct _struct_PaRewriteFuncs{
	PaReadMemoryProc procReadMemory;
	PaWriteMemoryProc procWriteMemory;
	PaGetReplacementProc procGetDLLReplacement;
	PaDisplayMessageProc procDisplayInfo;
	PaDisplayMessageProc procDisplayError;
	LPVOID pUserData;
} PaRewriteFuncs_t, *PaRewriteFuncs_p;

static BOOL s_RewriteTable(EXTERNAL_PTR xpTable, DWORD nTableSize, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs);
static BOOL s_RewriteTableDirect(PIMAGE_IMPORT_DESCRIPTOR pdescImports, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs);

BOOL PaRewriteImports(EXTERNAL_PTR xpImageBase, PaReadMemoryProc procReadMemory, PaWriteMemoryProc procWriteMemory,
	PaGetReplacementProc procGetDLLReplacement, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError,
	LPVOID pUserData)
{
	LPVOID xpNTHeaders, xpImports;
	IMAGE_DOS_HEADER hdrDOS;
	IMAGE_NT_HEADERS hdrNT;
	DWORD nSizeImports;
	BOOL bSucceeded;
	PaRewriteFuncs_t funcs;

	bSucceeded = FALSE;
	funcs.procReadMemory = procReadMemory;
	funcs.procWriteMemory = procWriteMemory;
	funcs.procGetDLLReplacement = procGetDLLReplacement;
	funcs.procDisplayInfo = procDisplayInfo;
	funcs.procDisplayError = procDisplayError;
	funcs.pUserData = pUserData;

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

	return s_RewriteTable(xpImports, nSizeImports, xpImageBase, &funcs);
}

static BOOL s_RewriteTable(EXTERNAL_PTR xpTable, DWORD nTableSize, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs) {
	PIMAGE_IMPORT_DESCRIPTOR pdescImports;
	BOOL bSucceeded;

	bSucceeded = FALSE;

	pdescImports = HeapAlloc(GetProcessHeap(), 0, nTableSize);
	if (pdescImports == NULL) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X allocating memory for import directory table\r\n", GetLastError());
		return FALSE;
	}

	if (!pfuncs->procReadMemory(xpTable, nTableSize, pdescImports, pfuncs->pUserData)) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X reading import directory table\r\n", GetLastError());
		goto L_exit;
	}

	bSucceeded = s_RewriteTableDirect(pdescImports, xpImageBase, pfuncs);

L_exit:
	HeapFree(GetProcessHeap(), 0, pdescImports);
	return bSucceeded;
}

static BOOL s_RewriteTableDirect(PIMAGE_IMPORT_DESCRIPTOR pdescImports, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs) {
	char szImportDLLName[MAX_PATH + 1];
	char szNormalizedImportDLLName[MAX_PATH + 1];
	LPCSTR pcszReplacementDLL;
	EXTERNAL_PTR xpImportDLLName;

	// iterate through the imports
	for (pdescImports; pdescImports->Name != 0; pdescImports++) {
		xpImportDLLName = (BYTE*)xpImageBase + pdescImports->Name;
		pfuncs->procDisplayInfo(pfuncs->pUserData, "Import: name at 0x%08X -> ", (uintptr_t)xpImportDLLName);

		// read and normalize the import dll name
		if (!pfuncs->procReadMemory(xpImportDLLName, sizeof(szImportDLLName) - 1, szImportDLLName, pfuncs->pUserData)) {
			pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X reading imported DLL name\r\n", GetLastError());
			return FALSE;
		}

		strcpy(szNormalizedImportDLLName, szImportDLLName);
		CbPathRemoveExtensionA(szNormalizedImportDLLName);
		CbStringToLowerA(szNormalizedImportDLLName);
		pfuncs->procDisplayInfo(pfuncs->pUserData, "%s (%s)\r\n", szImportDLLName, szNormalizedImportDLLName);

		// check if it's in the list
		pcszReplacementDLL = pfuncs->procGetDLLReplacement(szNormalizedImportDLLName, pfuncs->pUserData);
		if (pcszReplacementDLL == NULL)
			continue; // nope, let it be

		// replace it
		if (strlen(pcszReplacementDLL) > strlen(szImportDLLName)) {
			pfuncs->procDisplayError(pfuncs->pUserData,
				"\tError: Cannot replace \"%s\" with \"%s\" because the replacement name is longer than the original name",
				szImportDLLName, pcszReplacementDLL);
			return FALSE;
		}

		if (!pfuncs->procWriteMemory(pcszReplacementDLL, xpImportDLLName, strlen(pcszReplacementDLL) + 1, pfuncs->pUserData)) {
			pfuncs->procDisplayError(pfuncs->pUserData, "\tError 0x%08X writing new DLL name \"%s\"\r\n", GetLastError(), pcszReplacementDLL);
			return FALSE;
		}

		pfuncs->procDisplayInfo(pfuncs->pUserData, "\tReplaced with %s\r\n", pcszReplacementDLL);
	}

	return TRUE;
}
