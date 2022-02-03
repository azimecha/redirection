#include "RewriteImports.h"
#include <FilePaths.h>
#include <ImportHelper.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h> // FOURCC
#include <winternl.h>

#define CB_NTDLL_NO_TYPES
#define CB_NTDLL_NO_FUNCS
#include <NTDLL.h>

typedef struct _struct_PaRewriteFuncs{
	PaReadMemoryProc procReadMemory;
	PaWriteMemoryProc procWriteMemory;
	PaGetReplacementProc procGetDLLReplacement;
	PaDisplayMessageProc procDisplayInfo;
	PaDisplayMessageProc procDisplayError;
	LPVOID pUserData;
} PaRewriteFuncs_t, *PaRewriteFuncs_p;

typedef BOOL(* DataDirOperation_t)(LPVOID pDirData, DWORD nDirStartRVA, DWORD nDirSize, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs);
static BOOL s_RewriteDataDirectory(PIMAGE_NT_HEADERS phdrNT, DWORD nDirectory, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs,
	DataDirOperation_t procOperation);

static BOOL s_ReplaceDLLNames(PIMAGE_IMPORT_DESCRIPTOR pdescImports, DWORD nDirStartRVA, DWORD nDirSize, EXTERNAL_PTR xpImageBase, 
	PaRewriteFuncs_p pfuncs);
static BOOL s_FixBadForwards(PIMAGE_EXPORT_DIRECTORY pdescExports, DWORD nDirStartRVA, DWORD nDirSize, EXTERNAL_PTR xpImageBase, 
	PaRewriteFuncs_p pfuncs);

static const char s_cszBadForwardPrefix[] = ".dll";

// no kernel32 calls (unless callbacks do)
BOOL PaRewriteImports(EXTERNAL_PTR xpImageBase, PaReadMemoryProc procReadMemory, PaWriteMemoryProc procWriteMemory,
	PaGetReplacementProc procGetDLLReplacement, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError,
	LPVOID pUserData)
{
	LPVOID xpNTHeaders;
	IMAGE_DOS_HEADER hdrDOS;
	IMAGE_NT_HEADERS hdrNT;
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
		procDisplayError(pUserData, "Error 0x%08X reading image DOS header\r\n", CbLastWinAPIError);
		return FALSE;
	}

	if (hdrDOS.e_magic != MAKEWORD('M', 'Z')) {
		procDisplayError(pUserData, "Image DOS header does not start with MZ");
		return FALSE;
	}

	xpNTHeaders = (LPBYTE)xpImageBase + hdrDOS.e_lfanew;
	procDisplayInfo(pUserData, "NT headers at: 0x%08X\r\n", (uintptr_t)xpNTHeaders);

	// read the NT header
	if (!procReadMemory(xpNTHeaders, sizeof(hdrNT), &hdrNT, pUserData)) {
		procDisplayError(pUserData, "Error 0x%08X reading image NT headers\r\n", CbLastWinAPIError);
		return FALSE;
	}


	if (hdrNT.Signature != mmioFOURCC('P', 'E', 0, 0)) {
		procDisplayError(pUserData, "Image NT header does not start with PE\r\n");
		return FALSE;
	}

#if 0
	// fix system version
	hdrNT.OptionalHeader.MajorOperatingSystemVersion = 5;
	hdrNT.OptionalHeader.MinorOperatingSystemVersion = 0;
	hdrNT.OptionalHeader.MajorSubsystemVersion = 5;
	hdrNT.OptionalHeader.MinorSubsystemVersion = 0;
	if (!procWriteMemory(&hdrNT, xpNTHeaders, sizeof(hdrNT), pUserData)) {
		procDisplayError(pUserData, "Error 0x%08X writing image NT headers\r\n", GetLastError());
		return FALSE;
	}
#endif

	// redirect imports
	if (!s_RewriteDataDirectory(&hdrNT, 1, xpImageBase, &funcs, s_ReplaceDLLNames))
		return FALSE;

	// fix bad forwards
	return s_RewriteDataDirectory(&hdrNT, 0, xpImageBase, &funcs, s_FixBadForwards);
}

// no kernel32 calls (unless callbacks do)
static BOOL s_RewriteDataDirectory(PIMAGE_NT_HEADERS phdrNT, DWORD nDirectory, EXTERNAL_PTR xpImageBase, PaRewriteFuncs_p pfuncs, 
	DataDirOperation_t procOperation) 
{
	EXTERNAL_PTR xpDirectory;
	DWORD nDirSize, nDirStartRVA;
	LPVOID pData;
	BOOL bSucceeded;

	if (phdrNT->OptionalHeader.NumberOfRvaAndSizes <= nDirectory) {
		pfuncs->procDisplayInfo(pfuncs->pUserData, "Image has no directory %u (directory count is %u)\r\n", nDirectory, 
			phdrNT->OptionalHeader.NumberOfRvaAndSizes);
		return TRUE;
	}

	nDirStartRVA = phdrNT->OptionalHeader.DataDirectory[nDirectory].VirtualAddress;
	xpDirectory = (LPBYTE)xpImageBase + nDirStartRVA;
	nDirSize = phdrNT->OptionalHeader.DataDirectory[nDirectory].Size;
	pfuncs->procDisplayInfo(pfuncs->pUserData, "Data directory %u: location 0x%08X, size %u\r\n", nDirectory, (uintptr_t)xpDirectory, 
		(uintptr_t)nDirSize);

	if (nDirSize == 0) {
		pfuncs->procDisplayInfo(pfuncs->pUserData, "Image has no directory %u (size is 0)\r\n", nDirectory, 
			phdrNT->OptionalHeader.NumberOfRvaAndSizes);
		return TRUE;
	}

	bSucceeded = FALSE;

	pData = CbHeapAllocate(nDirSize, FALSE);
	if (pData == NULL) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X allocating memory for directory %u\r\n", GetLastError(), nDirectory);
		return FALSE;
	}

	if (!pfuncs->procReadMemory(xpDirectory, nDirSize, pData, pfuncs->pUserData)) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X reading directory %u\r\n", GetLastError(), nDirectory);
		goto L_exit;
	}

	bSucceeded = procOperation(pData, nDirStartRVA, nDirSize, xpImageBase, pfuncs);

L_exit:
	CbHeapFree(pData);
	return bSucceeded;
}

// no kernel32 calls (unless callbacks do)
static BOOL s_ReplaceDLLNames(PIMAGE_IMPORT_DESCRIPTOR pdescImports, DWORD nDirStartRVA, DWORD nDirSize, EXTERNAL_PTR xpImageBase, 
	PaRewriteFuncs_p pfuncs)
{
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

// some newer MS DLLs have incorrect forwards - the .dll extension is wrongly included as part of the target DLL name
// for information on how forwards are stored:
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
// ----------
// no kernel32 calls (unless callbacks do)
static BOOL s_FixBadForwards(PIMAGE_EXPORT_DIRECTORY pdirExports, DWORD nDirStartRVA, DWORD nDirSize, EXTERNAL_PTR xpImageBase, 
	PaRewriteFuncs_p pfuncs) 
{
	DWORD nFunction, nFuncAddrsSize;
	BOOL bSucceeded, bIsForward;
	LPDWORD pnFunctionAddrs;
	EXTERNAL_PTR xpFunctionAddrs;
	LPSTR pszForwardTarget;
	LPSTR pszForwardFuncName;

	bSucceeded = FALSE;
	xpFunctionAddrs = (BYTE*)xpImageBase + pdirExports->AddressOfFunctions;
	nFuncAddrsSize = pdirExports->NumberOfFunctions * sizeof(DWORD);

	if (nFuncAddrsSize == 0)
		return TRUE;

	// read function RVAs
	pnFunctionAddrs = CbHeapAllocate(nFuncAddrsSize, FALSE);
	if (pnFunctionAddrs == NULL) 
		return FALSE;

	if (!pfuncs->procReadMemory(xpFunctionAddrs, nFuncAddrsSize, pnFunctionAddrs, pfuncs->pUserData)) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X reading function addresses (%u bytes at 0x%08X)\r\n",
			GetLastError(), nFuncAddrsSize, xpFunctionAddrs);
		goto L_exit;
	}

	// process functions
	for (nFunction = 0; nFunction < pdirExports->NumberOfFunctions; nFunction++) {
		// the function is forwarded if the RVA is inside the export directory
		bIsForward = (pnFunctionAddrs[nFunction] >= nDirStartRVA) && (pnFunctionAddrs[nFunction] < (nDirStartRVA + nDirSize));

		pfuncs->procDisplayInfo(pfuncs->pUserData, "Export %u: %s at RVA 0x%08X%s", nFunction, bIsForward ? "forward" : "code",
			pnFunctionAddrs[nFunction], bIsForward ?  " -> " : "\r\n");

		if (!bIsForward)
			continue;

		// get the forwarded name
		pszForwardTarget = (LPSTR)((BYTE*)pdirExports + (pnFunctionAddrs[nFunction] - nDirStartRVA));
		pfuncs->procDisplayInfo(pfuncs->pUserData, "%s\r\n", pszForwardTarget);

		pszForwardFuncName = strchr(pszForwardTarget, '.');
		if (pszForwardFuncName == NULL) {
			pfuncs->procDisplayError(pfuncs->pUserData, "\tFormat is unrecoverable (no dot anywhere)\r\n");
			goto L_exit;
		}

		// check for the .dll extension
		if (!CbStringStartsWithIA(pszForwardFuncName, s_cszBadForwardPrefix))
			continue; // no prefix, OK

		// remove the .dll extension
		memmove(pszForwardFuncName, pszForwardFuncName + sizeof(s_cszBadForwardPrefix) - 1, strlen(pszForwardFuncName) + 2
			- sizeof(s_cszBadForwardPrefix));

		pfuncs->procDisplayInfo(pfuncs->pUserData, "\tReplaced with %s\r\n", pszForwardFuncName);
	}

	// write updated export directory
	if (!pfuncs->procWriteMemory(pdirExports, (BYTE*)xpImageBase + nDirStartRVA, nDirSize, pfuncs->pUserData)) {
		pfuncs->procDisplayError(pfuncs->pUserData, "Error 0x%08X writing updated export directory\r\n", GetLastError());
		goto L_exit;
	}

	bSucceeded = TRUE;

L_exit:
	CbHeapFree(pnFunctionAddrs);
	return bSucceeded;
}
