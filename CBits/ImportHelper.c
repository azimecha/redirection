#include "ImportHelper.h"
#include "NTDLL.h"
#include "PartialStdio.h"
#include "FilePaths.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h>

#ifndef STATUS_INVALID_IMAGE_FORMAT
#define STATUS_INVALID_IMAGE_FORMAT 0xC000007B
#endif

#ifndef STATUS_INVALID_PARAMETER_2
#define STATUS_INVALID_PARAMETER_2 0xC00000F0
#endif

PLDR_DATA_TABLE_ENTRY_FULL CbGetLoadedImageByIndex(unsigned nIndex) {
	PPEB_LDR_DATA_FULL pdataLoader;
	PLDR_DATA_TABLE_ENTRY_FULL pentCur;

	pdataLoader = (PPEB_LDR_DATA_FULL)(CbGetPEB()->Ldr);
	pentCur = CONTAINING_RECORD(pdataLoader->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

	while ((nIndex > 0) && (pentCur != NULL)) {
		pentCur = CONTAINING_RECORD(pentCur->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
		nIndex--;
	}

	if (pentCur == NULL)
		CbGetTEB()->LastErrorValue = ERROR_NOT_FOUND;

	return pentCur;
}

PLDR_DATA_TABLE_ENTRY_FULL CbGetLoadedImageByName(LPCSTR pcszModuleName) {
	char szDesiredModuleName[MAX_PATH + 1];
	LPSTR pszDesiredModuleName, pszCurModuleName;
	PPEB_LDR_DATA_FULL pdataLoader;
	PLDR_DATA_TABLE_ENTRY_FULL pentCur, pentFirst;
	ANSI_STRING asCurModuleFullName;
	char szCurModuleFullName[MAX_PATH + 1];
	NTSTATUS status;

	if (strlen(pcszModuleName) >= sizeof(szDesiredModuleName)) {
		CbGetTEB()->LastErrorValue = ERROR_DS_NAME_TOO_LONG;
		return NULL;
	}

	strcpy(szDesiredModuleName, pcszModuleName);
	pszDesiredModuleName = CbNormalizeModuleName(szDesiredModuleName);

	pdataLoader = (PPEB_LDR_DATA_FULL)(CbGetPEB()->Ldr);
	pentFirst = CONTAINING_RECORD(&pdataLoader->InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
	pentCur = CONTAINING_RECORD(pdataLoader->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

	asCurModuleFullName.Buffer = szCurModuleFullName;
	asCurModuleFullName.Length = 0;
	asCurModuleFullName.MaximumLength = sizeof(szCurModuleFullName) - 1;

	while ((pentCur != NULL) && (pentCur != pentFirst)) {
		if (pentCur->FullDllName.Buffer != NULL) {
			status = RtlUnicodeStringToAnsiString(&asCurModuleFullName, &pentCur->FullDllName, FALSE);
			if (status == 0) {
				szCurModuleFullName[asCurModuleFullName.Length] = 0;
				pszCurModuleName = CbNormalizeModuleName(szCurModuleFullName);
				if (!stricmp(pszCurModuleName, pszDesiredModuleName))
					return pentCur;
			}
		}

		pentCur = CONTAINING_RECORD(pentCur->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
	}

	CbGetTEB()->LastErrorValue = ERROR_NOT_FOUND;
	return NULL;
}

LPVOID CbGetSymbolAddress(LPVOID pImageBase, LPCSTR pcszSymbolName) {
	LPVOID pSymbol;
	NTSTATUS status;

	status = (NTSTATUS)CbGetSymbolAddressEx(pImageBase, pcszSymbolName, 0, &pSymbol);
	if (status != 0) {
		CbGetTEB()->LastErrorValue = RtlNtStatusToDosError(status);
		return NULL;
	}

	return pSymbol;
}

NTSTATUS CbGetSymbolAddressEx(LPVOID pImageBase, LPCSTR pcszSymbolName, WORD nOrdinal, OUT LPVOID* ppSymbol) {
	PIMAGE_DOS_HEADER phdrDOS;
	PIMAGE_NT_HEADERS phdrNT;
	PIMAGE_EXPORT_DIRECTORY pdirExports;
	LPWORD pnOrdinals;
	LPDWORD pnNameRVAs;
	LPDWORD pnFunctionRVAs;
	DWORD nName;
	LPCSTR pcszCurName;

	// find the library's NT headers
	phdrDOS = (PIMAGE_DOS_HEADER)pImageBase;
	if (phdrDOS->e_magic != MAKEWORD('M', 'Z'))
		return STATUS_INVALID_IMAGE_FORMAT;

	phdrNT = (PIMAGE_NT_HEADERS)((BYTE*)phdrDOS + phdrDOS->e_lfanew);
	if (phdrNT->Signature != mmioFOURCC('P', 'E', 0, 0))
		return STATUS_INVALID_IMAGE_FORMAT;

	// find the export directory
	if (phdrNT->OptionalHeader.DataDirectory[0].Size == 0) goto L_notfound;
	pdirExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)phdrDOS + phdrNT->OptionalHeader.DataDirectory[0].VirtualAddress);
	if (pdirExports == NULL) goto L_notfound;

	pnOrdinals = (LPWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNameOrdinals);
	if (pnOrdinals == NULL) goto L_notfound;

	pnNameRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNames);
	if (pnNameRVAs == NULL) goto L_notfound;

	pnFunctionRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfFunctions);
	if (pnNameRVAs == NULL) goto L_notfound;

	// safer to prioritize name over ordinal if name was specified
	if (pcszSymbolName) {
		// find by name
		for (nName = 0; nName < pdirExports->NumberOfNames; nName++) {
			pcszCurName = (LPCSTR)((BYTE*)phdrDOS + pnNameRVAs[nName]);
			if (stricmp(pcszCurName, pcszSymbolName) == 0) {
				*ppSymbol = (BYTE*)phdrDOS + pnFunctionRVAs[pnOrdinals[nName]];
				return 0;
			}
		}

		// if the name wasn't found, don't blindly use the ordinal
		goto L_notfound;
	}

	// find by ordinal (no name was given)
	if (nOrdinal) {
		if (nOrdinal > pdirExports->NumberOfFunctions)
			goto L_notfound;

		*ppSymbol = (BYTE*)phdrDOS + pnFunctionRVAs[nOrdinal];
		return 0;
	}

	// neither name nor ordinal was given, return the most infuriating error code
	return STATUS_INVALID_PARAMETER_2;

L_notfound: // we get here if something went wrong
	return STATUS_ENTRYPOINT_NOT_FOUND;
}

LPSTR CbNormalizeModuleName(LPSTR pszName) {
	pszName = (LPSTR)CbPathGetFilenameA(pszName);
	CbPathRemoveExtensionA(pszName);
	CbStringToLowerA(pszName);
	return pszName;
}
