#include "ImportHelper.h"
#include "NTDLL.h"
#include "PartialStdio.h"
#include "FilePaths.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h>

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
	LPSTR pszDesiredModuleName;
	PPEB_LDR_DATA_FULL pdataLoader;
	PLDR_DATA_TABLE_ENTRY_FULL pentCur;
	ANSI_STRING asCurModuleName;
	char szCurModuleName[MAX_PATH + 1];
	NTSTATUS status;

	if (strlen(pcszModuleName) >= sizeof(szDesiredModuleName)) {
		CbGetTEB()->LastErrorValue = ERROR_DS_NAME_TOO_LONG;
		return NULL;
	}

	strcpy(szDesiredModuleName, pcszModuleName);
	pszDesiredModuleName = CbNormalizeModuleName(szDesiredModuleName);

	pdataLoader = (PPEB_LDR_DATA_FULL)(CbGetPEB()->Ldr);
	pentCur = CONTAINING_RECORD(pdataLoader->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

	asCurModuleName.Buffer = szCurModuleName;
	asCurModuleName.Length = 0;
	asCurModuleName.MaximumLength = sizeof(szCurModuleName) - 1;

	while (pentCur != NULL) {
		status = RtlUnicodeStringToAnsiString(&asCurModuleName, &pentCur->FullDllName, FALSE);
		if (status == 0) {
			szCurModuleName[asCurModuleName.Length] = 0;
			if (!stricmp(szCurModuleName, pcszModuleName))
				return pentCur;
		}

		pentCur = CONTAINING_RECORD(pentCur->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
	}

	CbGetTEB()->LastErrorValue = ERROR_NOT_FOUND;
	return NULL;
}

LPVOID CbGetSymbolAddress(LPVOID pImageBase, LPCSTR pcszSymbolName) {
	PIMAGE_DOS_HEADER phdrDOS;
	PIMAGE_NT_HEADERS phdrNT;
	PIMAGE_EXPORT_DIRECTORY pdirExports;
	LPWORD pnOrdinals;
	LPDWORD pnNameRVAs;
	LPDWORD pnFunctionRVAs;
	DWORD nName;
	LPCSTR pcszCurName;

	phdrDOS = (PIMAGE_DOS_HEADER)pImageBase;
	if (phdrDOS->e_magic != MAKEWORD('M', 'Z')) {
		CbGetTEB()->LastErrorValue = ERROR_INVALID_EXE_SIGNATURE;
		return NULL;
	}

	phdrNT = (PIMAGE_NT_HEADERS)((BYTE*)phdrDOS + phdrDOS->e_lfanew);
	if (phdrNT->Signature != mmioFOURCC('P', 'E', 0, 0)) {
		CbGetTEB()->LastErrorValue = ERROR_INVALID_EXE_SIGNATURE;
		return NULL;
	}

	if (phdrNT->OptionalHeader.DataDirectory[0].Size == 0) goto L_notfound;
	pdirExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)phdrDOS + phdrNT->OptionalHeader.DataDirectory[0].VirtualAddress);
	if (pdirExports == NULL) goto L_notfound;

	pnOrdinals = (LPWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNameOrdinals);
	if (pnOrdinals == NULL) goto L_notfound;

	pnNameRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNames);
	if (pnNameRVAs == NULL) goto L_notfound;

	pnFunctionRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfFunctions);
	if (pnNameRVAs == NULL) goto L_notfound;

	for (nName = 0; nName < pdirExports->NumberOfNames; nName++) {
		pcszCurName = (LPCSTR)((BYTE*)phdrDOS + pnNameRVAs[nName]);
		if (stricmp(pcszCurName, pcszSymbolName) == 0)
			return (BYTE*)phdrDOS + pnFunctionRVAs[pnOrdinals[nName]];
	}

L_notfound:
	CbGetTEB()->LastErrorValue = ERROR_NOT_FOUND;
	return NULL;
}

LPSTR CbNormalizeModuleName(LPSTR pszName) {
	pszName = (LPSTR)CbPathGetFilenameA(pszName);
	CbPathRemoveExtensionA(pszName);
	CbStringToLowerA(pszName);
	return pszName;
}
