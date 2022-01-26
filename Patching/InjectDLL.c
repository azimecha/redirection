#include "InjectDLL.h"
#include "ConfigReading.h"
#include <NTDLL.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef struct _struct_PaModule {
	HMODULE m_hModule;
	HANDLE m_hDLLFile;
	HANDLE m_hLocalMapping;
	LPVOID m_pMappedBase;
	LPVOID m_pLocalBase;
	PaDisplayMessageProc m_procDisplayInfo;
	PaDisplayMessageProc m_procDisplayError;
	LPVOID m_pUserData;
	char m_szPath[MAX_PATH];
} PaModule;

PaModuleHandle PaModuleOpen(LPCSTR pcszDLLName, PaDisplayMessageProc procDisplayInfo, PaDisplayMessageProc procDisplayError, LPVOID pUserData) {
	DWORD nError = 0;
	PaModuleHandle hModule = NULL;

	// first create the PaModule struct, initializing everything to null
	hModule = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PaModule));
	if (hModule == NULL) {
		nError = GetLastError();
		procDisplayError(pUserData, "Error 0x%08X allocating %u bytes for module structure\r\n", GetLastError(), sizeof(PaModule));
		goto L_errorexit;
	}

	// check if we've already loaded the module
	hModule->m_hModule = GetModuleHandleA(pcszDLLName);
	if (hModule->m_hModule != NULL) {
		procDisplayInfo(pUserData, "Found %s already loaded at 0x%08X\r\n", pcszDLLName, (UINT_PTR)hModule->m_hModule);
		hModule->m_pLocalBase = (LPVOID)hModule->m_hModule;

		// fill path from existing
		if (GetModuleFileNameA(hModule->m_hModule, hModule->m_szPath, sizeof(hModule->m_szPath)) == 0) {
			nError = GetLastError();
			procDisplayError(pUserData, "Error 0x%08X reading module filename\r\n", GetLastError());
			goto L_errorexit;
		}

		return hModule;
	}

	// nope? don't load it as a library, but map it in so we can look at it

	// find it
	if (!PaFindModulePath(pcszDLLName, hModule->m_szPath, sizeof(hModule->m_szPath))) {
		nError = GetLastError();
		procDisplayError(pUserData, "Error 0x%08X locating %s\r\n", nError, pcszDLLName);
		goto L_errorexit;
	}

	procDisplayInfo(pUserData, "Located %s at path %s\r\n", pcszDLLName, hModule->m_szPath);

	// open it
	hModule->m_hDLLFile = CreateFileA(hModule->m_szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hModule->m_hDLLFile == INVALID_HANDLE_VALUE) {
		nError = GetLastError();
		hModule->m_hDLLFile = NULL;
		procDisplayError(pUserData, "Error 0x%08X opening %s\r\n", nError, hModule->m_szPath);
		goto L_errorexit;
	}

	// create the mapping object
	hModule->m_hLocalMapping = CreateFileMappingA(hModule->m_hDLLFile, NULL, PAGE_WRITECOPY | SEC_IMAGE, 0, 0, NULL);
	if (hModule->m_hLocalMapping == NULL) {
		nError = GetLastError();
		procDisplayError(pUserData, "Error 0x%08X creating file mapping for %s\r\n", nError, pcszDLLName);
		goto L_errorexit;
	}

	// map it
	hModule->m_pMappedBase = MapViewOfFile(hModule->m_hLocalMapping, FILE_MAP_READ, 0, 0, 0);
	if (hModule->m_pMappedBase == NULL) {
		nError = GetLastError();
		procDisplayError(pUserData, "Error 0x%08X mapping %s into memory\r\n", nError, pcszDLLName);
		goto L_errorexit;
	}

	// done
	hModule->m_pLocalBase = hModule->m_pMappedBase;
	procDisplayInfo(pUserData, "Mapped %s at 0x%08X\r\n", pcszDLLName, hModule->m_pMappedBase);
	return hModule;

L_errorexit:
	PaModuleClose(hModule);
	SetLastError(nError);
	return NULL;
}

LPVOID PaModuleGetBaseAddress(PaModuleHandle hModule) {
	return hModule->m_pLocalBase;
}

LPCSTR PaModuleGetFilePath(PaModuleHandle hModule) {
	return hModule->m_szPath;
}

void PaModuleClose(PaModuleHandle hModule) {
	if (hModule != NULL) {
		if (hModule->m_pMappedBase != NULL) UnmapViewOfFile(hModule->m_pMappedBase);
		if (hModule->m_hLocalMapping != NULL) CloseHandle(hModule->m_hLocalMapping);
		if (hModule->m_hModule != NULL) FreeLibrary(hModule->m_hModule);
		if (hModule->m_hDLLFile != NULL) CloseHandle(hModule->m_hDLLFile);

		HeapFree(GetProcessHeap(), 0, hModule);
	}
}

EXTERNAL_PTR PaInjectWithoutLoad(PaModuleHandle hModule, HANDLE hTargetProcess) {
	DWORD nError = 0;
	NTSTATUS status = 0;
	EXTERNAL_PTR pForeignAddress = NULL;
	SIZE_T nSize = 0;

	// ensure mapping object created
	if (hModule->m_hLocalMapping == NULL) {
		// ensure file open 
		if (hModule->m_hDLLFile == NULL) {
			// open file
			hModule->m_hDLLFile = CreateFileA(hModule->m_szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hModule->m_hDLLFile == INVALID_HANDLE_VALUE) {
				nError = GetLastError();
				hModule->m_hDLLFile = NULL;
				hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X opening %s\r\n", nError, hModule->m_szPath);
				SetLastError(nError);
				return NULL;
			}
		}

		// create mapping object
		hModule->m_hLocalMapping = CreateFileMappingA(hModule->m_hDLLFile, NULL, PAGE_READONLY | SEC_IMAGE | SEC_COMMIT, 0, 0, NULL);
		if (hModule->m_hLocalMapping == NULL) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X creating file mapping for %s\r\n", nError, hModule->m_szPath);
			SetLastError(nError);
			return NULL;
		}
	}

	// map into the target
	status = NtMapViewOfSection(hModule->m_hLocalMapping, hTargetProcess, &pForeignAddress, 0, 0, NULL, &nSize, ViewUnmap, 0, PAGE_READONLY);
	if (status != 0) {
		nError = RtlNtStatusToDosError(status);
		hModule->m_procDisplayError(hModule->m_pUserData, "NT error 0x%08X (WinAPI error 0x%08X) mapping section into process\r\n",
			status, nError);
		SetLastError(nError);
		return NULL;
	}

	return pForeignAddress;
}

EXTERNAL_PTR PaGetRemoteSymbol(PaModuleHandle hModule, EXTERNAL_PTR pBaseAddress, LPCSTR pcszSymbolName) {
	LPBYTE pLocalFunc;
	DWORD nError;

	pLocalFunc = CbGetSymbolAddress(hModule->m_pLocalBase, pcszSymbolName);
	if (pLocalFunc == NULL) {
		nError = GetLastError();
		hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X retrieving address of %s\r\n", nError, pcszSymbolName);
		SetLastError(nError);
		return NULL;
	}

	return (pLocalFunc - (LPBYTE)hModule->m_pLocalBase) + (LPBYTE)pBaseAddress;
}
