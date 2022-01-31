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

typedef struct _struct_PaLdrDataTableEntryWithStrings {
	LDR_DATA_TABLE_ENTRY_FULL m_entry;
	BYTE m_arrFwdCompat[256]; // zeroed for compatibility if MS increases size of LDR_DATA_TABLE_ENTRY
	WCHAR m_wzFullDLLName[MAX_PATH];
	WCHAR m_wzBaseDLLName[MAX_PATH];
} PaLdrDataTableEntryWithStrings;

static BOOL s_ReadMemoryExternal(EXTERNAL_PTR pSrcBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData);
static DWORD s_InsertListEntry(PaModuleHandle hModule, HANDLE hProcess, PLIST_ENTRY pentThisItemLocal, EXTERNAL_PTR xpPrevListItem, 
	EXTERNAL_PTR xpThisListItem, EXTERNAL_PTR xpNextListItem);

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

	hModule->m_procDisplayInfo = procDisplayInfo;
	hModule->m_procDisplayError = procDisplayError;
	hModule->m_pUserData = pUserData;

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

PIMAGE_NT_HEADERS PaModuleGetNTHeaders(PaModuleHandle hModule) {
	return (PIMAGE_NT_HEADERS)((LPBYTE)hModule->m_pLocalBase + ((PIMAGE_DOS_HEADER)hModule->m_pLocalBase)->e_lfanew);
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

#pragma warning(push)
#pragma warning(disable:4101)

EXTERNAL_PTR PaInjectWithoutLoad(PaModuleHandle hModule, HANDLE hTargetProcess, BOOL bRegisterAsLoaded) {
	DWORD nError = 0;
	NTSTATUS status = 0;
	EXTERNAL_PTR pForeignAddress = NULL, xpLoaderEntry = NULL;
	SIZE_T nSize = 0;
	PaLdrDataTableEntryWithStrings entry;
	PLDR_DATA_TABLE_ENTRY_FULL pentInLoadOrder = NULL, pentInMemoryOrder = NULL, pentInInitOrder = NULL;
	SIZE_T nInLoadOrder = 0, nInMemoryOrder = 0, nInInitOrder = 0, nBytesRead, nEntry;
	PEXTERNAL_PTR pxpInLoadOrder = NULL, pxpInMemoryOrder = NULL, pxpInInitOrder = NULL;
	PIMAGE_NT_HEADERS phdrNT;
	PEB peb;
	PEB_LDR_DATA_FULL dataLoader;
	BOOL bDidRegister = FALSE;

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
				goto L_exit;
			}
		}

		// create mapping object
		hModule->m_hLocalMapping = CreateFileMappingA(hModule->m_hDLLFile, NULL, PAGE_READONLY | SEC_IMAGE | SEC_COMMIT, 0, 0, NULL);
		if (hModule->m_hLocalMapping == NULL) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X creating file mapping for %s\r\n", nError, hModule->m_szPath);
			goto L_exit;
		}
	}

	// map into the target
	status = NtMapViewOfSection(hModule->m_hLocalMapping, hTargetProcess, &pForeignAddress, 0, 0, NULL, &nSize, ViewUnmap, 0, PAGE_READONLY);
	if (status != 0) {
		nError = RtlNtStatusToDosError(status);
		hModule->m_procDisplayError(hModule->m_pUserData, "NT error 0x%08X (WinAPI error 0x%08X) mapping section into process\r\n",
			status, nError);
		goto L_exit;
	}

#if 0 // UNTESTED
	if (bRegisterAsLoaded) {
		// basic loader data table entry setup
		phdrNT = PaModuleGetNTHeaders(hModule);
		RtlSecureZeroMemory(&entry, sizeof(entry));
		entry.m_entry.DllBase = pForeignAddress;
		entry.m_entry.SizeOfImage = phdrNT->OptionalHeader.SizeOfImage;
		entry.m_entry.EntryPoint = (BYTE*)pForeignAddress + phdrNT->OptionalHeader.AddressOfEntryPoint;

		// suspend the process to prevent race conditions wrt. modules list
		status = NtSuspendProcess(hTargetProcess);
		if (status != 0) {
			nError = RtlNtStatusToDosError(status);
			hModule->m_procDisplayError(hModule->m_pUserData, "NT error 0x%08X (WinAPI error 0x%08X) suspending process\r\n",
				status, nError);
			goto L_exit;
		}

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Suspended process\r\n");

		// get PEB
		if (!PaGetProcessEnvBlock(hTargetProcess, &peb)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading process environment block\r\n", nError);
			goto L_exit;
		}

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Loader data at 0x%08X\r\n", peb.Ldr);

		// read loader data
		if (!ReadProcessMemory(hTargetProcess, peb.Ldr, &dataLoader, sizeof(dataLoader), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading process loader data\r\n", nError);
			goto L_exit;
		}

		// read module lists
		if (dataLoader.InLoadOrderModuleList.Flink != NULL) {
			pentInLoadOrder = PaReadListItems(sizeof(*pentInLoadOrder), FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks),
				dataLoader.InLoadOrderModuleList.Flink, s_ReadMemoryExternal, (LPVOID)hTargetProcess, &nInLoadOrder, &pxpInLoadOrder);
			if (pentInLoadOrder == NULL) {
				nError = GetLastError();
				hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading module list in load order\r\n", nError);
				goto L_exit;
			}
		}

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Load order list: %u modules, array at 0x%08X local, xptrs at 0x%08X local\r\n",
			nInInitOrder, pentInLoadOrder, pxpInLoadOrder);

		if (dataLoader.InMemoryOrderModuleList.Flink != NULL) {
			pentInMemoryOrder = PaReadListItems(sizeof(*pentInMemoryOrder), FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks),
				dataLoader.InMemoryOrderModuleList.Flink, s_ReadMemoryExternal, (LPVOID)hTargetProcess, &nInMemoryOrder, &pxpInMemoryOrder);
			if (pentInMemoryOrder == NULL) {
				nError = GetLastError();
				hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading module list in memory order\r\n", nError);
				goto L_exit;
			}
		}

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Memory order list: %u modules, array at 0x%08X local, xptrs at 0x%08X local\r\n",
			nInMemoryOrder, pentInMemoryOrder, pxpInMemoryOrder);

		if (dataLoader.InInitializationOrderModuleList.Flink != NULL) {
			pentInInitOrder = PaReadListItems(sizeof(*pentInInitOrder), FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InInitializationOrderLinks),
				dataLoader.InInitializationOrderModuleList.Flink, s_ReadMemoryExternal, (LPVOID)hTargetProcess, &nInInitOrder, &pxpInInitOrder);
			if (pentInInitOrder == NULL) {
				nError = GetLastError();
				hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading module list in init order\r\n", nError);
				goto L_exit;
			}
		}

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Initialization order list: %u modules, array at 0x%08X local, xptrs at 0x%08X local\r\n",
			nInInitOrder, pentInInitOrder, pxpInInitOrder);

		// allocate space for new entry
		xpLoaderEntry = VirtualAllocEx(hTargetProcess, NULL, sizeof(entry), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (xpLoaderEntry == NULL) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X allocating %u bytes in target process for loader entry\r\n",
				nError, sizeof(entry));
			goto L_exit;
		}

		// set list pointers for load-order list
		nError = s_InsertListEntry(hModule, hTargetProcess, &entry.m_entry.InLoadOrderLinks,
			pxpInLoadOrder ? (BYTE*)pxpInLoadOrder[nInLoadOrder - 1] + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks) : NULL,
			(BYTE*)xpLoaderEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks), NULL);
		if (nError != 0) goto L_exit;

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Previous module in load order at 0x%08X\r\n", entry.m_entry.InLoadOrderLinks.Blink);

		// set list pointers for init-order list
		nError = s_InsertListEntry(hModule, hTargetProcess, &entry.m_entry.InInitializationOrderLinks,
			pxpInInitOrder ? (BYTE*)pxpInInitOrder[nInInitOrder - 1] + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InInitializationOrderLinks) : NULL,
			(BYTE*)xpLoaderEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InInitializationOrderLinks), NULL);
		if (nError != 0) goto L_exit;

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Previous module in init order at 0x%08X\r\n", entry.m_entry.InInitializationOrderLinks.Blink);

		// set list pointers for memory-order-list
		// nEntry will be the _next_ item after this one
		for (nEntry = 0; nEntry < nInMemoryOrder; nEntry++) {
			if (pentInMemoryOrder[nEntry].DllBase > entry.m_entry.DllBase)
				break;
		}

		nError = s_InsertListEntry(hModule, hTargetProcess, &entry.m_entry.InMemoryOrderLinks, 
			pxpInMemoryOrder ? pxpInMemoryOrder[nEntry] : NULL, 
			(BYTE*)xpLoaderEntry + FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks),
			(nEntry < (nInMemoryOrder - 1)) ? pxpInMemoryOrder[nEntry] : NULL);
		if (nError != 0) goto L_exit;

		hModule->m_procDisplayInfo(hModule->m_pUserData, "Previous module in memory order at 0x%08X\r\n", entry.m_entry.InInitializationOrderLinks.Blink);
		hModule->m_procDisplayInfo(hModule->m_pUserData, "Next module in memory order at 0x%08X\r\n", entry.m_entry.InInitializationOrderLinks.Flink);

		// copy entry into process memory
		if (!WriteProcessMemory(hTargetProcess, xpLoaderEntry, &entry, sizeof(entry), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X copying list entry into process\r\n", nError);
			goto L_exit;
		}

		//L_resume: // resume the process
		status = NtResumeProcess(hTargetProcess);
		if (status != 0) {
			nError = RtlNtStatusToDosError(status);
			hModule->m_procDisplayError(hModule->m_pUserData, "NT error 0x%08X (WinAPI error 0x%08X) resuming process\r\n",
				status, nError);
			goto L_exit;
		}
	}
#endif

L_exit:
	if (pentInLoadOrder != NULL) PaFreeListItems(pentInLoadOrder);
	if (pentInMemoryOrder != NULL) PaFreeListItems(pentInMemoryOrder);
	if (pentInInitOrder != NULL) PaFreeListItems(pentInInitOrder);
	if (pxpInLoadOrder != NULL) PaFreeListItems(pxpInLoadOrder);
	if (pxpInMemoryOrder != NULL) PaFreeListItems(pxpInMemoryOrder);
	if (pxpInInitOrder != NULL) PaFreeListItems(pxpInInitOrder);
	SetLastError(nError);
	return (!bRegisterAsLoaded || bDidRegister) ? pForeignAddress : NULL;
}

#pragma warning(pop)

static DWORD s_InsertListEntry(PaModuleHandle hModule, HANDLE hProcess, PLIST_ENTRY pentThisItemLocal, EXTERNAL_PTR xpPrevListItem,
	EXTERNAL_PTR xpThisListItem, EXTERNAL_PTR xpNextListItem)
{
	LIST_ENTRY entryPrev, entryNext;
	SIZE_T nBytesRead;
	DWORD nError;

	if (xpPrevListItem != NULL) {
		if (!ReadProcessMemory(hProcess, xpPrevListItem, &entryPrev, sizeof(LIST_ENTRY), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading previous list entry\r\n", nError);
			return nError;
		}
	}

	if (xpNextListItem != NULL) {
		if (!ReadProcessMemory(hProcess, xpNextListItem, &entryNext, sizeof(LIST_ENTRY), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X reading next list entry\r\n", nError);
			return nError;
		}
	}

	if ((xpPrevListItem == NULL) && (xpNextListItem == NULL)) {
		// only item in list
		pentThisItemLocal->Blink = NULL;
		pentThisItemLocal->Flink = NULL;
	} else if (xpPrevListItem == NULL) {
		// first item in list
		pentThisItemLocal->Blink = NULL;
		pentThisItemLocal->Flink = xpNextListItem;
		entryNext.Blink = xpThisListItem;
	} else if (xpNextListItem == NULL) {
		// last item in list
		pentThisItemLocal->Blink = xpPrevListItem;
		pentThisItemLocal->Flink = NULL;
		entryPrev.Flink = xpThisListItem;
	} else {
		// not first or last
		pentThisItemLocal->Blink = xpPrevListItem;
		pentThisItemLocal->Flink = xpNextListItem;
		entryPrev.Flink = xpThisListItem;
		entryNext.Blink = xpThisListItem;
	}

	if (xpPrevListItem != NULL) {
		if (!WriteProcessMemory(hProcess, xpPrevListItem, &entryPrev, sizeof(LIST_ENTRY), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X writing previous list entry\r\n", nError);
			return nError;
		}
	}

	if (xpNextListItem != NULL) {
		if (!WriteProcessMemory(hProcess, xpNextListItem, &entryNext, sizeof(LIST_ENTRY), &nBytesRead)) {
			nError = GetLastError();
			hModule->m_procDisplayError(hModule->m_pUserData, "Error 0x%08X writing next list entry\r\n", nError);
			return nError;
		}
	}

	return 0;
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

BOOL PaGetProcessEnvBlock(HANDLE hTargetProcess, PPEB ppeb) {
	PROCESS_BASIC_INFORMATION infProcess;
	NTSTATUS status;
	ULONG nSize;
	SIZE_T nBytesRead;

	if (ppeb == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	status = NtQueryInformationProcess(hTargetProcess, ProcessBasicInformation, &infProcess, sizeof(infProcess), &nSize);
	if (status != 0) {
		SetLastError(RtlNtStatusToDosError(status));
		return FALSE;
	}

	if (infProcess.PebBaseAddress == NULL) {
		SetLastError(ERROR_NOT_FOUND);
		return FALSE;
	}

	if (!ReadProcessMemory(hTargetProcess, infProcess.PebBaseAddress, ppeb, sizeof(PEB), &nBytesRead))
		return FALSE;

	return TRUE;
}

LPVOID PaReadListItems(SIZE_T nItemSize, SIZE_T nListEntryOffset, EXTERNAL_PTR xpAnyItem, PaReadMemoryProc procReadMemory, LPVOID pUserData,
	PSIZE_T pnItemCount, OPTIONAL EXTERNAL_PTR** ppxpItemAddresses)
{
	HANDLE hHeap;
	LPBYTE pItems = NULL, pCurItem = NULL, pItemsNew = NULL;
	PLIST_ENTRY pentCur = NULL;
	EXTERNAL_PTR xpCurItem = NULL, xpPriorItem = NULL;
	EXTERNAL_PTR* pxpItemAddressesNew;
	DWORD nError;

	*pnItemCount = 0;
	hHeap = GetProcessHeap();

	// allocate initial item & address buffers
	pItems = HeapAlloc(hHeap, 0, nItemSize);
	if (pItems == NULL) return NULL;
	pCurItem = pItems;
	pentCur = (PLIST_ENTRY)(pItems + nListEntryOffset);

	if (ppxpItemAddresses) {
		*ppxpItemAddresses = HeapAlloc(hHeap, 0, sizeof(EXTERNAL_PTR));
		if (*ppxpItemAddresses == NULL)
			goto L_errorexit;
	}

	// seek to first item
	xpCurItem = xpAnyItem;
	while (xpCurItem != NULL) {
		// read item
		if (!procReadMemory(xpCurItem, nItemSize, pCurItem, pUserData))
			goto L_errorexit;

		// go to next
		xpPriorItem = xpCurItem;
		xpCurItem = (EXTERNAL_PTR)((LPBYTE)pentCur->Blink - nListEntryOffset);
	}
	xpCurItem = xpPriorItem;

	// read all items
	while (xpCurItem != NULL) {
		// read item
		pCurItem = pItems + (*pnItemCount * nItemSize);
		pentCur = (PLIST_ENTRY)(pCurItem + nListEntryOffset);
		if (!procReadMemory(xpCurItem, nItemSize, pCurItem, pUserData))
			goto L_errorexit;
		if (ppxpItemAddresses)
			(*ppxpItemAddresses)[*pnItemCount] = xpCurItem;

		// expand items buffer
		pItemsNew = HeapReAlloc(hHeap, 0, pItems, (*pnItemCount + 2) * nItemSize);
		if (pItemsNew == NULL)
			goto L_errorexit;
		pItems = pItemsNew;

		// expand addresses buffer
		if (ppxpItemAddresses) {
			pxpItemAddressesNew = HeapReAlloc(hHeap, 0, pItems, (*pnItemCount + 2) * sizeof(EXTERNAL_PTR));
			if (pxpItemAddressesNew == NULL)
				goto L_errorexit;
			*ppxpItemAddresses = pxpItemAddressesNew;
		}

		// go to next
		(*pnItemCount)++;
		xpCurItem = (EXTERNAL_PTR)((LPBYTE)pentCur->Flink - nListEntryOffset);
	}
	
	// success
	return pItems;

L_errorexit:
	nError = GetLastError();
	if (pItems != NULL)
		HeapFree(hHeap, 0, pItems);
	if ((ppxpItemAddresses != NULL) && (*ppxpItemAddresses != NULL)) {
		HeapFree(hHeap, 0, *ppxpItemAddresses);
		*ppxpItemAddresses = NULL;
	}
	SetLastError(nError);
	return NULL;
}

void PaFreeListItems(LPVOID pListItems) {
	HeapFree(GetProcessHeap(), 0, pListItems);
}

static BOOL s_ReadMemoryExternal(EXTERNAL_PTR pSrcBase, SIZE_T nSize, LPVOID pDestBuffer, LPVOID pUserData) {
	SIZE_T nBytesRead;
	return ReadProcessMemory((HANDLE)pUserData, pSrcBase, pDestBuffer, nSize, &nBytesRead);
}
