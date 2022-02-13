#include "ThreadLocal.h"
#include "avl.h"
#include <NTDLL.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef struct _MW_TLS_ENTRY {
	DWORD nDataSize;
	MwTLSDtorProc_t procDtor;
	char szName[32];
	BYTE arrData[];
} MW_TLS_ENTRY, *PMW_TLS_ENTRY;

static avl_tree_t* s_GetLocalTree(void);
static PMW_TLS_ENTRY s_FindEntry(LPCGUID pcidObject);
static PMW_TLS_ENTRY s_CreateEntry(LPCGUID pidObject, DWORD nSize, OPTIONAL MwTLSCtorProc_t procCtor, OPTIONAL MwTLSDtorProc_t procDtor, 
	OPTIONAL LPCSTR pcszName);
static BOOL s_InsertEntry(LPCGUID pcidObject, PMW_TLS_ENTRY pEntry);
static void s_RemoveEntry(LPCGUID pcidObject);
static int s_CompareKeys(LPCGUID pcidA, LPCGUID pcidB);
static void s_DestructNode(LPGUID pidObject, PMW_TLS_ENTRY pEntry);
static void s_DestructEntryImpl(PMW_TLS_ENTRY pEntry);

static DWORD s_nIndex = -1;

PVOID MAGICWAYS_EXPORTED MwGetTLS(LPCGUID pcidObject, DWORD nSize, OPTIONAL MwTLSCtorProc_t procCtor, OPTIONAL MwTLSDtorProc_t procDtor,
	OPTIONAL LPCSTR pcszName)
{
	PMW_TLS_ENTRY pEntry = NULL;
	
	pEntry = s_FindEntry(pcidObject);
	if (pEntry != NULL)
		return pEntry->arrData;

	pEntry = s_CreateEntry(pcidObject, nSize, procCtor, procDtor, pcszName);
	return pEntry->arrData;
}

PVOID MAGICWAYS_EXPORTED MwTryGetTLS(LPCGUID pcidObject) {
	PMW_TLS_ENTRY pEntry = NULL;

	pEntry = s_FindEntry(pcidObject);
	if (pEntry == NULL) 
		CbLastWinAPIError = ERROR_NOT_FOUND;

	return pEntry ? pEntry->arrData : NULL;
}

void MAGICWAYS_EXPORTED MwDiscardTLS(LPCGUID pcidObject) {
	s_RemoveEntry(pcidObject);
}

BOOL MAGICWAYS_EXPORTED MwNullTLSCtor(PVOID pData) {
	return TRUE;
}

void MAGICWAYS_EXPORTED MwNullTLSDtor(PVOID pData) { }

BOOL TLSInitProcess(void) {
	s_nIndex = TlsAlloc();
	if (s_nIndex == (DWORD)-1)
		return FALSE;
}

BOOL TLSInitThread(void) {
	avl_tree_t* pTree = NULL;

	pTree = CbHeapAllocate(sizeof(avl_tree_t), 1);
	if (pTree == NULL)
		return FALSE;

	avl_initialize(pTree, s_CompareKeys, CbHeapFree);
	TlsSetValue(s_nIndex, pTree);
	return TRUE;
}

BOOL TLSUninitThread(void) {
	avl_tree_t* pTree = NULL;

	pTree = s_GetLocalTree();
	if (pTree != NULL)
		avl_destroy(pTree, s_DestructNode);

	return TRUE;
}

BOOL TLSUninitProcess(void) {
	TlsFree(s_nIndex);
	s_nIndex = (DWORD)-1;
	return TRUE;
}

static avl_tree_t* s_GetLocalTree(void) {
	avl_tree_t* pTree;

	pTree = TlsGetValue(s_nIndex);
	if (pTree == NULL) {
		TLSInitThread();
		pTree = TlsGetValue(s_nIndex);
	}

	return pTree;
}

static PMW_TLS_ENTRY s_FindEntry(LPCGUID pidObject) {
	avl_tree_t* pTree;

	pTree = s_GetLocalTree();
	if (pTree == NULL)
		return FALSE;

	return (PMW_TLS_ENTRY)avl_search(pTree, pidObject);
}

static PMW_TLS_ENTRY s_CreateEntry(LPCGUID pcidObject, DWORD nSize, OPTIONAL MwTLSCtorProc_t procCtor, OPTIONAL MwTLSDtorProc_t procDtor, OPTIONAL LPCSTR pcszName) {
	PMW_TLS_ENTRY pEntry = NULL;
	BOOL bSuccess = FALSE;
	BOOL bConstructed = FALSE;

	pEntry = CbHeapAllocate(sizeof(MW_TLS_ENTRY) + nSize, FALSE);
	if (pEntry == NULL)
		goto L_exit;

	pEntry->nDataSize = nSize;
	pEntry->procDtor = procDtor;
	strncpy(pEntry->szName, pcszName, sizeof(pEntry->szName) - 1);

	if (procCtor) {
		__try {
			bConstructed = procCtor(pEntry->arrData);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[ThreadLocal:s_CreateEntry] SEH exception 0x%08X in ctor!\r\n", GetExceptionCode());
		}

		if (!bConstructed) goto L_exit;
	}

	if (!s_InsertEntry(pcidObject, pEntry))
		goto L_exit;

	bSuccess = TRUE;

L_exit:
	if (!bSuccess && pEntry) {
		if (bConstructed)
			s_DestructEntryImpl(pEntry);
		else
			CbHeapFree(pEntry);
		pEntry = NULL;
	}
	return pEntry;
}

static BOOL s_InsertEntry(LPCGUID pcidObject, PMW_TLS_ENTRY pEntry) {
	avl_tree_t* pTree;
	LPGUID pidCopy = NULL;

	pTree = s_GetLocalTree();
	if (pTree == NULL)
		return FALSE;

	pidCopy = CbHeapAllocate(sizeof(GUID), 0);
	if (pidCopy == NULL)
		return FALSE;
	memcpy(pidCopy, pcidObject, sizeof(GUID));

	avl_insert(pTree, pidCopy, pEntry);
	return avl_search(pTree, pidCopy) != NULL;
}

static void s_RemoveEntry(LPCGUID pcidObject) {
	avl_tree_t* pTree;
	PMW_TLS_ENTRY pEntry;

	pTree = s_GetLocalTree();
	if (pTree == NULL)
		return;

	pEntry = avl_remove(pTree, pcidObject);
	if (pEntry)
		s_DestructEntryImpl(pEntry);
}

static int s_CompareKeys(LPCGUID pidA, LPCGUID pidB) {
	return memcmp(pidA, pidB, sizeof(GUID));
}

static void s_DestructNode(LPGUID pidObject, PMW_TLS_ENTRY pEntry) {
	s_DestructEntryImpl(pEntry);
	CbHeapFree(pidObject);
}

static void s_DestructEntryImpl(PMW_TLS_ENTRY pEntry) {
	if (pEntry->procDtor) {
		__try {
			pEntry->procDtor(pEntry->arrData);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[ThreadLocal:s_DestructEntryImpl] SEH exception 0x%08X in dtor!\r\n", GetExceptionCode());
		}
	}

	CbHeapFree(pEntry);
}
