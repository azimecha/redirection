#include "NTDLL.h"
#include "ImportHelper.h"

/*
#define CB_NTDLL_DEFINE(r,n,...)											\
	static const char s_cszFunc ## n [] = #n;								\
	static LPVOID s_pFunc ## n = NULL;										\
	__declspec(naked) r __stdcall n(__VA_ARGS__) {							\
		__asm { MOV EAX, DWORD PTR s_pFunc ## n }							\
		__asm { OR EAX, EAX }												\
		__asm { JNZ L_found }												\
		__asm { PUSH OFFSET s_cszFunc ## n }								\
		__asm { CALL CbGetNTDLLFunction }									\
		__asm { MOV DWORD PTR s_pFunc ## n, EAX}							\
	L_found:																\
		__asm { PUSH EAX }													\
		__asm { RET }														\
	}
*/

#define CB_NTDLL_DEFINE(r,n,a1,a2)											\
	static r (__stdcall* s_func ## n)a1;									\
	r __stdcall n a1 {														\
		if ((s_func ## n) == NULL)											\
			s_func ## n = CbGetNTDLLFunction(#n);							\
		return s_func ## n a2;												\
	}


typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	void*  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	void* PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA_FULL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA_FULL, * PPEB_LDR_DATA_FULL;

C_ASSERT(FIELD_OFFSET(PEB_LDR_DATA_FULL, InLoadOrderModuleList) == 0x0C);

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
} LDR_DATA_TABLE_ENTRY_FULL, * PLDR_DATA_TABLE_ENTRY_FULL;

LPVOID __stdcall CbGetNTDLLFunction(LPCSTR pcszFuncName) {
	PPEB_LDR_DATA_FULL pdataLoader;
	PLDR_DATA_TABLE_ENTRY_FULL pentNTDLL;
	PIMAGE_DOS_HEADER phdrDOS;
	PIMAGE_NT_HEADERS phdrNT;
	PIMAGE_EXPORT_DIRECTORY pdirExports;
	LPWORD pnOrdinals;
	LPDWORD pnNameRVAs;
	LPDWORD pnFunctionRVAs;
	DWORD nName;
	LPCSTR pcszCurName;

	pdataLoader = (PPEB_LDR_DATA_FULL)(CbGetPEB()->Ldr);
	pentNTDLL = CONTAINING_RECORD(pdataLoader->InLoadOrderModuleList.Flink->Flink, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
	phdrDOS = (PIMAGE_DOS_HEADER)pentNTDLL->DllBase;
	phdrNT = (PIMAGE_NT_HEADERS)((BYTE*)phdrDOS + phdrDOS->e_lfanew);
	pdirExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)phdrDOS + phdrNT->OptionalHeader.DataDirectory[0].VirtualAddress);

	pnOrdinals = (LPWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNameOrdinals);
	pnNameRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfNames);
	pnFunctionRVAs = (LPDWORD)((BYTE*)phdrDOS + pdirExports->AddressOfFunctions);

	for (nName = 0; nName < pdirExports->NumberOfNames; nName++) {
		pcszCurName = (LPCSTR)((BYTE*)phdrDOS + pnNameRVAs[nName]);
		if (strcmp(pcszCurName, pcszFuncName) == 0)
			return (BYTE*)phdrDOS + pnFunctionRVAs[pnOrdinals[nName]];
	}

	return NULL;
}

CB_NTDLL_DEFINE(NTSTATUS, RtlAnsiStringToUnicodeString, (PUNICODE_STRING a, PCANSI_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(NTSTATUS, RtlUnicodeStringToAnsiString, (PANSI_STRING a, PCUNICODE_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(NTSTATUS, NtQueryInformationFile, (HANDLE a, PIO_STATUS_BLOCK b, PVOID c, ULONG d, FILE_INFORMATION_CLASS e), (a, b, c, d, e));
