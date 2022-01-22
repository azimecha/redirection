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


LPVOID __stdcall CbGetNTDLLFunction(LPCSTR pcszFuncName) {
	PLDR_DATA_TABLE_ENTRY_FULL pentNTDLL;

	pentNTDLL = CbGetLoadedImageByIndex(1);
	if (pentNTDLL == NULL) return NULL;

	return CbGetSymbolAddress(pentNTDLL->DllBase, pcszFuncName);
}

CB_NTDLL_DEFINE(NTSTATUS, RtlAnsiStringToUnicodeString, (PUNICODE_STRING a, PCANSI_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(NTSTATUS, RtlUnicodeStringToAnsiString, (PANSI_STRING a, PCUNICODE_STRING b, BOOLEAN c), (a, b, c));
CB_NTDLL_DEFINE(NTSTATUS, NtQueryInformationFile, (HANDLE a, PIO_STATUS_BLOCK b, PVOID c, ULONG d, FILE_INFORMATION_CLASS e), (a, b, c, d, e));
CB_NTDLL_DEFINE(NTSTATUS, NtQuerySection, (HANDLE a, SECTION_INFORMATION_CLASS b, PVOID c, ULONG d, PULONG e), (a, b, c, d, e));
CB_NTDLL_DEFINE(NTSTATUS, NtUnmapViewOfSection, (HANDLE a, PVOID b), (a, b));
