#pragma once

#ifndef HEADER_IMPORTHELPER
#define HEADER_IMPORTHELPER

// Allows undecorated functions to be called

#define CB_UNDECORATED_EXTERN(r,f,...)										\
	extern int f;															\
	__declspec(naked) static r __stdcall CbImported ## f(__VA_ARGS__) {		\
		__asm JMP OFFSET f													\
	}

#define CB_UNDECORATED_CALL(f,...) CbImported ## f(__VA_ARGS__)

// d = dll, r = return type, c = calling conv., f = func name
#define CB_LOADONDEMAND_EXTERN(d,r,c,f,...)									\
	typedef r (c* CbOnDemandType ## f)(__VA_ARGS__);						\
																			\
	static CbOnDemandType ## f CbOnDemandRetrieve ## f(void) {				\
		static CbOnDemandType ## f proc;									\
		HANDLE hDLL;														\
																			\
		if (proc == NULL) {													\
			hDLL = LoadLibraryA(d);											\
			if (hDLL == NULL)												\
				return NULL;												\
																			\
			proc = (CbOnDemandType ## f)GetProcAddress(hDLL, #f);			\
			if (proc == NULL)												\
				FreeLibrary(hDLL);											\
		}																	\
																			\
		return proc;														\
	}

#define CB_LOADONDEMAND_CALL(f, ...) (CbOnDemandRetrieve ## f () (__VA_ARGS__))

// fb = fallback return value
#define CB_LOADONDEMAND_TRYCALL(fb, f, ...) ((CbOnDemandRetrieve ## f ()) ? (CbOnDemandRetrieve ## f () (__VA_ARGS__)) : (fb))

struct _TEB;
struct _PEB;

__declspec(naked) static inline struct _TEB* __stdcall CbGetTEB(void) {
	__asm MOV EAX, DWORD PTR FS : [0x18] ;
	__asm RET 0;
}

__declspec(naked) static inline struct _PEB* __stdcall CbGetPEB(void) {
	__asm MOV EAX, DWORD PTR FS : [0x30] ;
	__asm RET 0;
}

#endif
