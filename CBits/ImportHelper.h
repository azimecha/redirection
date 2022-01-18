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

#endif
