#pragma once

#ifndef HEADER_WAYSTLS
#define HEADER_WAYSTLS

#ifndef MAGICWAYS_EXPORTED
#ifdef MAGICWAYS_BUILD
#define MAGICWAYS_EXPORTED __declspec(dllexport) __stdcall
#else
#define MAGICWAYS_EXPORTED __declspec(dllimport) __stdcall
#endif
#endif

#define _X86_
#include <minwindef.h>

typedef BOOL (__stdcall* MwTLSCtorProc_t)(PVOID pData);
typedef void (__stdcall* MwTLSDtorProc_t)(PVOID pData);

// get an object stored in TLS, creating it if needed
PVOID MAGICWAYS_EXPORTED MwGetTLS(LPCGUID pcidObject, DWORD nSize, OPTIONAL MwTLSCtorProc_t procCtor, OPTIONAL MwTLSDtorProc_t procDtor, 
	OPTIONAL LPCSTR pcszName);

// tries to get an object stored in TLS, returns null with LastError = ERROR_NOT_FOUND if not found
PVOID MAGICWAYS_EXPORTED MwTryGetTLS(LPCGUID pcidObject);

// discard an object stored in TLS, if it exists
void MAGICWAYS_EXPORTED MwDiscardTLS(LPCGUID pcidObject);

// can be used if ctor/dtor not requred
BOOL MAGICWAYS_EXPORTED MwNullTLSCtor(PVOID pData);
void MAGICWAYS_EXPORTED MwNullTLSDtor(PVOID pData);

#endif
