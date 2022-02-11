#pragma once

#ifndef HEADER_WAYSTLS
#define HEADER_WAYSTLS

#ifndef MAGICWAYS_EXPORTED
#ifdef MAGICWAYS_BUILD
#define MAGICWAYS_EXPORTED __declspec(dllexport)
#else
#define MAGICWAYS_EXPORTED __declspec(dllimport)
#endif
#endif

#define _X86_
#include <minwindef.h>

typedef BOOL (__stdcall* MwTLSCtorProc_t)(PVOID pData);
typedef void (__stdcall* MwTLSDtorProc_t)(PVOID pData);

// get an object stored in TLS, creating it if needed
PVOID MAGICWAYS_EXPORTED MwGetTLS(LPCGUID pidObject, DWORD nSize, OPTIONAL MwTLSCtorProc_t procCtor, OPTIONAL MwTLSDtorProc_t procDtor, 
	OPTIONAL LPCSTR pcszName);

// discard an object stored in TLS, if it exists
void MAGICWAYS_EXPORTED MwDiscardTLS(LPCGUID pidObject);

#endif
