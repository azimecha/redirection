#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifdef _MSC_VER
#pragma warning(disable:6031)
#endif

#if 0

// Unlike the standard one, this strncpy is actually secure (pszDest will always be null terminated)
char* strncpy(char* pszDest, const char* pcszSrc, size_t nDestSize) {
	RtlSecureZeroMemory(pszDest, nDestSize);
	lstrcpynA(pszDest, pcszSrc, nDestSize - 1);
	return pszDest;
}

#endif
