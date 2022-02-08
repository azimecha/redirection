#include "FilePaths.h"
#include "NTDLL.h"
#include <string.h>
#include <stdint.h>

void CbPathRemoveExtensionA(char* pcszPath) {
	// get filename part only
	pcszPath = (char*)CbPathGetFilenameA(pcszPath);
	
	// find last dot
	pcszPath = strrchr(pcszPath, '.');

	// found one? replace it with a null
	if (pcszPath) *pcszPath = 0;
}

const char* CbPathGetFilenameA(const char* pcszPath) {
	const char* pcszCur;

	for (pcszCur = CbStringSeekEndA(pcszPath); pcszCur >= pcszPath; pcszCur--) {
		switch (*pcszCur) {
		case ':':
		case '\\':
		case '/':
			return pcszCur + 1;
		}
	}

	return pcszPath;
}

const char* CbStringSeekEndA(const char* pcszString) {
	while (*pcszString) pcszString++;
	return pcszString;
}

void CbStringToLowerA(char* pcszString) {
	while (*pcszString) {
		*pcszString = (char)tolower(*pcszString);
		pcszString++;
	}
}

int CbStringStartsWithA(const char* pcszCheck, const char* pcszCheckFor) {
	while (*pcszCheckFor) {
		if (*pcszCheck != *pcszCheckFor)
			return 0;
		pcszCheck++; pcszCheckFor++;
	}

	return 1;
}

int CbStringStartsWithIA(const char* pcszCheck, const char* pcszCheckFor) {
	while (*pcszCheckFor) {
		if (tolower(*pcszCheck) != tolower(*pcszCheckFor))
			return 0;
		pcszCheck++; pcszCheckFor++;
	}

	return 1;
}

int CbTryAppendToBufferA(char** ppszBuffer, size_t* pnSize, const char* pcszToAppend) {
	size_t nLength;

	nLength = strlen(pcszToAppend);
	if (nLength >= *pnSize)
		return 0;

	memcpy(*ppszBuffer, pcszToAppend, nLength + 1);

	*ppszBuffer += nLength;
	*pnSize -= nLength;
	return 1;
}


int stricmp(const char* a, const char* b) {
	return strnicmp(a, b, SIZE_MAX);
}

int strnicmp(const char* a, const char* b, size_t n) {
	char ca, cb;

	while (*a && *b && n) {
		ca = tolower(*a);
		cb = tolower(*b);
		if (ca < cb) return -1;
		if (ca > cb) return 1;

		a++; b++; n--;
	}

	// at this point one (or both) is a null so we don't need to convert
	if (n == 0)
		return 0;
	else if (*a < *b)
		return -1;
	else if (*a > *b)
		return 1;
	else
		return 0;
}

int strccat(char* pszDest, size_t nDestBufSize, const char* pcszSrc) {
	if (nDestBufSize == 0)
		return pcszSrc[0] == '\0';

	nDestBufSize--; // leave space for null

	while (*pszDest && (nDestBufSize > 0)) {
		pszDest++;
		nDestBufSize--;
	}

	if (nDestBufSize == 0)
		return pcszSrc[0] == '\0';

	while (*pcszSrc && (nDestBufSize > 0)) {
		*pszDest = *pcszSrc;
		pszDest++;
		pcszSrc++;
		nDestBufSize--;
	}

	*pszDest = 0;
	return *pcszSrc == 0;
}

size_t wcstombs(char* pszDest, const wchar_t* pwzSrc, size_t nMax) {
	UNICODE_STRING usSrc;
	ANSI_STRING asDest;

	usSrc.Buffer = (LPWSTR)pwzSrc;
	usSrc.Length = (USHORT)wcslen(pwzSrc);
	usSrc.MaximumLength = usSrc.Length;

	asDest.Buffer = pszDest;
	asDest.Length = 0;
	asDest.MaximumLength = (USHORT)(nMax - 1);

	if (RtlUnicodeStringToAnsiString(&asDest, &usSrc, FALSE))
		return (size_t)-1;

	pszDest[asDest.Length] = 0;
	return asDest.Length;
}

size_t mbstowcs(wchar_t* pwzDest, const char* pszSrc, size_t nMax) {
	UNICODE_STRING usDest;
	ANSI_STRING asSrc;

	asSrc.Buffer = (LPSTR)pszSrc;
	asSrc.Length = (USHORT)strlen(pszSrc);
	asSrc.MaximumLength = asSrc.Length;

	usDest.Buffer = pwzDest;
	usDest.Length = 0;
	usDest.MaximumLength = (USHORT)(nMax - 1);

	if (RtlAnsiStringToUnicodeString(&usDest, &asSrc, FALSE))
		return (size_t)-1;

	pwzDest[usDest.Length / 2] = 0;
	return usDest.Length / 2;
}

size_t wcslen(const wchar_t* pcwzString) {
	size_t nLength = 0;

	while (*pcwzString) {
		nLength++;
		pcwzString++;
	}

	return nLength;
}
