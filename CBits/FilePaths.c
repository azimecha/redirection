#include "FilePaths.h"
#include "PartialStdio.h"
#include <string.h>

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
