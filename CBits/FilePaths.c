#include "FilePaths.h"
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
		if ((*pcszString >= 'A') && (*pcszString <= 'Z'))
			*pcszString = 'a' + (*pcszString - 'A');
		pcszString++;
	}
}
