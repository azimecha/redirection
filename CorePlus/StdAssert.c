#include "PartialStdio.h"
#include <stdio.h>
#include <assert.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void _assert(char const* pcszMessage, char const* pcszFilename, unsigned nLine) {
	char szBuffer[1024];

	snprintf(szBuffer, sizeof(szBuffer), "Assertion failed: %s\r\nLocation: %s line %u\r\n", pcszMessage, pcszFilename, nLine);
	printf("%s", szBuffer);
	MessageBoxA(NULL, szBuffer, "Error", MB_ICONERROR);
	ExitProcess(1);
}

void _wassert(wchar_t const* pcwzMessage, wchar_t const* pcwzFilename, unsigned nLine) {
	char szMessageBuf[512];
	char szFilenameBuf[MAX_PATH];

	if (wcstombs(szMessageBuf, pcwzMessage, sizeof(szMessageBuf)) == (size_t)-1)
		strncpy(szMessageBuf, "(message too long)", sizeof(szMessageBuf));

	if (wcstombs(szFilenameBuf, pcwzFilename, sizeof(szFilenameBuf)) == (size_t)-1)
		strncpy(szFilenameBuf, "(filename too long)", sizeof(szFilenameBuf));

	_assert(szMessageBuf, szFilenameBuf, nLine);
}
