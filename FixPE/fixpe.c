// Fixes MSVC PE file problems

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <CommandLineToArgv.h>
#include <winternl.h>
#include <stdio.h>
#include <Vfw.h>

#define FIXPE_RICHHEADER_START 0x80

void ENTRY_POINT(void) {
	int argc;
	LPSTR* argv;
	HANDLE hPEFile;
	DWORD nBytesRead;
	IMAGE_DOS_HEADER hdrDOS;
	int nRichHeaderLength;
	LARGE_INTEGER liMoveDist;
	DWORD nReplacement;
	IMAGE_NT_HEADERS hdrNT;

	argv = CommandLineToArgvA(GetCommandLineA(), &argc);
	if (argc < 2) {
		puts("Usage: fixpe <target.exe>");
		ExitProcess(1);
	}

	hPEFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPEFile == INVALID_HANDLE_VALUE) {
		printf("Error 0x%08X opening %s\r\n", GetLastError(), argv[1]);
		ExitProcess(1);
	}

	if (!ReadFile(hPEFile, &hdrDOS, sizeof(hdrDOS), &nBytesRead, NULL)) {
		printf("Error 0x%08X reading DOS header\r\n", GetLastError());
		ExitProcess(1);
	}

	if (hdrDOS.e_magic != MAKEWORD('M', 'Z')) {
		printf("File is not a PE file (DOS header has signature 0x%04X)\r\n", hdrDOS.e_magic);
		ExitProcess(1);
	}

	// strip rich header

	liMoveDist.QuadPart = FIXPE_RICHHEADER_START;
	if (!SetFilePointerEx(hPEFile, liMoveDist, NULL, FILE_BEGIN)) {
		printf("Error 0x%08X seeking to start of rich header\r\n", GetLastError());
		ExitProcess(1);
	}

	nRichHeaderLength = hdrDOS.e_lfanew - FIXPE_RICHHEADER_START;
	nReplacement = mmioFOURCC('b', 'a', 'k', 'a');

	while (nRichHeaderLength >= sizeof(nReplacement)) {
		if (!WriteFile(hPEFile, &nReplacement, sizeof(nReplacement), &nBytesRead, NULL)) {
			printf("Error 0x%08X overwriting rich header\r\n", GetLastError());
			ExitProcess(1);
		}

		nRichHeaderLength -= sizeof(nReplacement);
	}

	// reduce minimum version to NT 5.x

	liMoveDist.QuadPart = hdrDOS.e_lfanew;
	if (!SetFilePointerEx(hPEFile, liMoveDist, NULL, FILE_BEGIN)) {
		printf("Error 0x%08X seeking to start of PE header\r\n", GetLastError());
		ExitProcess(1);
	}

	if (!ReadFile(hPEFile, &hdrNT, sizeof(hdrNT), &nBytesRead, NULL)) {
		printf("Error 0x%08X reading NT header\r\n", GetLastError());
		ExitProcess(1);
	}

	if (hdrNT.Signature != mmioFOURCC('P', 'E', 0, 0)) {
		printf("File is not a PE file (NT header has signature 0x%08X)\r\n", hdrNT.Signature);
		ExitProcess(1);
	}

	hdrNT.OptionalHeader.MajorOperatingSystemVersion = 5;
	hdrNT.OptionalHeader.MinorOperatingSystemVersion = 0;
	hdrNT.OptionalHeader.MajorSubsystemVersion = 5;
	hdrNT.OptionalHeader.MinorSubsystemVersion = 0;

	if (!SetFilePointerEx(hPEFile, liMoveDist, NULL, FILE_BEGIN)) {
		printf("Error 0x%08X seeking back to start of PE header\r\n", GetLastError());
		ExitProcess(1);
	}

	if (!WriteFile(hPEFile, &hdrNT, sizeof(hdrNT), &nBytesRead, NULL)) {
		printf("Error 0x%08X writing NT header\r\n", GetLastError());
		ExitProcess(1);
	}

	printf("Fixed %s\r\n", argv[1]);
	CloseHandle(hPEFile);

	ExitProcess(0);
}

