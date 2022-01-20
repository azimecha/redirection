#include "ConfigReading.h"
#include "FilePaths.h"
#include "ImportHelper.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

BOOL CbFindConfigFile(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize) {
	return CbFindConfigFileDirect(pcszFileName, hTargetProcess, pszPathBuffer, nBufSize)
		|| CbFindConfigFileDirect(pcszFileName, GetCurrentProcess(), pszPathBuffer, nBufSize);
}

BOOL CbFindConfigFileDirect(const char* pcszFileName, HANDLE hTargetProcess, char* pszPathBuffer, size_t nBufSize) {
	HANDLE hINIFile;
	LPSTR pszFilenameStart;

	if (!CbGetProcessExecutablePath(hTargetProcess, pszPathBuffer, nBufSize - strlen(pcszFileName)))
		return FALSE;

	pszFilenameStart = (LPSTR)CbPathGetFilenameA(pszPathBuffer);
	if (pszFilenameStart == NULL)
		return FALSE;
	*pszFilenameStart = 0;

	strcat(pszPathBuffer, pcszFileName);

	hINIFile = CreateFileA(pszPathBuffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	CloseHandle(hINIFile);

	return hINIFile != INVALID_HANDLE_VALUE;
}

#define CB_CONFIGREADING_NTPREFIX "\\\\.\\"
#define CB_CONFIGREADING_NTREMOVE "\\Device\\"

BOOL CbGetProcessExecutablePath(HANDLE hProcess, char* pszPathBuffer, size_t nBufSize) {
	char szNTPath[MAX_PATH + 1];

	if (nBufSize < sizeof(CB_CONFIGREADING_NTPREFIX))
		return FALSE;

	strcpy(pszPathBuffer, CB_CONFIGREADING_NTPREFIX);

	if (!GetProcessImageFileNameA(hProcess, pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, nBufSize - (sizeof(CB_CONFIGREADING_NTPREFIX) - 1)))
		return FALSE;

	if (memcmp(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, CB_CONFIGREADING_NTREMOVE, sizeof(CB_CONFIGREADING_NTREMOVE) - 1) != 0)
		return FALSE;

	memmove(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) - 1, pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) + sizeof(CB_CONFIGREADING_NTREMOVE) - 2,
		strlen(pszPathBuffer + sizeof(CB_CONFIGREADING_NTPREFIX) + sizeof(CB_CONFIGREADING_NTREMOVE) - 2) + 1);

	return TRUE;
}

#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND 0xC0000139
#endif

typedef DWORD NTSTATUS;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

CB_LOADONDEMAND_EXTERN("ntdll.dll", NTSTATUS, __stdcall, RtlAnsiStringToUnicodeString, PUNICODE_STRING us, PANSI_STRING as, BOOL bAlloc);
CB_LOADONDEMAND_EXTERN("ntdll.dll", NTSTATUS, __stdcall, RtlUnicodeStringToAnsiString, PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
CB_LOADONDEMAND_EXTERN("ntdll.dll", ULONG, __stdcall, RtlNtStatusToDosError, NTSTATUS status);

#if 0

// https://stackoverflow.com/questions/4445108/how-can-i-convert-a-native-nt-pathname-into-a-win32-path-name



//typedef NTSTATUS(WINAPI* RtlAnsiStringToUnicodeString_t)(PUNICODE_STRING, PANSI_STRING, BOOL);

typedef struct _RTL_BUFFER {
	PUCHAR    Buffer;
	PUCHAR    StaticBuffer;
	SIZE_T    Size;
	SIZE_T    StaticSize;
	SIZE_T    ReservedForAllocatedSize; // for future doubling
	PVOID     ReservedForIMalloc; // for future pluggable growth
} RTL_BUFFER, * PRTL_BUFFER;

typedef struct _RTL_UNICODE_STRING_BUFFER {
	UNICODE_STRING String;
	RTL_BUFFER     ByteBuffer;
	UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;

#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_AMBIGUOUS   (0x00000001)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_UNC         (0x00000002)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_DRIVE       (0x00000003)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_ALREADY_DOS (0x00000004)

//typedef NTSTATUS(WINAPI* RtlNtPathNameToDosPathName_t)(__in ULONG Flags, __inout PRTL_UNICODE_STRING_BUFFER Path, __out_opt PULONG Disposition, __inout_opt PWSTR* FilePart);

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)
#define RTL_DUPSTR_ADD_NULL                          RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE
#define RTL_DUPSTR_ALLOC_NULL                        RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING

//typedef NTSTATUS(WINAPI* RtlDuplicateUnicodeString_t)(_In_ ULONG Flags, _In_ PUNICODE_STRING StringIn, _Out_ PUNICODE_STRING StringOut);

/*typedef NTSTATUS(WINAPI* RtlUnicodeStringToAnsiString_t)(
	PANSI_STRING     DestinationString,
	PCUNICODE_STRING SourceString,
	BOOLEAN          AllocateDestinationString
);

typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS status);*/

CB_LOADONDEMAND_EXTERN("ntdll.dll", NTSTATUS, __stdcall, RtlNtPathNameToDosPathName, ULONG Flags, PRTL_UNICODE_STRING_BUFFER Path, PULONG Disposition, PWSTR* FilePart);
CB_LOADONDEMAND_EXTERN("ntdll.dll", NTSTATUS, __stdcall, RtlDuplicateUnicodeString, ULONG Flags, PUNICODE_STRING StringIn, PUNICODE_STRING StringOut);

BOOL CbNtPathToWinPath(const char* pcszNTPath, char* pszWinPath, size_t nBufSize) {
	NTSTATUS status;
	ANSI_STRING asNTPath, asWinPath;
	WCHAR wzPath[MAX_PATH + 1];
	RTL_UNICODE_STRING_BUFFER usbPath;

	asNTPath.Buffer = (PCHAR)pcszNTPath;
	asNTPath.Length = (USHORT)strlen(pcszNTPath);
	asNTPath.MaximumLength = asNTPath.Length + 1;

	RtlSecureZeroMemory(&usbPath, sizeof(usbPath));
	usbPath.String.Buffer = wzPath;
	usbPath.String.Length = 0;
	usbPath.String.MaximumLength = ARRAYSIZE(wzPath);
	usbPath.ByteBuffer.Buffer = (PUCHAR)wzPath;
	usbPath.ByteBuffer.Size = sizeof(wzPath);

	status = CB_LOADONDEMAND_TRYCALL(STATUS_ENTRYPOINT_NOT_FOUND, RtlAnsiStringToUnicodeString, &usbPath.String, &asNTPath, FALSE);
	if (status != 0) {
		SetLastError(CB_LOADONDEMAND_TRYCALL(ERROR_NOT_FOUND, RtlNtStatusToDosError, status));
		return FALSE;
	}

	status = CB_LOADONDEMAND_TRYCALL(STATUS_ENTRYPOINT_NOT_FOUND, RtlNtPathNameToDosPathName, 0, &usbPath, NULL, NULL);
	if (status != 0) {
		SetLastError(CB_LOADONDEMAND_TRYCALL(ERROR_NOT_FOUND, RtlNtStatusToDosError, status));
		return FALSE;
	}

	asWinPath.Buffer = pszWinPath;
	asWinPath.Length = 0;
	asWinPath.MaximumLength = (USHORT)nBufSize;

	status = CB_LOADONDEMAND_TRYCALL(STATUS_ENTRYPOINT_NOT_FOUND, RtlUnicodeStringToAnsiString, &asWinPath, &usbPath.String, FALSE);
	if (status != 0) {
		SetLastError(CB_LOADONDEMAND_TRYCALL(ERROR_NOT_FOUND, RtlNtStatusToDosError, status));
		return FALSE;
	}

	return TRUE;
}

#elif 0

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

CB_LOADONDEMAND_EXTERN("ntdll.dll", NTSTATUS, __stdcall, NtCreateFile, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

#define FILE_OPEN 1

BOOL CbNtPathToWinPath(const char* pcszNTPath, char* pszWinPath, size_t nBufSize) {
	NTSTATUS status;
	ANSI_STRING asNTPath, asWinPath;
	WCHAR wzPath[MAX_PATH + 1];
	UNICODE_STRING usNTPath;
	HANDLE hFile;
	OBJECT_ATTRIBUTES attrib;
	IO_STATUS_BLOCK iosb;

	asNTPath.Buffer = (PCHAR)pcszNTPath;
	asNTPath.Length = (USHORT)strlen(pcszNTPath);
	asNTPath.MaximumLength = asNTPath.Length + 1;

	usNTPath.Buffer = wzPath;
	usNTPath.Length = 0;
	usNTPath.MaximumLength = ARRAYSIZE(wzPath);

	status = CB_LOADONDEMAND_TRYCALL(STATUS_ENTRYPOINT_NOT_FOUND, RtlAnsiStringToUnicodeString, &usNTPath, &asNTPath, FALSE);
	if (status != 0) {
		SetLastError(CB_LOADONDEMAND_TRYCALL(ERROR_NOT_FOUND, RtlNtStatusToDosError, status));
		return FALSE;
	}

	RtlSecureZeroMemory(&attrib, sizeof(attrib));
	attrib.ObjectName = &usNTPath;

	status = CB_LOADONDEMAND_TRYCALL(STATUS_ENTRYPOINT_NOT_FOUND, NtCreateFile, &hFile, GENERIC_READ, &attrib, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0);
	if (status != 0) {
		SetLastError(CB_LOADONDEMAND_TRYCALL(ERROR_NOT_FOUND, RtlNtStatusToDosError, status));
		return FALSE;
	}


}

#elif 0

// https://docs.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle

BOOL CbNtPathToWinPath(const char* pcszNTPath, char* pszWinPath, size_t nBufSize) {
	// Translate path with device name to drive letters.
	char szTemp[MAX_PATH];
	char szName[MAX_PATH];
	char szTempFile[MAX_PATH];
	char szDrive[3];
	BOOL bFound = FALSE;
	char* p;
	size_t uNameLen;

	szTemp[0] = '\0';

	if (GetLogicalDriveStringsA(MAX_PATH - 1, szTemp)) {
		p = szTemp;

		do {
			// Copy the drive letter to the template string
			*szDrive = *p;

			// Look up each device name
			if (QueryDosDeviceA(szDrive, szName, MAX_PATH)) {
				uNameLen = strlen(szName);

				if (uNameLen < MAX_PATH) {
					bFound = strcmp(pcszNTPath, szName, uNameLen) == 0 && *(pcszNTPath + uNameLen) == '\\';

					if (bFound) {
						// Reconstruct pszFilename using szTempFile
						// Replace device path with DOS path
						/*TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile,
							MAX_PATH,
							TEXT("%s%s"),
							szDrive,
							pcszNTPath + uNameLen);
						StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));*/

						snprintf(szTempFile, MAX_PATH, "%s%s", szDrive, pcszNTPath + uNameLen);
						strncpy(pszWinPath, szTempFile, nBufSize);
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		} while (!bFound && *p); // end of string
	}

	return bFound;
}

#endif

