#pragma once

#ifndef HEADER_NTDLL
#define HEADER_NTDLL

#include "ImportHelper.h"

#define _X86_
#include <minwindef.h>

typedef DWORD NTSTATUS;
typedef ULONG ACCESS_MASK;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef const ANSI_STRING* PCANSI_STRING;

#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND 0xC0000139
#endif

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_BUFFER {
	PUCHAR    Buffer;
	PUCHAR    StaticBuffer;
	SIZE_T    Size;
	SIZE_T    StaticSize;
	SIZE_T    ReservedForAllocatedSize;
	PVOID     ReservedForIMalloc;
} RTL_BUFFER, * PRTL_BUFFER;

typedef struct _RTL_UNICODE_STRING_BUFFER {
	UNICODE_STRING String;
	RTL_BUFFER     ByteBuffer;
	UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS(__stdcall* NtCreateSection_t)(PHANDLE phSection, ACCESS_MASK access, POBJECT_ATTRIBUTES attrib,
	PLARGE_INTEGER pnMaxSize, ULONG nProtection, ULONG nAllocAttribs, HANDLE hFile);

typedef NTSTATUS(__stdcall* NtMapViewOfSection_t)(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, DWORD nInheritDisposition,
	ULONG nAllocationType, ULONG nWin32Protection);

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

        //
        //  These are special versions of these operations (defined earlier)
        //  which can be used by kernel mode drivers only to bypass security
        //  access checks for Rename and HardLink operations.  These operations
        //  are only recognized by the IOManager, a file system should never
        //  receive these.
        //

        FileRenameInformationBypassAccessCheck,         // 56
        FileLinkInformationBypassAccessCheck,           // 57

            //
            // End of special information classes reserved for IOManager.
            //

            FileVolumeNameInformation,                      // 58
            FileIdInformation,                              // 59
            FileIdExtdDirectoryInformation,                 // 60
            FileReplaceCompletionInformation,               // 61
            FileHardLinkFullIdInformation,                  // 62
            FileIdExtdBothDirectoryInformation,             // 63
            FileDispositionInformationEx,                   // 64
            FileRenameInformationEx,                        // 65
            FileRenameInformationExBypassAccessCheck,       // 66
            FileDesiredStorageClassInformation,             // 67
            FileStatInformation,                            // 68
            FileMemoryPartitionInformation,                 // 69
            FileStatLxInformation,                          // 70
            FileCaseSensitiveInformation,                   // 71
            FileLinkInformationEx,                          // 72
            FileLinkInformationExBypassAccessCheck,         // 73
            FileStorageReserveIdInformation,                // 74
            FileCaseSensitiveInformationForceAccessCheck,   // 75
            FileKnownFolderInformation,   // 76

            FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// Process Environment Block
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	void* ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	void* PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

// Thread Environment Block
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
typedef struct _TEB {
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB  ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID Reserved2[397];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

C_ASSERT(FIELD_OFFSET(TEB, ProcessEnvironmentBlock) == 0x30);
C_ASSERT(FIELD_OFFSET(TEB, TlsSlots) == 0x0E10);

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA_FULL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA_FULL, * PPEB_LDR_DATA_FULL;

C_ASSERT(FIELD_OFFSET(PEB_LDR_DATA_FULL, InLoadOrderModuleList) == 0x0C);

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
} LDR_DATA_TABLE_ENTRY_FULL, * PLDR_DATA_TABLE_ENTRY_FULL;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID                   EntryPoint;
	ULONG                   StackZeroBits;
	ULONG                   StackReserved;
	ULONG                   StackCommit;
	ULONG                   ImageSubsystem;
	WORD                    SubSystemVersionLow;
	WORD                    SubSystemVersionHigh;
	ULONG                   Unknown1;
	ULONG                   ImageCharacteristics;
	ULONG                   ImageMachineType;
	ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

// TODO: Different on older versions of Windows? 
// see http://www.rohitab.com/discuss/topic/41092-how-to-use-ntqueryvirtualmemory-to-get-loaded-dlls/
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

NTSTATUS __stdcall RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
NTSTATUS __stdcall RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
NTSTATUS __stdcall NtQueryInformationFile(HANDLE hFile, PIO_STATUS_BLOCK piosb, PVOID pInfoBuffer, ULONG nBufSize, FILE_INFORMATION_CLASS iclass);
NTSTATUS __stdcall NtQuerySection(HANDLE hSection, SECTION_INFORMATION_CLASS iclass, PVOID pInfoBuffer, ULONG nBufSize, PULONG pResultSize);
NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE hProcess, PVOID pBaseAddress);
NTSTATUS __stdcall NtQueryVirtualMemory(HANDLE hProcess, PVOID pBaseAddress, MEMORY_INFORMATION_CLASS iclass, PVOID pBuffer, ULONG nBufSize,
	PULONG pnResultSize);

LPVOID __stdcall CbGetNTDLLFunction(LPCSTR pcszFuncName);

#endif
