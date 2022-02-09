#pragma once

#ifndef HEADER_NTDLL
#define HEADER_NTDLL

#include "ImportHelper.h"

#ifndef STATUS_INVALID_PARAMETER_1
#define STATUS_INVALID_PARAMETER_1 0xC00000EF
#endif

#ifndef STATUS_INVALID_PARAMETER_2
#define STATUS_INVALID_PARAMETER_2 0xC00000F0
#endif

#ifndef STATUS_INVALID_PARAMETER_3
#define STATUS_INVALID_PARAMETER_3 0xC00000F1
#endif

#ifndef STATUS_INVALID_PARAMETER_4
#define STATUS_INVALID_PARAMETER_4 0xC00000F2
#endif

// Define CB_NTDLL_NO_TYPES to prevent any types from being declared that could conflict with ones in Windows headers
#ifndef CB_NTDLL_NO_TYPES

#define _X86_
#include <minwindef.h>

#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_CREATE_TREE_CONNECTION 0x00000080
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000
#define FILE_COPY_STRUCTURED_STORAGE 0x00000041
#define FILE_STRUCTURED_STORAGE 0x00000441

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005

#define OBJ_CASE_INSENSITIVE 0x40

#define CB_CURRENT_PROCESS (HANDLE)(-1)

#ifndef STATUS_FILE_CORRUPT_ERROR
#define STATUS_FILE_CORRUPT_ERROR 0xC0000102
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND 0xC0000225
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#endif

#ifndef STATUS_NO_SUCH_FILE
#define STATUS_NO_SUCH_FILE 0xC000000F
#endif

#ifndef STATUS_SEVERITY_SUCCESS
#define STATUS_SEVERITY_SUCCESS 0
#endif

#ifndef STATUS_SEVERITY_INFORMATIONAL
#define STATUS_SEVERITY_INFORMATIONAL 1
#endif

#ifndef STATUS_SEVERITY_WARNING
#define STATUS_SEVERITY_WARNING 2
#endif

#ifndef STATUS_SEVERITY_ERROR
#define STATUS_SEVERITY_ERROR 3
#endif

#define CB_NTSTATUS_SEVERITY(s) (((s) & 0xC0000000) >> 30)
#define CB_NT_FAILED(s) (CB_NTSTATUS_SEVERITY(s) == STATUS_SEVERITY_ERROR)

#ifndef WAIT_ABANDONED
#define WAIT_ABANDONED 0x0080
#endif

#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0
#endif

#ifndef WAIT_TIMEOUT
#define WAIT_TIMEOUT 0x0102
#endif

#ifndef WAIT_FAILED
#define WAIT_FAILED (DWORD)0xFFFFFFFF
#endif

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

typedef struct _STRING {
	WORD Length;
	WORD MaximumLength;
	CHAR* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef PVOID* PPVOID;

typedef struct _PEB_FULL {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID					FastPebLockRoutine;
	PVOID					FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID					FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID*					ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB_FULL, * PPEB_FULL;

C_ASSERT(sizeof(PEB_FULL) == sizeof(PEB));

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
	PVOID Reserved5a[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

C_ASSERT(FIELD_OFFSET(TEB, ProcessEnvironmentBlock) == 0x30);
C_ASSERT(FIELD_OFFSET(TEB, TlsSlots) == 0x0E10);
C_ASSERT(FIELD_OFFSET(TEB, TlsExpansionSlots) == 0x0F94);

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

// https://www.nirsoft.net/kernel_struct/vista/SECTION_IMAGE_INFORMATION.html
typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	ULONG MaximumStackSize;
	ULONG CommittedStackSize;
	ULONG SubSystemType;
	union {
		struct {
			WORD SubSystemMinorVersion;
			WORD SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	WORD ImageCharacteristics;
	WORD DllCharacteristics;
	WORD Machine;
	UCHAR ImageContainsCode;
	UCHAR ImageFlags;
	ULONG ComPlusNativeReady : 1;
	ULONG ComPlusILOnly : 1;
	ULONG ImageDynamicallyRelocated : 1;
	ULONG Reserved : 5;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
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

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// https://stackoverflow.com/questions/5454667/how-to-get-the-process-environment-block-peb-from-extern-process
// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29,
	ProcessSubsystemInformation = 75
} PROCESSINFOCLASS;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _RTL_PATH_TYPE {
	RtlPathTypeUnknown,
	RtlPathTypeUncAbsolute,
	RtlPathTypeDriveAbsolute,
	RtlPathTypeDriveRelative,
	RtlPathTypeRooted,
	RtlPathTypeRelative,
	RtlPathTypeLocalDevice,
	RtlPathTypeRootLocalDevice
} RTL_PATH_TYPE;

// https://jgrunzweig.github.io/posts/2014/12/unique-technique-for-iterating-through-processes/
typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _VM_COUNTERS {
	SIZE_T             PeakVirtualSize;
	SIZE_T             VirtualSize;
	ULONG              PageFaultCount;
	SIZE_T             PeakWorkingSetSize;
	SIZE_T             WorkingSetSize;
	SIZE_T             QuotaPeakPagedPoolUsage;
	SIZE_T             QuotaPagedPoolUsage;
	SIZE_T             QuotaPeakNonPagedPoolUsage;
	SIZE_T             QuotaNonPagedPoolUsage;
	SIZE_T             PagefileUsage;
	SIZE_T             PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {
	ULONG              NextEntryDelta;
	ULONG              ThreadCount;
	ULONG              Reserved1[6];
	LARGE_INTEGER      CreateTime;
	LARGE_INTEGER      UserTime;
	LARGE_INTEGER      KernelTime;
	UNICODE_STRING     ProcessName;
	KPRIORITY          BasePriority;
	ULONG              ProcessId;
	ULONG              InheritedFromProcessId;
	ULONG              HandleCount;
	ULONG              Reserved2[2];
	VM_COUNTERS        VmCounters;
	IO_COUNTERS        IoCounters;
	SYSTEM_THREADS     Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessAndThreadInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(__stdcall* NtQuerySection_t)(HANDLE hSection, SECTION_INFORMATION_CLASS iclass, PVOID pInfoBuffer, ULONG nBufSize,
	PULONG pnResultSize);

typedef NTSTATUS(__stdcall* NtCreateFile_t)(PHANDLE phFile, ACCESS_MASK access, POBJECT_ATTRIBUTES pAttrs, PIO_STATUS_BLOCK piosb,
	PLARGE_INTEGER pliAllocSize, ULONG attribs, ULONG nShare, ULONG nCreateDisposition, ULONG nCreateOption, PVOID pEABuffer,
	ULONG nEALength);

typedef NTSTATUS(__stdcall* LdrGetProcedureAddress_t)(HMODULE hModule, OPTIONAL PANSI_STRING pasFuncName, OPTIONAL WORD nOrdinal,
	OUT PVOID* ppAddressOUT);

typedef ULONG(__stdcall* RtlGetCurrentDirectory_U_t)(ULONG nMaxLen, OUT PWSTR pwzBuffer);

typedef BOOLEAN(__stdcall* RtlDoesFileExists_U_t)(PCWSTR pcwzPath); // [sic]

typedef ULONG (__stdcall* RtlGetFullPathName_U_t)(PCWSTR pcwzFileName, ULONG nBufSize, OUT PWSTR pwzBuffer, OPTIONAL OUT PWSTR pwzShortName);

typedef void(__stdcall* CbNTSubroutine_t)(void);

typedef NTSTATUS(__stdcall* DbgPrint_t)(LPCSTR pcszFormat, ...);

typedef void(__stdcall* RtlUnwind_t)(PVOID pTargetFrame, PVOID pTargetIP, PEXCEPTION_RECORD pExceptionRecord, PVOID pReturnValue);

#endif // CB_NTDLL_NO_TYPES

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

// Define CB_NTDLL_NO_TYPES to prevent any functions from being declared that could conflict with ones in Windows headers
#ifndef CB_NTDLL_NO_FUNCS

NTSTATUS __stdcall NtQueryInformationFile(HANDLE hFile, PIO_STATUS_BLOCK piosb, PVOID pInfoBuffer, ULONG nBufSize, FILE_INFORMATION_CLASS iclass);
NTSTATUS __stdcall NtQuerySection(HANDLE hSection, SECTION_INFORMATION_CLASS iclass, PVOID pInfoBuffer, ULONG nBufSize, PULONG pnResultSize);
NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE hProcess, PVOID pBaseAddress);
NTSTATUS __stdcall NtQueryVirtualMemory(HANDLE hProcess, PVOID pBaseAddress, MEMORY_INFORMATION_CLASS iclass, PVOID pBuffer, ULONG nBufSize,
	PULONG pnResultSize);
NTSTATUS __stdcall NtRaiseHardError(LONG nStatus, ULONG nParams, ULONG nMask, PULONG_PTR pnParams, ULONG nValidOptions, PULONG pnRespOption);
NTSTATUS __stdcall NtTerminateProcess(HANDLE hProcess, NTSTATUS nExitStatus);
NTSTATUS __stdcall NtMapViewOfSection(HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress,
	ULONG_PTR nZeroBits, SIZE_T nCommitSize, PLARGE_INTEGER pnSectionOffset, PSIZE_T pnViewSize, SECTION_INHERIT inherit,
	ULONG nAllocationType, ULONG nWin32Protection);
NTSTATUS __stdcall NtSuspendProcess(HANDLE hProcess);
NTSTATUS __stdcall NtResumeProcess(HANDLE hProcess);
NTSTATUS __stdcall NtQueryInformationProcess(HANDLE hProcess, PROCESSINFOCLASS iclass, PVOID pBuffer, ULONG nBufSize, PULONG npResultSize);
NTSTATUS __stdcall NtFlushInstructionCache(HANDLE hProcess, PVOID pBaseAddress, ULONG nBytes);
NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE hProcess, PVOID* ppBaseAddress, PULONG pnToProtect, ULONG nNewProt, PULONG pnOldProt);
NTSTATUS __stdcall NtCreateFile(PHANDLE phFile, ACCESS_MASK access, POBJECT_ATTRIBUTES pattr, PIO_STATUS_BLOCK piosb, PLARGE_INTEGER pliAllocSize,
	ULONG attribs, ULONG nShareMode, ULONG nCreateDisp, ULONG nCreateOpts, PVOID pEABuffer, ULONG nEALength);
NTSTATUS __stdcall NtCreateSection(PHANDLE phSection, ULONG nAccess, OPTIONAL POBJECT_ATTRIBUTES pattr, OPTIONAL PLARGE_INTEGER pliMaxSize,
	ULONG attribPage, ULONG attribSection, OPTIONAL HANDLE hFile);
NTSTATUS __stdcall NtClose(HANDLE hObject);
NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE hProcess, IN OUT PVOID* ppBase, ULONG nZeroBits, IN OUT PULONG pnSize, ULONG nType, ULONG nProtection);
NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE hProcess, PVOID* ppBase, IN OUT PULONG pnSize, ULONG nFreeType);
NTSTATUS __stdcall NtQuerySystemTime(PLARGE_INTEGER pliSystemTime);
NTSTATUS __stdcall NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS iclass, PVOID pBuffer, ULONG nBufSize, PULONG pnValueSize);
NTSTATUS __stdcall NtGetContextThread(HANDLE hThread, PCONTEXT pctx);
NTSTATUS __stdcall NtSuspendThread(HANDLE hThread, OUT OPTIONAL PULONG pnPrevSusCount);
NTSTATUS __stdcall NtResumeThread(HANDLE hThread, OUT OPTIONAL PULONG pnRemainingSusCount);
NTSTATUS __stdcall NtOpenThread(OUT PHANDLE pHThread, ACCESS_MASK maskAccess, POBJECT_ATTRIBUTES pAttribs, CLIENT_ID* pThreadID);

NTSTATUS __stdcall RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
NTSTATUS __stdcall RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
ULONG __stdcall RtlNtStatusToDosError(NTSTATUS status);
void __stdcall RtlFreeUnicodeString(PUNICODE_STRING pusFromRtl);
ULONG __stdcall RtlGetCurrentDirectory_U(ULONG nMaxLen, OUT PWSTR pwzBuffer);
BOOLEAN __stdcall RtlDoesFileExists_U(PCWSTR pcwzPath);
ULONG __stdcall RtlGetFullPathName_U(PCWSTR pcwzFileName, ULONG nBufSize, OUT PWSTR pwzBuffer, OPTIONAL OUT PWSTR pwzShortName);

PVOID __stdcall RtlCreateHeap(ULONG flags, OPTIONAL PVOID pBase, OPTIONAL SIZE_T nReserveSize, OPTIONAL SIZE_T nCommitSize, OPTIONAL PVOID pLock, 
	OPTIONAL PVOID pParams);
PVOID __stdcall RtlAllocateHeap(PVOID pHeap, OPTIONAL ULONG flags, SIZE_T nSize);
BOOL __stdcall RtlFreeHeap(PVOID pHeap, OPTIONAL ULONG flags, PVOID pBlock);
PVOID __stdcall RtlDestroyHeap(PVOID pHeap);
void __stdcall RtlAcquirePebLock(void);
void __stdcall RtlReleasePebLock(void);
void __stdcall CbRtlUnwind(PVOID pTargetFrame, PVOID pTargetIP, PEXCEPTION_RECORD pExceptionRecord, PVOID pReturnValue);

NTSTATUS __stdcall LdrLoadDll(OPTIONAL PWCHAR pwzFullPath, ULONG flags, PUNICODE_STRING pusModuleName, OUT PHANDLE phModule);

#define DbgPrint(f,...) (CbGetDebugPrintFunction()((f),__VA_ARGS__))
DbgPrint_t CbGetDebugPrintFunction(void);

#endif // CB_NTDLL_NO_FUNCS

LPVOID CbGetNTDLLFunction(LPCSTR pcszFuncName);
LPVOID CbGetNTDLLBaseAddress(void);

NTSTATUS CbCreateFileNT(LPCSTR pcszPath, ACCESS_MASK access, ULONG nShareMode, ULONG nCreateDisposition, ULONG options, OUT PHANDLE phFile);
NTSTATUS CbGetSectionName(HANDLE hProcess, LPVOID pMemoryArea, LPSTR pszNameBuf, SIZE_T nBufSize);
NTSTATUS CbGetCurrentDirectoryNT(LPSTR pszBuffer, SIZE_T nBufSize);

typedef enum _enum_CbSeverity {
	CbSeverityNull,
	CbSeverityInfo,
	CbSeverityWarning,
	CbSeverityError
} CbSeverity_t;

// These functions display a message box without loading/calling anything other than NTDLL
// Note: CbDisplayMessageA will allocate/free memory

NTSTATUS CbDisplayMessageUni(PUNICODE_STRING pusTitle, PUNICODE_STRING pusMessage, CbSeverity_t sev);
NTSTATUS CbDisplayMessageA(LPCSTR pcszTitle, LPCSTR pcszMessage, CbSeverity_t sev);
NTSTATUS CbDisplayMessageW(LPCWSTR pcwzTitle, LPCWSTR pcwzMessage, CbSeverity_t sev);
NTSTATUS CbDisplayError(DWORD nErrorCode, PEXCEPTION_POINTERS pex, LPCSTR pcszContext);

// set this before calling NTDLL funcs to force a specific address
// useful if running in an environment where the loaded modules list is uninitialized
extern LPVOID CbNTDLLBaseAddress;

// ntdll-only thread-safe heap functions
PVOID CbHeapAllocate(SIZE_T nBytes, BOOL bZeroInit);
void CbHeapFree(PVOID pBlock);

#endif
