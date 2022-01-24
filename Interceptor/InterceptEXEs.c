#include "InterceptEXEs.h"
#include <HookFunction.h>
#include <NTDLL.h>
#include <PartialStdio.h>

// executable minimum subsystem version to report to CreateProcess
#define WAYS_INTERCEPTED_SUBSYSTEM_VER_MAJOR 5
#define WAYS_INTERCEPTED_SUBSYSTEM_VER_MINOR 0

static NTSTATUS __stdcall s_InterceptedQuerySection(HANDLE hSection, SECTION_INFORMATION_CLASS iclass, PVOID pInfoBuffer,
	ULONG nBufSize, PULONG pnResultSize);

static NtQuerySection_t s_procRealQuerySection;

BOOL ApplyProcessCreationHooks(void) {
	NtQuerySection_t procNtQuerySection;

	procNtQuerySection = CbGetNTDLLFunction("NtQuerySection");
	if (procNtQuerySection == NULL) {
		dprintf("[ApplyProcessCreationHooks] NtQuerySection not found in NTDLL (error 0x%08X)\r\n", CbLastWinAPIError);
		return FALSE;
	}

	s_procRealQuerySection = PaHookSimpleFunction(procNtQuerySection, 16, s_InterceptedQuerySection);
	if (s_procRealQuerySection == NULL) {
		dprintf("[ApplyProcessCreationHooks] Error 0x%08X hooking NtQuerySection\r\n", CbLastWinAPIError);
		return FALSE;
	}

	return TRUE;
}

static NTSTATUS __stdcall s_InterceptedQuerySection(HANDLE hSection, SECTION_INFORMATION_CLASS iclass, PVOID pInfoBuffer,
	ULONG nBufSize, PULONG pnResultSize)
{
	NTSTATUS status;
	PSECTION_IMAGE_INFORMATION pinfSection;

	status = s_procRealQuerySection(hSection, iclass, pInfoBuffer, nBufSize, pnResultSize);
	if (status != 0) {
		dprintf("[InterceptedQuerySection] NtQuerySection returned 0x%08X\r\n", status);
		return status;
	}

	if (iclass == SectionImageInformation) {
		pinfSection = (PSECTION_IMAGE_INFORMATION)pInfoBuffer;

		dprintf("[InterceptedQuerySection] Subsystem version %u.%u -> %u.%u\r\n", pinfSection->SubSystemMajorVersion,
			pinfSection->SubSystemMinorVersion, WAYS_INTERCEPTED_SUBSYSTEM_VER_MAJOR, WAYS_INTERCEPTED_SUBSYSTEM_VER_MINOR);

		pinfSection->SubSystemMajorVersion = WAYS_INTERCEPTED_SUBSYSTEM_VER_MAJOR;
		pinfSection->SubSystemMinorVersion = WAYS_INTERCEPTED_SUBSYSTEM_VER_MINOR;
	}

	return 0;
}
