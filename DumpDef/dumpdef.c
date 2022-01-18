#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Vfw.h> // fourcc
#include <stdio.h>
#include <CommandLineToArgv.h>

static const char s_cszUsage[] = "Usage: dumpdef <i|r> file.dll out.def\r\n"
"\ti\tgenerate def for export library\r\n"
"\tr\tgenerate def for redirection dll\r\n"
"Note: May crash on bad DLLs, do not use against malware";

void ENTRY_POINT(void) {
	int argc; char** argv;
	char cOption;
	LPCSTR pcszDLLFile, pcszDEFFile, pcszDLLExpName, pcszExpName;
	HMODULE hDLLFile;
	FILE* pfDEFFile;
	BOOL bGenRedir;
	PBYTE pBaseAddress;
	PIMAGE_DOS_HEADER phdrDOS;
	PIMAGE_NT_HEADERS phdrNT;
	PIMAGE_EXPORT_DIRECTORY pdirExports;
	LPCSTR* ppcszNamesPerOrdinal;
	LPDWORD pnNameRVAs;
	LPWORD pnNameOrdinals;
	DWORD nName, nOrdinal;

	argv = CommandLineToArgvA(GetCommandLineA(), &argc);

	if (argc < 3) {
		puts(s_cszUsage);
		ExitProcess(1);
	}

	cOption = argv[1][0];
	pcszDLLFile = argv[2];
	pcszDEFFile = argv[3];

	switch (cOption) {
	case 'i':
	case 'I':
		bGenRedir = FALSE;
		break;

	case 'r':
	case 'R':
		bGenRedir = TRUE;
		break;

	default:
		printf("Invalid option %c\r\n", cOption);
		puts(s_cszUsage);
		ExitProcess(1);
	}

	hDLLFile = LoadLibraryExA(pcszDLLFile, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
	if (hDLLFile == NULL) {
		printf("Error 0x%08X opening %s\r\n", GetLastError(), pcszDLLFile);
		ExitProcess(1);
	}

	pBaseAddress = (PBYTE)hDLLFile - 2;
	phdrDOS = (PIMAGE_DOS_HEADER)pBaseAddress;
	if (phdrDOS->e_magic != MAKEWORD('M', 'Z')) {
		printf("Invalid DOS header magic 0x%02X\r\n", phdrDOS->e_magic);
		ExitProcess(1);
	}

	phdrNT = (PIMAGE_NT_HEADERS)(pBaseAddress + phdrDOS->e_lfanew);
	if (phdrNT->Signature != mmioFOURCC('P', 'E', 0, 0)) {
		printf("Invalid PE signature 0x%08X\r\n", phdrNT->Signature);
		ExitProcess(1);
	}

	printf("Note: %u directory entries\r\n", phdrNT->OptionalHeader.NumberOfRvaAndSizes);

	// note: export table is entry 0
	if (phdrNT->OptionalHeader.NumberOfRvaAndSizes == 0) {
		puts("DLL has no export directory!");
		ExitProcess(1);
	}

	if (phdrNT->OptionalHeader.DataDirectory[0].Size < sizeof(*pdirExports)) {
		printf("Export directory size %u is less than minimum size %u\r\n", phdrNT->OptionalHeader.DataDirectory[0].Size, sizeof(*pdirExports));
		ExitProcess(1);
	}

	pdirExports = (PIMAGE_EXPORT_DIRECTORY)(pBaseAddress + phdrNT->OptionalHeader.DataDirectory[0].VirtualAddress);
	pcszDLLExpName = (LPCSTR)(pBaseAddress + pdirExports->Name);
	pnNameRVAs = (LPDWORD)(pBaseAddress + pdirExports->AddressOfNames);
	pnNameOrdinals = (LPDWORD)(pBaseAddress + pdirExports->AddressOfNameOrdinals);
	printf("Note: Export name is %s\r\n", pcszDLLExpName);
	printf("Note: %u exported symbols (%u named)\r\n", pdirExports->NumberOfFunctions, pdirExports->NumberOfNames);

	ppcszNamesPerOrdinal = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pdirExports->NumberOfFunctions * sizeof(LPCSTR));
	if (ppcszNamesPerOrdinal == NULL) {
		printf("Error 0x%08X allocating memory for name table\r\n", GetLastError());
		ExitProcess(1);
	}

	for (nName = 0; nName < pdirExports->NumberOfNames; nName++) {
		pcszExpName = (LPCSTR)(pBaseAddress + pnNameRVAs[nName]);
		ppcszNamesPerOrdinal[pnNameOrdinals[nName]] = pcszExpName;
	}

	puts(" ---- Export table ---- ");
	for (nOrdinal = 0; nOrdinal < pdirExports->NumberOfFunctions; nOrdinal++)
		printf("%10u  %s\r\n", nOrdinal, ppcszNamesPerOrdinal[nOrdinal] ? ppcszNamesPerOrdinal[nOrdinal] : "");
	puts(" ---- End of export table ---- ");

	ExitProcess(0);
}
