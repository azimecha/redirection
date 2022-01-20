#define _X86_
#include <windef.h>
#include <ImportHelper.h>

CB_UNDECORATED_EXTERN(void, ExitProcess, unsigned nExitCode);

__declspec(dllimport) extern int __stdcall MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
#define MB_ICONEXCLAMATION 0x30

void __stdcall TestExitProcess(unsigned nExitCode) {
	MessageBoxA(NULL, "I loved a DLL with magic ways...", "\"Critical alert from Microsoft\"", MB_ICONEXCLAMATION);
	CB_UNDECORATED_CALL(ExitProcess, nExitCode);
}
