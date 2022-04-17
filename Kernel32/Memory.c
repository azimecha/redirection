#include <WaysTLS.h>
#include <ImportHelper.h>
#include <NTDLL.h>

#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <minwinbase.h>

CB_UNDECORATED_EXTERN(LPVOID, VirtualAllocEx, HANDLE hProcess, LPVOID pAddress, SIZE_T nSize, DWORD nAllocType, DWORD nProtType);

LPVOID __stdcall Impl_VirtualAllocExNuma(HANDLE hProcess, LPVOID pAddress, SIZE_T nSize, DWORD nAllocType, DWORD nProtType, DWORD nNumaNode) {
	return CB_UNDECORATED_CALL(VirtualAllocEx, hProcess, pAddress, nSize, nAllocType, nProtType);
}
