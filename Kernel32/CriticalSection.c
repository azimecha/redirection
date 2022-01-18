//#define WIN32_LEAN_AND_MEAN
//#include <Windows.h>
#include <ImportHelper.h>

CB_UNDECORATED_EXTERN(int, InitializeCriticalSectionAndSpinCount, void* pCS, unsigned nSpinCt);

int __stdcall Impl_InitializeCriticalSectionEx(void* pCS, unsigned nSpinCt, unsigned flags) {
	return CB_UNDECORATED_CALL(InitializeCriticalSectionAndSpinCount, pCS, nSpinCt);
}
