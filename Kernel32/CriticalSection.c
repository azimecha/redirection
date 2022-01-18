//#define WIN32_LEAN_AND_MEAN
//#include <Windows.h>

extern int __stdcall InitializeCriticalSectionAndSpinCount(void*, unsigned);

int __stdcall Impl_InitializeCriticalSectionEx(void* pCS, unsigned nSpinCt, unsigned flags) {
	return InitializeCriticalSectionAndSpinCount(pCS, nSpinCt);
}
