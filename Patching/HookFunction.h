#pragma once

#ifndef HEADER_HOOKFUNCTION
#define HEADER_HOOKFUNCTION

#define _X86_
#include <minwindef.h>

// returns new location of original code
// only works for VERY simple functions (no jumps)
LPVOID PaHookSimpleFunction(LPVOID pFunction, SIZE_T nSize, LPVOID pHook);

// jumps straight to new func
BOOL PaReplaceFunction(LPVOID pFunction, LPVOID pNewFunction);

#endif // !HEADER_HOOKFUNCTION
