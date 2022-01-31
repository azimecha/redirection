#pragma once

#ifndef HEADER_HOOKFUNCTION
#define HEADER_HOOKFUNCTION

#define _X86_
#include <minwindef.h>

#define PA_HOOK_INSTR_CALL 0xE8
#define PA_HOOK_INSTR_JMP 0xE9
#define PA_HOOK_INSTR_PUSH 0x68
#define PA_HOOK_INSTR_RET 0xC3

#pragma pack(1)
typedef struct _struct_PaHookCode {
	BYTE instrPush;
	LPVOID pJumpAddr;
	BYTE instrRet;
} PaHookCode_t, * PaHookCode_p;
#pragma pack()

#define PA_REPLACEFUNC_CODESIZE sizeof(PaHookCode_t)

#include "RewriteImports.h"

// returns new location of original code
// only works for VERY simple functions (no jumps)
LPVOID PaHookSimpleFunction(LPVOID pFunction, SIZE_T nSize, LPVOID pHook);

// jumps straight to new func
BOOL PaReplaceFunction(LPVOID pFunction, LPVOID pNewFunction);
BOOL PaReplaceFunctionEx(HANDLE hProcess, EXTERNAL_PTR pFunction, EXTERNAL_PTR pNewFunction, OUT OPTIONAL LPVOID pRemovedCodeBuf);

#endif // !HEADER_HOOKFUNCTION
