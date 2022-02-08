//
// except.c
//
// MSVCRT exception handling
//
// Copyright (C) 2022 Azimecha
// Copyright (C) 2002 Michael Ringgaard. All rights reserved.
// Copyright (C) 2000 Jon Griffiths
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.  
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.  
// 3. Neither the name of the project nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
// SUCH DAMAGE.
// 

#include <stdint.h>

typedef unsigned int DWORD;
typedef unsigned char BYTE;
typedef unsigned long ULONG;
typedef int LONG;
typedef uintptr_t UINT_PTR;
typedef uintptr_t* PUINT_PTR;
typedef unsigned short WORD;
typedef uintptr_t DWORD_PTR;

#define CONTEXT_i386    0x00010000
#define CONTEXT_i486    0x00010000

#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L)
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L)
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

#define MAXIMUM_SUPPORTED_EXTENSION     512

#define SIZE_OF_80387_REGISTERS      80

typedef struct _FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
	DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef FLOATING_SAVE_AREA* PFLOATING_SAVE_AREA;

typedef struct _CONTEXT {
	DWORD ContextFlags;

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	FLOATING_SAVE_AREA FloatSave;

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;
	DWORD   EFlags;
	DWORD   Esp;
	DWORD   SegSs;

	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;

typedef CONTEXT* PCONTEXT;
typedef CONTEXT* LPCONTEXT;

#define STATUS_NONCONTINUABLE_EXCEPTION     0xC0000025
#define STATUS_INVALID_DISPOSITION          0xC0000026
#define STATUS_UNWIND                       0xC0000027
#define STATUS_BAD_STACK                    0xC0000028
#define STATUS_INVALID_UNWIND_TARGET        0xC0000029

#define STATUS_GUARD_PAGE_VIOLATION         0x80000001
#define EXCEPTION_DATATYPE_MISALIGNMENT     0x80000002
#define EXCEPTION_ACCESS_VIOLATION          0xC0000005
#define EXCEPTION_ILLEGAL_INSTRUCTION       0xC000001D
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     0xC000008C
#define EXCEPTION_INT_DIVIDE_BY_ZERO        0xC0000094
#define EXCEPTION_INT_OVERFLOW              0xC0000095
#define EXCEPTION_STACK_OVERFLOW            0xC00000FD

#define EXCEPTION_EXECUTE_HANDLER           1
#define EXCEPTION_CONTINUE_SEARCH           0
#define EXCEPTION_CONTINUE_EXECUTION        -1

#define EH_NONCONTINUABLE   0x01
#define EH_UNWINDING        0x02
#define EH_EXIT_UNWIND      0x04
#define EH_STACK_INVALID    0x08
#define EH_NESTED_CALL      0x10

#define EXCEPTION_CONTINUABLE        0
#define EXCEPTION_NONCONTINUABLE     EH_NONCONTINUABLE

#define EXCEPTION_MAXIMUM_PARAMETERS 15

typedef void* PVOID;

typedef struct _EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	struct _EXCEPTION_RECORD* ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG* ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, * PEXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

typedef LONG(__stdcall* PTOP_LEVEL_EXCEPTION_FILTER)(PEXCEPTION_POINTERS ExceptionInfo);
typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef enum _EXCEPTION_DISPOSITION {
	ExceptionContinueExecution,
	ExceptionContinueSearch,
	ExceptionNestedException,
	ExceptionCollidedUnwind
} EXCEPTION_DISPOSITION;

struct _EXCEPTION_FRAME;

typedef EXCEPTION_DISPOSITION(*PEXCEPTION_HANDLER)(
	struct _EXCEPTION_RECORD* ExceptionRecord,
	struct _EXCEPTION_FRAME* EstablisherFrame,
	struct _CONTEXT* ContextRecord,
	struct _EXCEPTION_FRAME** DispatcherContext);

typedef struct _EXCEPTION_FRAME {
	struct _EXCEPTION_FRAME* prev;
	PEXCEPTION_HANDLER handler;
} EXCEPTION_FRAME, * PEXCEPTION_FRAME;

typedef struct _NESTED_FRAME {
	EXCEPTION_FRAME frame;
	EXCEPTION_FRAME* prev;
} NESTED_FRAME;

typedef struct _SCOPETABLE {
	int previousTryLevel;
	int (*lpfnFilter)(PEXCEPTION_POINTERS);
	int (*lpfnHandler)(void);
} SCOPETABLE, * PSCOPETABLE;

typedef struct _MSVCRT_EXCEPTION_FRAME {
	EXCEPTION_FRAME* prev;
	void (*handler)(PEXCEPTION_RECORD, PEXCEPTION_FRAME, PCONTEXT, PEXCEPTION_RECORD);
	PSCOPETABLE scopetable;
	int trylevel;
	int _ebp;
	PEXCEPTION_POINTERS xpointers;
} MSVCRT_EXCEPTION_FRAME;

#define TRYLEVEL_END (-1) // End of trylevel list

#pragma warning(disable: 4731) // C4731: frame pointer register 'ebp' modified by inline assembly code

static void call_finally_block(void* code_block, void* base_ptr) {
	__asm {
		mov eax, [code_block]
		mov ebp, [base_ptr]
		call eax
	}
}

static DWORD call_filter(void* func, void* arg, void* base_ptr) {
	DWORD rc;

	__asm {
		push ebp
		push[arg]
		mov eax, [func]
		mov ebp, [base_ptr]
		call eax
		pop ebp
		pop ebp
		mov[rc], eax
	}

	return rc;
}

static EXCEPTION_DISPOSITION msvcrt_nested_handler(EXCEPTION_RECORD* rec, EXCEPTION_FRAME* frame, CONTEXT* ctxt, EXCEPTION_FRAME** dispatcher) {
	if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) return ExceptionContinueSearch;
	*dispatcher = frame;
	return ExceptionCollidedUnwind;
}

extern void __stdcall CbRtlUnwind(PVOID a, PVOID b, PEXCEPTION_RECORD c, PVOID d);

void _global_unwind2(PEXCEPTION_FRAME frame) {
	CbRtlUnwind(frame, 0, 0, 0);
}

void _local_unwind2(MSVCRT_EXCEPTION_FRAME* frame, int trylevel) {
	MSVCRT_EXCEPTION_FRAME* curframe = frame;
	//EXCEPTION_FRAME reg;

	//syslog(LOG_DEBUG, "_local_unwind2(%p,%d,%d)",frame, frame->trylevel, trylevel);

	// Register a handler in case of a nested exception
	//reg.handler = (PEXCEPTION_HANDLER) msvcrt_nested_handler;
	//reg.prev = (PEXCEPTION_FRAME) gettib()->except;
	//push_frame(&reg);

	while (frame->trylevel != TRYLEVEL_END && frame->trylevel != trylevel) {
		int curtrylevel = frame->scopetable[frame->trylevel].previousTryLevel;
		curframe = frame;
		curframe->trylevel = curtrylevel;
		if (!frame->scopetable[curtrylevel].lpfnFilter) {
			//syslog(LOG_WARNING, "warning: __try block cleanup not implemented - expect crash!");
			// TODO: Remove current frame, set ebp, call frame->scopetable[curtrylevel].lpfnHandler()
		}
	}
	//pop_frame(&reg);
}

int _except_handler3(PEXCEPTION_RECORD rec, MSVCRT_EXCEPTION_FRAME* frame, PCONTEXT context, void* dispatcher) {
	long retval;
	int trylevel;
	EXCEPTION_POINTERS exceptPtrs;
	PSCOPETABLE pScopeTable;

	//syslog(LOG_DEBUG, "msvcrt: exception %lx flags=%lx at %p handler=%p %p %p semi-stub",
	//       rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
	//       frame->handler, context, dispatcher);

	__asm cld;

	if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) {
		// Unwinding the current frame
		_local_unwind2(frame, TRYLEVEL_END);
		return ExceptionContinueSearch;
	}
	else {
		// Hunting for handler
		exceptPtrs.ExceptionRecord = rec;
		exceptPtrs.ContextRecord = context;
		*((DWORD*)frame - 1) = (DWORD)&exceptPtrs;
		trylevel = frame->trylevel;
		pScopeTable = frame->scopetable;

		while (trylevel != TRYLEVEL_END) {
			if (pScopeTable[trylevel].lpfnFilter) {
				//syslog(LOG_DEBUG, "filter = %p", pScopeTable[trylevel].lpfnFilter);

				retval = call_filter(pScopeTable[trylevel].lpfnFilter, &exceptPtrs, &frame->_ebp);

				//syslog(LOG_DEBUG, "filter returned %s", retval == EXCEPTION_CONTINUE_EXECUTION ?
				//      "CONTINUE_EXECUTION" : retval == EXCEPTION_EXECUTE_HANDLER ?
				//      "EXECUTE_HANDLER" : "CONTINUE_SEARCH");

				if (retval == EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;

				if (retval == EXCEPTION_EXECUTE_HANDLER) {
					// Unwind all higher frames, this one will handle the exception
					_global_unwind2((PEXCEPTION_FRAME)frame);
					_local_unwind2(frame, trylevel);

					// Set our trylevel to the enclosing block, and call the __finally code, which won't return
					frame->trylevel = pScopeTable->previousTryLevel;
					//syslog(LOG_DEBUG, "__finally block %p",pScopeTable[trylevel].lpfnHandler);
					call_finally_block(pScopeTable[trylevel].lpfnHandler, &frame->_ebp);
					//DbgPrint("Returned from __finally block");
				}
			}
			trylevel = pScopeTable->previousTryLevel;
		}
	}

	return ExceptionContinueSearch;
}

UINT_PTR __security_cookie = 0xBB40E64E;

extern PVOID __safe_se_handler_table[];
extern BYTE  __safe_se_handler_count;

typedef struct {
	DWORD       Size;
	DWORD       TimeDateStamp;
	WORD        MajorVersion;
	WORD        MinorVersion;
	DWORD       GlobalFlagsClear;
	DWORD       GlobalFlagsSet;
	DWORD       CriticalSectionDefaultTimeout;
	DWORD       DeCommitFreeBlockThreshold;
	DWORD       DeCommitTotalFreeThreshold;
	DWORD       LockPrefixTable;
	DWORD       MaximumAllocationSize;
	DWORD       VirtualMemoryThreshold;
	DWORD       ProcessHeapFlags;
	DWORD       ProcessAffinityMask;
	WORD        CSDVersion;
	WORD        Reserved1;
	DWORD       EditList;
	PUINT_PTR   SecurityCookie;
	PVOID* SEHandlerTable;
	DWORD       SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32_2;

const
IMAGE_LOAD_CONFIG_DIRECTORY32_2 _load_config_used = {
	sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32_2),
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	&__security_cookie,
	__safe_se_handler_table,
	(DWORD)(DWORD_PTR)&__safe_se_handler_count
};
