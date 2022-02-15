#pragma once

#ifndef HEADER_INTERCEPTWAITS
#define HEADER_INTERCEPTWAITS

#define _X86_
#include <minwindef.h>

BOOL ApplyWaitHooks(void);
DWORD DisableIOInterception(DWORD nThreadID);

#endif
