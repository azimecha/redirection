#pragma once

#ifndef HEADER_INTERCEPTIO
#define HEADER_INTERCEPTIO

#include "Exported/WaysIO.h"

BOOL ApplyIOHooks(void);
DWORD DisableIOInterception(DWORD nThreadID);

#endif
