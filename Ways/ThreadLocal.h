#pragma once

#ifndef HEADER_THREADLOCAL
#define HEADER_THREADLOCAL

#include "Exported/WaysTLS.h"

BOOL TLSInitProcess(void);
BOOL TLSInitThread(void);
BOOL TLSUninitThread(void);
BOOL TLSUninitProcess(void);

#endif
