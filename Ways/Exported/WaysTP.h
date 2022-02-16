#pragma once

#ifndef HEADER_WAYSTP
#define HEADER_WAYSTP

#include "WaysDef.h"

HANDLE MAGICWAYS_EXPORTED MwGetPoolThread(void);
void MAGICWAYS_EXPORTED MwReturnPoolThread(HANDLE hThread);

DWORD MAGICWAYS_EXPORTED MwAPCProcessingThreadProc(PVOID pParams);

#endif
