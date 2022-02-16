#pragma once

#ifndef HEADER_WAYSIO
#define HEADER_WAYSIO

#include "WaysDef.h"

DWORD MAGICWAYS_EXPORTED MwCancelHandleIO(HANDLE hObject);
DWORD MAGICWAYS_EXPORTED MwCancelIORequest(PVOID pIOStatusBlock);
DWORD MAGICWAYS_EXPORTED MwCancelThreadIO(HANDLE hThread, BOOL bSyncOnly);

#endif
