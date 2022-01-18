#pragma once

#ifndef HEADER_COMMANDLINETOARGV
#define HEADER_COMMANDLINETOARGV

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

PWCHAR*
CommandLineToArgvW(
    PWCHAR CmdLine,
    int* _argc
);

PCHAR*
CommandLineToArgvA(
    PCHAR CmdLine,
    int* _argc
);

#endif
