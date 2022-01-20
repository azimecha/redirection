#pragma once

#ifndef HEADER_COMMANDLINETOARGV
#define HEADER_COMMANDLINETOARGV

#define _X86_
#include <windef.h>

// this function just returns a pointer to the rest of the line without munging it
// pass 0 as the escape character to disable escape character processing
LPCSTR CbGetNextArgument(LPCSTR pcszCommandLine, char cEscape);

// these functions actually process all the args

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
