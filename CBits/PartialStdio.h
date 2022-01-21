#pragma once

#ifndef HEADER_PARTIALSTDIO
#define HEADER_PARTIALSTDIO

// Additional functions not present in the default stdio.h
#include <stdarg.h>

// Print to debugger
void dprintf(const char* pcszFormat, ...);
void vdprintf(const char* pcszFormat, va_list va);

#endif
