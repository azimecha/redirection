#pragma once

#ifndef HEADER_PARTIALSTDIO
#define HEADER_PARTIALSTDIO

// Additional functions not present in the default stdio.h
#include <stdarg.h>

// Print to debugger
void dprintf(const char* pcszFormat, ...);
void vdprintf(const char* pcszFormat, va_list va);

static inline int tolower(int c) { return ((c >= 'A') && (c <= 'Z')) ? (c - 'A' + 'a') : c; }
static inline int toupper(int c) { return ((c >= 'a') && (c <= 'z')) ? (c - 'a' + 'A') : c; }

int stricmp(const char* a, const char* b);

#endif
