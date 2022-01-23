#pragma once

#ifndef HEADER_PARTIALSTDIO
#define HEADER_PARTIALSTDIO

// Additional functions not present in the default stdio.h
#include <stdarg.h>
#include <stdint.h>

// Print to debugger
void dprintf(const char* pcszFormat, ...);
void vdprintf(const char* pcszFormat, va_list va);

static inline int tolower(int c) { return ((c >= 'A') && (c <= 'Z')) ? (c - 'A' + 'a') : c; }
static inline int toupper(int c) { return ((c >= 'a') && (c <= 'z')) ? (c - 'a' + 'A') : c; }

// Case insensitive comparison
int stricmp(const char* a, const char* b);

// strcat that actually works how you'd expect: using a maximum total size
// returns 1 if it was able to concat the whole thing, 0 otherwise
int strccat(char* pszDest, size_t nDestBufSize, const char* pcszSrc);

#endif
