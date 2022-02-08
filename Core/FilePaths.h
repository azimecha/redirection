#pragma once

#ifndef HEADER_FILEPATHS
#define HEADER_FILEPATHS

void CbPathRemoveExtensionA(char* pcszPath);
const char* CbPathGetFilenameA(const char* pcszPath);
const char* CbStringSeekEndA(const char* pcszString);
void CbStringToLowerA(char* pcszString);
int CbStringStartsWithA(const char* pcszCheck, const char* pcszCheckFor);
int CbStringStartsWithIA(const char* pcszCheck, const char* pcszCheckFor);
int CbTryAppendToBufferA(char** ppszBuffer, unsigned int* pnSize, const char* pcszToAppend);

static inline int tolower(int c) { return ((c >= 'A') && (c <= 'Z')) ? (c - 'A' + 'a') : c; }
static inline int toupper(int c) { return ((c >= 'a') && (c <= 'z')) ? (c - 'a' + 'A') : c; }

#endif
