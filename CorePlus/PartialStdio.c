#include "PartialStdio.h"
#include "NTDLL.h"
#include "ImportHelper.h"
#include <stb_sprintf.h>

#include <stdio.h>
#include <limits.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int fclose(FILE* pf) {
	return !CloseHandle((HANDLE)pf);
}

int fgetc(FILE* pf) {
	char c;
	DWORD nRead = 0;

	if (!ReadFile((HANDLE)pf, &c, 1, &nRead, NULL))
		return EOF;

	return (int)c;
}

int fgetpos(FILE* pf, fpos_t* pnPos) {
	LARGE_INTEGER liNullMove, liCurPos;

	RtlSecureZeroMemory(&liNullMove, sizeof(liNullMove));

	if (!SetFilePointerEx((HANDLE)pf, liNullMove, &liCurPos, FILE_CURRENT))
		return EOF;

	*pnPos = liCurPos.QuadPart;
	return 0;
}

char* fgets(char* pszOut, int nMax, FILE* pf) {
	BOOL bReadOne = FALSE;
	char* pszOutCur;
	int nVal;

	pszOutCur = pszOut;
	while (nMax > 1) {
		nVal = fgetc(pf);
		if (nVal < 0) return bReadOne ? pszOut : NULL;

		*pszOutCur = (char)nVal;
		pszOutCur++;
		nMax--;

		switch (pszOutCur[-1]) {
		case '\r':
		case '\n':
			goto done;
		}
	}

done:
	*pszOutCur = 0;
	return pszOut;
}

FILE* fopen(const char* pcszFilename, const char* pcszMode) {
	DWORD nAccess = 0, nCreationDispo = 0;
	BOOL bAppend = FALSE;
	HANDLE hFile;

	switch (pcszMode[0]) {
	case 'r':
		nAccess = FILE_READ_DATA;
		nCreationDispo = OPEN_EXISTING;
		break;

	case 'w':
		nAccess = FILE_WRITE_DATA;
		nCreationDispo = CREATE_ALWAYS;
		break;

	case 'a':
		nAccess = FILE_WRITE_DATA;
		nCreationDispo = OPEN_ALWAYS;
		bAppend = TRUE;
		break;

	case '\0':
		return NULL;
	}

	while (*pcszMode) {
		if (*pcszMode == '+')
			nAccess = FILE_READ_DATA | FILE_WRITE_DATA;
		pcszMode++;
	}

	hFile = CreateFileA(pcszFilename, nAccess, FILE_SHARE_READ, NULL, nCreationDispo, 0, NULL);
	return (hFile == INVALID_HANDLE_VALUE) ? NULL : (FILE*)hFile;
}

typedef struct _FPRINTF_DATA_BAG {
	HANDLE hFile;
	char szBuffer[STB_SPRINTF_MIN];
} FPRINTF_DATA_BAG, *PFPRINTF_DATA_BAG;

static BOOL s_WriteAll(HANDLE hFile, const BYTE* pcData, DWORD nBytes) {
	DWORD nWritten;

	while (nBytes > 0) {
		if (!WriteFile(hFile, pcData, nBytes, &nWritten, NULL))
			return FALSE;

		nBytes -= nWritten;
		pcData += nWritten;
	}

	return TRUE;
}

static char* s_CallbackFPrintF(char const* pcsBuf, PFPRINTF_DATA_BAG pData, int nBufFill) {
	return s_WriteAll(pData->hFile, pcsBuf, nBufFill) ? pData->szBuffer : NULL;
}

int vfprintf(FILE* pf, const char* pcszFormat, va_list va) {
	FPRINTF_DATA_BAG data;
	data.hFile = (HANDLE)pf;
	return vsprintfcb(s_CallbackFPrintF, &data, data.szBuffer, pcszFormat, va);
}

int fprintf(FILE* pf, const char* pcszFormat, ...) {
	va_list va;
	int nRetVal;

	va_start(va, pcszFormat);
	nRetVal = vfprintf(pf, pcszFormat, va);
	va_end(va);

	return nRetVal;
}

int fputc(int nChar, FILE* pf) {
	DWORD nWritten;
	char c;

	c = nChar;
	if (!WriteFile((HANDLE)pf, &c, 1, &nWritten, NULL))
		return EOF;

	return (nWritten == 1) ? nChar : EOF;
}

int fputs(const char* pcszToWrite, FILE* pf) {
	return s_WriteAll((HANDLE)pf, pcszToWrite, strlen(pcszToWrite)) ? 0 : EOF;
}

size_t fread(void* pBuffer, size_t nElemSize, size_t nCount, FILE* pf) {
	BYTE* pBufCur;
	DWORD nRead = 0;
	size_t nElemsRead = 0;

	if ((nElemSize == 0) || (nCount == 0))
		return 0;

	pBufCur = (BYTE*)pBuffer;
	while (nElemsRead < nCount) {
		if (!ReadFile((HANDLE)pf, pBufCur, nElemSize, &nRead, NULL))
			break;

		if (nRead != nElemSize)
			break;

		nElemsRead++;
		pBufCur += nElemSize;
	}

	return nElemsRead;
}

int fseek(FILE* pf, long nOffset, int nOrigin) {
	DWORD nMoveMethod;
	LARGE_INTEGER liOffset;

	switch (nOrigin) {
	case SEEK_SET:
		nMoveMethod = FILE_BEGIN;
		break;

	case SEEK_CUR:
		nMoveMethod = FILE_CURRENT;
		break;

	case SEEK_END:
		nMoveMethod = FILE_END;
		break;

	default:
		return EOF;
	}

	liOffset.QuadPart = nOffset;
	return SetFilePointerEx((HANDLE)pf, liOffset, NULL, nMoveMethod) ? 0 : EOF;
}

int fsetpos(FILE* pf, const fpos_t* pnPos) {
	LARGE_INTEGER liMoveTo;
	liMoveTo.QuadPart = *pnPos;
	return SetFilePointerEx((HANDLE)pf, liMoveTo, NULL, FILE_BEGIN) ? 0 : EOF;
}

long ftell(FILE* pf) {
	fpos_t nPos;
	return fgetpos(pf, &nPos) == 0 ? (long)nPos : -1L;
}

size_t fwrite(const void* pData, size_t nElemSize, size_t nCount, FILE* pf) {
	size_t nElemsWritten = 0;
	const BYTE* pDataCur;

	pDataCur = pData;
	while (nElemsWritten < nCount) {
		if (!s_WriteAll((HANDLE)pf, pDataCur, nElemSize))
			break;

		nElemsWritten++;
		pDataCur += nElemSize;
	}

	return nElemsWritten;
}

int getc(FILE* pf) {
	return fgetc(pf);
}

int getchar(void) {
	return getc(GetStdHandle(STD_INPUT_HANDLE));
}

static void s_Trim(char* pszBuffer, const char* pcszToTrim) {
	char* pszCurPos;

	for (pszCurPos = pszBuffer + strlen(pszBuffer) - 1; pszCurPos >= pszBuffer; pszCurPos--) {
		if (strchr(pcszToTrim, *pszCurPos))
			*pszCurPos = 0;
		else
			break;
	}
}

// Please never use this function
char* gets(char* pszBuffer) {
	if (!fgets(pszBuffer, INT_MAX, (FILE*)GetStdHandle(STD_INPUT_HANDLE)))
		return NULL;

	s_Trim(pszBuffer, "\r\n");
	return pszBuffer;
}

int printf(const char* pcszFormat, ...) {
	va_list va;
	int nRetVal;

	va_start(va, pcszFormat);
	nRetVal = vfprintf((FILE*)GetStdHandle(STD_OUTPUT_HANDLE), pcszFormat, va);
	va_end(va);

	return nRetVal;
}

int putc(int nChar, FILE* pf) {
	return fputc(nChar, pf);
}

int putchar(int nChar) {
	return fputc(nChar, (FILE*)GetStdHandle(STD_OUTPUT_HANDLE));
}

int puts(const char* pcszString) {
	FILE* pfStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	return (fputs(pcszString, pfStdout) != EOF) && (fputs("\r\n", pfStdout) != EOF);
}

void rewind(FILE* pf) {
	fseek(pf, 0, SEEK_SET);
}

int vprintf(const char* pcszFormat, va_list va) {
	return vfprintf((FILE*)GetStdHandle(STD_OUTPUT_HANDLE), pcszFormat, va);
}

static char* s_CallbackDebugPrint(char const* pcsBuf, char* pBufferStart, int nBufFill) {
	char szTempBuf[STB_SPRINTF_MIN + 1];

	memcpy(szTempBuf, pcsBuf, nBufFill);
	szTempBuf[nBufFill] = 0;

	DbgPrint("%s", szTempBuf);

	return pBufferStart;
}

void dprintf(const char* pcszFormat, ...) {
	va_list va;

	va_start(va, pcszFormat);
	vdprintf(pcszFormat, va);
	va_end(va);
}

void vdprintf(const char* pcszFormat, va_list va) {
	char szBuffer[STB_SPRINTF_MIN];
	vsprintfcb(s_CallbackDebugPrint, szBuffer, szBuffer, pcszFormat, va);
}
