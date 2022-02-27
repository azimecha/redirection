#include "CommandLineToArgv.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

LPCSTR CbGetNextArgument(LPCSTR pcszCommandLine, char cEscape) {
    BOOL bInQuotes = FALSE;

    // skip any leading spaces
    while (*pcszCommandLine == ' ')
        pcszCommandLine++;

    // go until we find an unquoted space
    while (*pcszCommandLine) {
        switch (*pcszCommandLine) {
        case ' ':
            if (!bInQuotes) {
                // skip additional spaces
                while (*pcszCommandLine == ' ')
                    pcszCommandLine++;
                return pcszCommandLine;
            }
            break;

        case '"':
            bInQuotes = !bInQuotes;

        default:
            if ((*pcszCommandLine == cEscape) && (pcszCommandLine[1] != 0))
                pcszCommandLine++; // skip escaped char
            break;
        }

        pcszCommandLine++;
    }

    // nothing. return empty string
    return pcszCommandLine;
}

// http://alter.org.ua/en/docs/win/args/

PWCHAR*
CommandLineToArgvW(
    PWCHAR CmdLine,
    int* _argc
)
{
    PWCHAR* argv;
    PWCHAR  _argv;
    ULONG   len;
    ULONG   argc;
    WCHAR   a;
    ULONG   i, j;

    BOOLEAN  in_QM;
    BOOLEAN  in_TEXT;
    BOOLEAN  in_SPACE;

    len = lstrlenW(CmdLine);
    i = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

    argv = (PWCHAR*)GlobalAlloc(GMEM_FIXED,
        i + (len + 2) * sizeof(WCHAR));
    if (argv == NULL)
        return NULL;

    _argv = (PWCHAR)(((PUCHAR)argv) + i);

    argc = 0;
    argv[argc] = _argv;
    in_QM = FALSE;
    in_TEXT = FALSE;
    in_SPACE = TRUE;
    i = 0;
    j = 0;

    while (a = CmdLine[i]) {
        if (in_QM) {
            if (a == '\"') {
                in_QM = FALSE;
            }
            else {
                _argv[j] = a;
                j++;
            }
        }
        else {
            switch (a) {
            case '\"':
                in_QM = TRUE;
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                in_SPACE = FALSE;
                break;
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                if (in_TEXT) {
                    _argv[j] = '\0';
                    j++;
                }
                in_TEXT = FALSE;
                in_SPACE = TRUE;
                break;
            default:
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                _argv[j] = a;
                j++;
                in_SPACE = FALSE;
                break;
            }
        }
        i++;
    }
    _argv[j] = '\0';
    argv[argc] = NULL;

    (*_argc) = argc;
    return argv;
}

PCHAR*
CommandLineToArgvA(
    PCHAR CmdLine,
    int* _argc
)
{
    PCHAR* argv;
    PCHAR  _argv;
    ULONG   len;
    ULONG   argc;
    CHAR   a;
    ULONG   i, j;

    BOOLEAN  in_QM;
    BOOLEAN  in_TEXT;
    BOOLEAN  in_SPACE;

    len = strlen(CmdLine);
    i = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

    argv = (PCHAR*)GlobalAlloc(GMEM_FIXED,
        i + (len + 2) * sizeof(CHAR));

    _argv = (PCHAR)(((PUCHAR)argv) + i);

    argc = 0;
    argv[argc] = _argv;
    in_QM = FALSE;
    in_TEXT = FALSE;
    in_SPACE = TRUE;
    i = 0;
    j = 0;

    while (a = CmdLine[i]) {
        if (in_QM) {
            if (a == '\"') {
                in_QM = FALSE;
            }
            else {
                _argv[j] = a;
                j++;
            }
        }
        else {
            switch (a) {
            case '\"':
                in_QM = TRUE;
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                in_SPACE = FALSE;
                break;
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                if (in_TEXT) {
                    _argv[j] = '\0';
                    j++;
                }
                in_TEXT = FALSE;
                in_SPACE = TRUE;
                break;
            default:
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                _argv[j] = a;
                j++;
                in_SPACE = FALSE;
                break;
            }
        }
        i++;
    }
    _argv[j] = '\0';
    argv[argc] = NULL;

    (*_argc) = argc;
    return argv;
}
