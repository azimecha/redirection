#if 0
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int WINAPI Impl_LCMapStringEx(LPCWSTR pcwzLocale, DWORD flags, LPCWSTR pcwzSource, int nSourceChars,
	LPWSTR pwzDest, int nDestChars, LPNLSVERSIONINFO pinfVersion, LPVOID pReserved, LPARAM pSortHandle)
{
	LCID nLocale;

	if (pcwzLocale == LOCALE_NAME_USER_DEFAULT)
		nLocale = LOCALE_USER_DEFAULT;
	else if (!lstrcmpiW(pcwzLocale, LOCALE_NAME_INVARIANT))
		nLocale = LOCALE_INVARIANT;
	else if (!lstrcmpiW(pcwzLocale, LOCALE_NAME_SYSTEM_DEFAULT))
		nLocale = LOCALE_SYSTEM_DEFAULT;
	else {
		OutputDebugStringA("Unknown locale, using invariant\r\n");
		nLocale = LOCALE_INVARIANT;
	}

	return LCMapStringW(nLocale, flags, pcwzSource, nSourceChars, pwzDest, nDestChars);
}
#endif