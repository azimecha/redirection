#define _X86_
#include <windef.h>
#include <ImportHelper.h>
#include <string.h>

typedef struct _nlsversioninfo {
	DWORD dwNLSVersionInfoSize;
	DWORD dwNLSVersion;
	DWORD dwDefinedVersion;
	DWORD dwEffectiveId;
	GUID  guidCustomVersion;
} NLSVERSIONINFO, *LPNLSVERSIONINFO;

#define LOCALE_NAME_USER_DEFAULT            NULL
#define LOCALE_NAME_INVARIANT               L""
#define LOCALE_NAME_SYSTEM_DEFAULT          L"!x-sys-default-locale"

CB_UNDECORATED_EXTERN(int, LCMapStringW, LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
CB_UNDECORATED_EXTERN(int, lstrcmpiW, LPCWSTR str1, LPCWSTR str2);

int WINAPI Impl_LCMapStringEx(LPCWSTR pcwzLocale, DWORD flags, LPCWSTR pcwzSource, int nSourceChars,
	LPWSTR pwzDest, int nDestChars, LPNLSVERSIONINFO pinfVersion, LPVOID pReserved, LPARAM pSortHandle)
{
	LCID nLocale;

	if (pcwzLocale == LOCALE_NAME_USER_DEFAULT)
		nLocale = LOCALE_USER_DEFAULT;
	else if (!CB_UNDECORATED_CALL(lstrcmpiW, pcwzLocale, LOCALE_NAME_INVARIANT))
		nLocale = LOCALE_INVARIANT;
	else if (!CB_UNDECORATED_CALL(lstrcmpiW, pcwzLocale, LOCALE_NAME_SYSTEM_DEFAULT))
		nLocale = LOCALE_SYSTEM_DEFAULT;
	else 
		nLocale = LOCALE_INVARIANT;

	return CB_UNDECORATED_CALL(LCMapStringW, nLocale, flags, pcwzSource, nSourceChars, pwzDest, nDestChars);
}
