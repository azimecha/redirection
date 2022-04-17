#define _X86_
#include <windef.h>
#include <ImportHelper.h>
#include <string.h>
#include <winerror.h>

typedef struct _nlsversioninfo {
	DWORD dwNLSVersionInfoSize;
	DWORD dwNLSVersion;
	DWORD dwDefinedVersion;
	DWORD dwEffectiveId;
	GUID  guidCustomVersion;
} NLSVERSIONINFO, *LPNLSVERSIONINFO;

typedef DWORD LCTYPE;

#define LOCALE_NAME_USER_DEFAULT            NULL
#define LOCALE_NAME_INVARIANT               L""
#define LOCALE_NAME_SYSTEM_DEFAULT          L"!x-sys-default-locale"
#define K32R_LOCALE_NAME_USER_DEFAULT		L"!x-user-default-locale" // made up - not in windows

CB_UNDECORATED_EXTERN(int, LCMapStringW, LCID nLocale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
CB_UNDECORATED_EXTERN(int, GetLocaleInfoW, LCID nLocale, LCTYPE nType, LPWSTR pwzData, int nDataSize);
CB_UNDECORATED_EXTERN(int, lstrcmpiW, LPCWSTR str1, LPCWSTR str2);

static s_LCIDFromName(LPCWSTR pcwzLocaleName);

static const WCHAR s_cwzExUserDefaultLocaleName[] = K32R_LOCALE_NAME_USER_DEFAULT;

int WINAPI Impl_LCMapStringEx(LPCWSTR pcwzLocale, DWORD flags, LPCWSTR pcwzSource, int nSourceChars,
	LPWSTR pwzDest, int nDestChars, LPNLSVERSIONINFO pinfVersion, LPVOID pReserved, LPARAM pSortHandle)
{
	return CB_UNDECORATED_CALL(LCMapStringW, s_LCIDFromName(pcwzLocale), flags, pcwzSource, nSourceChars, pwzDest, nDestChars);
}

int WINAPI Impl_GetLocaleInfoEx(LPCWSTR pcwzLocaleName, LCTYPE nType, LPWSTR pwzData, int nDataSize) {
	return CB_UNDECORATED_CALL(GetLocaleInfoW, s_LCIDFromName(pcwzLocaleName), nType, pwzData, nDataSize);
}

int WINAPI Impl_GetUserDefaultLocaleName(LPWSTR pwzLocaleName, int nBufSize) {
	if (nBufSize < sizeof(s_cwzExUserDefaultLocaleName)) {
		CbLastWinAPIError = ERROR_INSUFFICIENT_BUFFER;
		return 0;
	}

	memcpy(pwzLocaleName, s_cwzExUserDefaultLocaleName, sizeof(s_cwzExUserDefaultLocaleName));
	return sizeof(s_cwzExUserDefaultLocaleName);
}

static s_LCIDFromName(LPCWSTR pcwzLocaleName) {
	if (pcwzLocaleName == LOCALE_NAME_USER_DEFAULT)
		return LOCALE_USER_DEFAULT;
	else if (!CB_UNDECORATED_CALL(lstrcmpiW, pcwzLocaleName, LOCALE_NAME_INVARIANT))
		return LOCALE_INVARIANT;
	else if (!CB_UNDECORATED_CALL(lstrcmpiW, pcwzLocaleName, LOCALE_NAME_SYSTEM_DEFAULT))
		return LOCALE_SYSTEM_DEFAULT;
	else if (!CB_UNDECORATED_CALL(lstrcmpiW, pcwzLocaleName, s_cwzExUserDefaultLocaleName))
		return LOCALE_USER_DEFAULT;
	else
		return LOCALE_INVARIANT;
}
