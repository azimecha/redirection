#include <ImportHelper.h>

#if 0
#define KEY_ALL_ACCESS 0xF003F
#define KEY_CREATE_LINK 0x0020
#define KEY_CREATE_SUB_KEY 0x0004
#define KEY_ENUMERATE_SUB_KEYS 0x0008
#define KEY_EXECUTE 0x20019
#define KEY_NOTIFY 0x0010
#define KEY_QUERY_VALUE 0x0001
#define KEY_READ 0x20019
#define KEY_SET_VALUE 0x0002
#define KEY_WOW64_32KEY 0x0200
#define KEY_WOW64_64KEY 0x0100
#define KEY_WRITE 0x20006
#endif

#define ERROR_MORE_DATA 234

typedef DWORD REGSAM;
typedef DWORD LSTATUS;

CB_UNDECORATED_EXTERN(LSTATUS, RegOpenKeyExA, HKEY hKey, LPCSTR pcszSubkey, DWORD opts, REGSAM samDesired, PHKEY phResultKey);
CB_UNDECORATED_EXTERN(LSTATUS, RegOpenKeyExW, HKEY hKey, LPCWSTR pcwzSubkey, DWORD opts, REGSAM samDesired, PHKEY phResultKey);

CB_UNDECORATED_EXTERN(LSTATUS, RegQueryValueExA, HKEY hKey, LPCSTR pcszValueName, LPDWORD pnReserved, LPDWORD pnType,
	LPBYTE pData, LPDWORD pnDataSize);
CB_UNDECORATED_EXTERN(LSTATUS, RegQueryValueExW, HKEY hKey, LPCWSTR pcwzValueName, LPDWORD pnReserved, LPDWORD pnType,
	LPBYTE pData, LPDWORD pnDataSize);

CB_UNDECORATED_EXTERN(LSTATUS, RegCloseKey, HKEY hKey);

LSTATUS WINAPI Impl_RegGetValueA(HKEY hKey, LPCSTR pcszSubkey, LPCSTR pcszValue, DWORD flags, LPDWORD pnType, PVOID pData, LPDWORD pnDataSize) {
	LSTATUS status;
	HKEY hValueKey;
	DWORD nType, nBufSize;
	BOOL bCloseValueKey;

	nBufSize = pnDataSize ? *pnDataSize : 0;
	bCloseValueKey = FALSE;
	hValueKey = hKey;

	// open subkey if needed
	if ((pcszSubkey != NULL) && (*pcszSubkey != 0)) {
		status = CB_UNDECORATED_CALL(RegOpenKeyExA, hKey, pcszSubkey, 0, KEY_READ, &hValueKey);
		if (status != 0) return status;

		bCloseValueKey = TRUE;
	}

	// read value
	status = CB_UNDECORATED_CALL(RegQueryValueExA, hKey, pcszValue, NULL, &nType, pData, pnDataSize);
	if (status != 0) return status;

	// null terminate strings
	if ((pData != NULL) && (pnDataSize != NULL) && (*pnDataSize > 0)) {
		switch (nType) {
		case REG_SZ:
		case REG_MULTI_SZ:
		case REG_EXPAND_SZ:
			if (*pnDataSize == nBufSize)
				return ERROR_MORE_DATA; // cannot null terminate
			((LPSTR)pData)[*pnDataSize] = 0;
			break;

		default:
			break;
		}
	}

	// close subkey if needed
	if (bCloseValueKey)
		CB_UNDECORATED_CALL(RegCloseKey, hValueKey);

	return 0;
}

LSTATUS WINAPI Impl_RegGetValueW(HKEY hKey, LPCWSTR pcwzSubkey, LPCWSTR pcwzValue, DWORD flags, LPDWORD pnType, PVOID pData, LPDWORD pnDataSize) {
	LSTATUS status;
	HKEY hValueKey;
	DWORD nType, nBufSize;
	BOOL bCloseValueKey;

	nBufSize = pnDataSize ? *pnDataSize : 0;
	bCloseValueKey = FALSE;
	hValueKey = hKey;

	// open subkey if needed
	if ((pcwzSubkey != NULL) && (*pcwzSubkey != 0)) {
		status = CB_UNDECORATED_CALL(RegOpenKeyExW, hKey, pcwzSubkey, 0, KEY_READ, &hValueKey);
		if (status != 0) return status;

		bCloseValueKey = TRUE;
	}

	// read value
	status = CB_UNDECORATED_CALL(RegQueryValueExW, hKey, pcwzValue, NULL, &nType, pData, pnDataSize);
	if (status != 0) return status;

	// null terminate strings
	if ((pData != NULL) && (pnDataSize != NULL) && (*pnDataSize > 0)) {
		switch (nType) {
		case REG_SZ:
		case REG_MULTI_SZ:
		case REG_EXPAND_SZ:
			if (*pnDataSize > (nBufSize - sizeof(WCHAR)))
				return ERROR_MORE_DATA; // cannot null terminate
			*(LPWSTR)((BYTE*)pData + *pnDataSize) = 0;
			break;

		default:
			break;
		}
	}

	// close subkey if needed
	if (bCloseValueKey)
		CB_UNDECORATED_CALL(RegCloseKey, hValueKey);

	return 0;
}

