#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <assert.h>

static const char s_cszData1[] = "I'd just like to interject for a moment.";
static const char s_cszData2[] = "What you're referring to as Linux, is in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux.";
static const char s_cszData3[] = "Linux is not an operating system unto itself, but rather another free component of a fully functioning GNU system "
	"made useful by the GNU corelibs, shell utilities and vital system components comprising a full OS as defined by POSIX.";

__declspec(dllimport) extern int WaysDummy;

void ENTRY_POINT(void) {
	HANDLE hFile;
	DWORD nTransferred;
	LARGE_INTEGER liNewPos;
	char szData1Read[sizeof(s_cszData1)];
	char szData2Read[sizeof(s_cszData2)];
	char szData3Read[sizeof(s_cszData3)];
	OVERLAPPED ovl;

	Sleep(WaysDummy / 1000000); // ensure ways.dll loaded

	hFile = CreateFileA("test1.dat", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	assert(hFile != INVALID_HANDLE_VALUE);

	assert(WriteFile(hFile, s_cszData1, sizeof(s_cszData1), &nTransferred, NULL));
	assert(nTransferred == sizeof(s_cszData1));

	liNewPos.QuadPart = 0;
	assert(SetFilePointerEx(hFile, liNewPos, &liNewPos, FILE_BEGIN));
	assert(liNewPos.QuadPart == 0);

	assert(ReadFile(hFile, szData1Read, sizeof(szData1Read), &nTransferred, NULL));
	assert(nTransferred == sizeof(szData1Read));
	assert(memcmp(szData1Read, s_cszData1, sizeof(s_cszData1)) == 0);

	memset(&ovl, 0, sizeof(ovl));
	ovl.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	assert(ovl.hEvent != NULL);

	assert(WriteFile(hFile, s_cszData2, sizeof(s_cszData2), &nTransferred, &ovl));

	assert(GetOverlappedResult(hFile, &ovl, &nTransferred, TRUE));
	assert(nTransferred == sizeof(s_cszData2));

	assert(ReadFile(hFile, szData2Read, sizeof(szData2Read), &nTransferred, &ovl));

	assert(GetOverlappedResult(hFile, &ovl, &nTransferred, TRUE));
	assert(nTransferred == sizeof(s_cszData2));

	assert(memcmp(szData2Read, s_cszData2, sizeof(s_cszData2)) == 0);

	assert(CloseHandle(hFile));

	hFile = CreateFileA("test2.dat", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
	assert(hFile != INVALID_HANDLE_VALUE);

	if (!WriteFile(hFile, s_cszData3, sizeof(s_cszData3), &nTransferred, &ovl))
		assert(GetLastError() == ERROR_IO_PENDING);

	assert(GetOverlappedResult(hFile, &ovl, &nTransferred, TRUE));
	assert(nTransferred == sizeof(s_cszData3));

	if (!ReadFile(hFile, szData3Read, sizeof(szData3Read), &nTransferred, &ovl))
		assert(GetLastError() == ERROR_IO_PENDING);

	assert(GetOverlappedResult(hFile, &ovl, &nTransferred, TRUE));
	assert(nTransferred == sizeof(s_cszData3));

	assert(memcmp(szData3Read, s_cszData3, sizeof(s_cszData3)) == 0);

	assert(CloseHandle(hFile));
	ExitProcess(0);
}


