#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <assert.h>

static DWORD WINAPI s_Pipe1ThreadProc(LPVOID param);
static DWORD WINAPI s_Pipe2ThreadProc(LPVOID param);
static DWORD WINAPI s_Cancel1AThreadProc(LPVOID param);
static DWORD WINAPI s_Cancel1BThreadProc(LPVOID param);

__declspec(dllimport) BOOL WINAPI CancelIoEx(HANDLE hFile, LPOVERLAPPED povl);
__declspec(dllimport) BOOL WINAPI CancelSynchronousIo(HANDLE hThread);

static const char s_cszData1[] = "I'd just like to interject for a moment.";
static const char s_cszData2[] = "What you're referring to as Linux, is in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux.";
static const char s_cszData3[] = "Linux is not an operating system unto itself, but rather another free component of a fully functioning GNU system "
	"made useful by the GNU corelibs, shell utilities and vital system components comprising a full OS as defined by POSIX.";
static const char s_cszData4[] = "Many computer users run a modified version of the GNU system every day, without realizing it.";
static const char s_cszData5[] = "Through a peculiar turn of events, the version of GNU which is widely used today is often called Linux, "
	"and many of its users are not aware that it is basically the GNU system, developed by the GNU Project.";

static const char s_cszPipe2Name[] = "\\\\.\\pipe\\IOCancellationTest";

__declspec(dllimport) extern int WaysDummy;

void ENTRY_POINT(void) {
	HANDLE hFile, hPipeWriteEnd, hPipeReadEnd, hThread, hCancelThread, hCurrentThread;
	DWORD nTransferred;
	LARGE_INTEGER liNewPos;
	char szData1Read[sizeof(s_cszData1)];
	char szData2Read[sizeof(s_cszData2)];
	char szData3Read[sizeof(s_cszData3)];
	char szData4Read[sizeof(s_cszData4)];
	char szData5Read[sizeof(s_cszData5)];
	OVERLAPPED ovl;

	Sleep(WaysDummy / 1000000); // ensure ways.dll loaded

	// non-overlapped
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

	// overlapped
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

	// cancellation (non-overlapped)
	assert(CreatePipe(&hPipeReadEnd, &hPipeWriteEnd, NULL, 0));
	assert(hThread = CreateThread(NULL, 0, s_Pipe1ThreadProc, (LPVOID)hPipeWriteEnd, 0, NULL));
	assert(CloseHandle(hThread));

	assert(hCancelThread = CreateThread(NULL, 0, s_Cancel1AThreadProc, (LPVOID)hPipeReadEnd, 0, NULL));
	assert(CloseHandle(hCancelThread));

	assert(!ReadFile(hPipeReadEnd, szData4Read, sizeof(szData4Read), &nTransferred, NULL));
	assert(GetLastError() == ERROR_CANCELLED);

	assert(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &hCurrentThread, THREAD_TERMINATE, FALSE, 0));
	assert(hCancelThread = CreateThread(NULL, 0, s_Cancel1BThreadProc, (LPVOID)hCurrentThread, 0, NULL));
	assert(CloseHandle(hCancelThread));

	assert(!ReadFile(hPipeReadEnd, szData4Read, sizeof(szData4Read), &nTransferred, NULL));
	assert(GetLastError() == ERROR_CANCELLED);

	assert(CloseHandle(hCurrentThread));
	assert(CloseHandle(hPipeReadEnd));
	assert(CloseHandle(hPipeWriteEnd));

	// cancellation (overlapped)
	assert(hPipeWriteEnd = CreateNamedPipeA(s_cszPipe2Name, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, INFINITE, NULL));
	assert(hThread = CreateThread(NULL, 0, s_Pipe2ThreadProc, (LPVOID)hPipeWriteEnd, 0, NULL));
	assert(CloseHandle(hThread));

	assert(hPipeReadEnd = CreateFileA(s_cszPipe2Name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL));
	
	assert(!ReadFile(hPipeReadEnd, szData5Read, sizeof(szData5Read), &nTransferred, &ovl));
	assert(GetLastError() == ERROR_IO_PENDING);

	assert(CancelIo(hPipeReadEnd));

	assert(!GetOverlappedResult(hPipeReadEnd, &ovl, &nTransferred, TRUE));
	assert(GetLastError() == ERROR_CANCELLED);

	assert(!ReadFile(hPipeReadEnd, szData5Read, sizeof(szData5Read), &nTransferred, &ovl));
	assert(GetLastError() == ERROR_IO_PENDING);

	assert(CancelIoEx(hPipeReadEnd, NULL));

	assert(!GetOverlappedResult(hPipeReadEnd, &ovl, &nTransferred, TRUE));
	assert(GetLastError() == ERROR_CANCELLED);

	assert(!ReadFile(hPipeReadEnd, szData5Read, sizeof(szData5Read), &nTransferred, &ovl));
	assert(GetLastError() == ERROR_IO_PENDING);

	assert(CancelIoEx(hPipeReadEnd, &ovl));

	assert(!GetOverlappedResult(hPipeReadEnd, &ovl, &nTransferred, TRUE));
	assert(GetLastError() == ERROR_CANCELLED);

	assert(CloseHandle(hPipeReadEnd));
	assert(CloseHandle(hPipeWriteEnd));

	ExitProcess(0);
}

static DWORD WINAPI s_Pipe1ThreadProc(LPVOID param) {
	assert(ConnectNamedPipe((HANDLE)param, NULL));
	return 0;
}

static DWORD WINAPI s_Pipe2ThreadProc(LPVOID param) {
	assert(ConnectNamedPipe((HANDLE)param, NULL));
	return 0;
}

static DWORD WINAPI s_Cancel1AThreadProc(LPVOID param) {
	Sleep(500);
	assert(CancelIoEx((HANDLE)param, NULL));
	return 0;
}

static DWORD WINAPI s_Cancel1BThreadProc(LPVOID param) {
	Sleep(500);
	assert(CancelSynchronousIo((HANDLE)param));
	return 0;
}
