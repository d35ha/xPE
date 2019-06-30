#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifndef UTILS_H_
#define UTILS_H_

#pragma comment (lib, "ntdll.lib")

#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

#define GET_DIRECTORY_ENTRY(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].VirtualAddress
#define GET_DIRECTORY_SIZE(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].Size

typedef struct _RAW_FILE_INFO {
	HANDLE hFile;
	CHAR Path[MAX_PATH];
	DWORD dwSize;
	LPVOID lpDataBuffer;
} RAW_FILE_INFO, * PRAW_FILE_INFO;

enum
{
	x32,
	x64
};

enum
{
	exe,
	dll,
	sys
};

namespace Utils
{
	namespace Printf
	{
		VOID Success(LPCSTR _Format, ...);
		VOID Info(LPCSTR _Format, ...);
		VOID Fail(LPCSTR _Format, ...);
	};

	namespace Reportf
	{
		VOID BadPE(LPCSTR _PE , LPCSTR _Format, ...);
		VOID ApiError(LPCSTR _Api, LPCSTR _Format, ...);
		VOID ApiNtStatus(LPCSTR _Api, NTSTATUS ntCode, LPCSTR _Format, ...);
	};

	DWORD AlignUp(DWORD dwAddress, DWORD dwAlignment);
	BOOL RvaToOffset(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwRVA, LPDWORD lpOffset);
	BOOL IsValidReadPtr(LPVOID lpMem, DWORD dwSize);
	BOOL IsValidWritePtr(LPVOID lpMem, DWORD dwSize);
	BOOL GetPageProtectionFromSCNProtection(DWORD dwImageSCNCharacteristics, PDWORD lpPageProtection);
	BOOL SafeMemoryCopy(LPVOID lpDest, DWORD dwDestSize, LPVOID lpSource, DWORD dwSourceSize);
};

#endif
