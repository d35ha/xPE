#include "Load.h"

VOID CloseFileHandle(HANDLE hFile);
VOID ResetMemory(LPVOID lpMem, DWORD dwSize);

namespace Load
{
	namespace File
	{
		VOID Load(LPCSTR szFilePath, PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength)
		{
			ResetMemory(lpFileInfo, dwBufferLength);

			if (dwBufferLength < sizeof(lpFileInfo->hFile)) return;
			dwBufferLength -= sizeof(lpFileInfo->hFile);
			if (!(lpFileInfo->hFile = CreateFileA(
				szFilePath,
				GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			)) || INVALID_HANDLE_VALUE == lpFileInfo->hFile)
			{
				Utils::Reportf::ApiError("CreateFileA", "Error while opening the file %s", szFilePath);
				return;
			};

			if (dwBufferLength < sizeof(lpFileInfo->Path)) return;
			dwBufferLength -= sizeof(lpFileInfo->Path);
			strcpy_s(lpFileInfo->Path, sizeof(lpFileInfo->Path), szFilePath);

			LARGE_INTEGER u32FileSize;
			if (!GetFileSizeEx(
				lpFileInfo->hFile,
				&u32FileSize
			))
			{
				Utils::Reportf::ApiError("GetFileSizeEx", "Error while getting the size of the file %s", szFilePath);
				CloseFileHandle(lpFileInfo->hFile);
				ResetMemory(lpFileInfo, dwBufferLength);
				return;
			};
			if (dwBufferLength < sizeof(lpFileInfo->dwSize)) return;
			dwBufferLength -= sizeof(lpFileInfo->dwSize);
			lpFileInfo->dwSize = (DWORD)u32FileSize.QuadPart;

			LPVOID bFileContent = NULL;
			if (!(bFileContent = VirtualAlloc(
				NULL,
				lpFileInfo->dwSize,
				(MEM_COMMIT | MEM_RESERVE),
				PAGE_READWRITE
			)))
			{
				Utils::Reportf::ApiError("VirtualAlloc", "Error while allocating %d bytes of memory for the file %s", lpFileInfo->dwSize, szFilePath);
				CloseFileHandle(lpFileInfo->hFile);
				ResetMemory(lpFileInfo, dwBufferLength);
				return;
			};

			DWORD dwReadBytes = 0;
			if (!ReadFile(
				lpFileInfo->hFile,
				bFileContent,
				lpFileInfo->dwSize,
				&dwReadBytes,
				NULL
			) || dwReadBytes != lpFileInfo->dwSize)
			{
				Utils::Reportf::ApiError("ReadFile", "Error while reading the file %s", szFilePath);
				CloseFileHandle(lpFileInfo->hFile);
				ResetMemory(lpFileInfo, dwBufferLength);
				return;
			};
			if (dwBufferLength < sizeof(lpFileInfo->lpDataBuffer)) return;
			dwBufferLength -= sizeof(lpFileInfo->lpDataBuffer);
			lpFileInfo->lpDataBuffer = bFileContent;
		};
		VOID UnLoad(PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength)
		{
			if (!VirtualFree(
				lpFileInfo->lpDataBuffer,
				0,
				MEM_RELEASE
			))
			{
#if defined(_M_X64) || defined(__amd64__)
				Utils::Reportf::ApiError("VirtualFree", "Error while freeing the allocated memory at 0x%llx", (ULONGLONG)lpFileInfo->lpDataBuffer);
#else
				Utils::Reportf::ApiError("VirtualFree", "Error while freeing the allocated memory at 0x%lx", (ULONG)lpFileInfo->lpDataBuffer);
#endif
			};
			CloseFileHandle(lpFileInfo->hFile);
			ResetMemory(lpFileInfo, dwBufferLength);
		};
	}
};

VOID CloseFileHandle(HANDLE hFile)
{
	if (!CloseHandle(
		hFile
	))
	{
#if defined(_M_X64) || defined(__amd64__)
		Utils::Reportf::ApiError("CloseHandle", "Error while closing the handle 0x%llx", (ULONGLONG)hFile);
#else
		Utils::Reportf::ApiError("CloseHandle", "Error while closing the handle 0x%lx", (ULONG)hFile);
#endif
	};
};

VOID ResetMemory(LPVOID lpMem, DWORD dwSize)
{
	ZeroMemory(
		lpMem,
		dwSize
	);
};