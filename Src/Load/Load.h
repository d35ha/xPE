#include "../Utils/Utils.h"

namespace Load
{
	namespace File
	{
		BOOL Load(LPCSTR szFilePath, PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength);
		BOOL UnLoad(PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength);
	};

	namespace PE
	{
		BOOL GetDosHeader(PRAW_FILE_INFO lpFileInfo, PIMAGE_DOS_HEADER* lplpDosHeader);
		BOOL GetNtHeader(PRAW_FILE_INFO lpFileInfo, PIMAGE_NT_HEADERS* lplpNtHeader);
		BOOL GetArch(PRAW_FILE_INFO lpFileInfo, PDWORD Arch);
		BOOL GetType(PRAW_FILE_INFO lpFileInfo, PDWORD Type);
		BOOL CheckRelocation(PRAW_FILE_INFO lpFileInfo, PBOOL IsRelocatable);
		BOOL Map(PRAW_FILE_INFO lpFileInfo, LPVOID* lplpMappedPE);
		BOOL UnMap(LPVOID lpMappedPE, DWORD dwImageSize, PRAW_FILE_INFO lpUnMappedFileInfo);
		BOOL IsDirExists(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PBOOL IsExists);
		BOOL GetDirectoryInfo(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PDWORD lpDirEntry, PDWORD lpDirSize, BOOL IsMapped);
		LPCSTR GetDirTableName(DWORD dwDirectory);
	};

	namespace Process
	{
		BOOL GetHandle(DWORD dwPid, PHANDLE lpHandle, DWORD dwDesiredAccess);
		BOOL GetArch(HANDLE hProcess, PDWORD lpArch);
		BOOL GetPEB(HANDLE hProcess, PPEB lpPeb, LPVOID* lpPebAddress);
		BOOL GetModNtHeader(HANDLE hProcess, LPVOID lpModBase, LPVOID lpNtHeader);
	};
};
