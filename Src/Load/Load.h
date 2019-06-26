#include "../Utils/Utils.h"

typedef struct _RAW_FILE_INFO {
	HANDLE hFile;
	CHAR Path[MAX_PATH];
	DWORD dwSize;
	LPVOID lpDataBuffer;
} RAW_FILE_INFO, * PRAW_FILE_INFO;

namespace Load
{
	namespace File
	{
		VOID Load(LPCSTR szFilePath, PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength);
		VOID UnLoad(PRAW_FILE_INFO lpFileInfo, DWORD dwBufferLength);
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
	};

	namespace Process
	{
		BOOL GetHandle(DWORD dwPid, PHANDLE lpHandle, DWORD dwDesiredAccess);
		BOOL GetArch(HANDLE hProcess, PDWORD lpArch);
		BOOL GetPEB(HANDLE hProcess, PPEB lpPeb);
	};
};