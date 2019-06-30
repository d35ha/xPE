#include "Utils.h"

#define CONSOLE_COLOR_GREEN		0xA
#define CONSOLE_COLOR_YELLOW		0xE
#define CONSOLE_COLOR_RED		0xC
#define CONSOLE_COLOR_WHITE		0x7

CHAR ErrorMsg[MAX_PATH] = { 0 };
HANDLE StdoutConsoleHandle = NULL;
HANDLE StderrConsoleHandle = NULL;
LPCSTR GetLastErrorFormat(ULONG dwErrorCode = -1);
LPCSTR GetNtStatusFormat(NTSTATUS ntCode);

VOID GetStdoutConsoleHandle();
VOID GetStderrConsoleHandle();

VOID ChangeStdoutConsoleColors(WORD _Color);
VOID ChangeStderrConsoleColors(WORD _Color);

VOID PrintSuccess(LPCSTR _Format, va_list _ArgList = NULL);
VOID PrintInfo(LPCSTR _Format, va_list _ArgList = NULL);
VOID PrintError(LPCSTR _Format, va_list _ArgList = NULL);

VOID ReportApiError(LPCSTR _Api, LPCSTR _Format, va_list _ArgList = NULL);
VOID ReportApiNtStatus(LPCSTR _Api, NTSTATUS ntCode, LPCSTR _Format, va_list _ArgList = NULL);
VOID ReportBadPE(LPCSTR _PE, LPCSTR _Format, va_list _ArgList = NULL);

VOID PutToStream(FILE * _Stream, LPCSTR _Format, va_list _ArgList);

namespace Utils
{
	namespace Printf
	{
		VOID Success(LPCSTR _Format, ...)
		{
			ChangeStdoutConsoleColors(CONSOLE_COLOR_GREEN);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			PrintSuccess(_Format, ArgList);
			va_end(ArgList);
			ChangeStdoutConsoleColors(CONSOLE_COLOR_WHITE);
		};
		VOID Info(LPCSTR _Format, ...)
		{
			ChangeStdoutConsoleColors(CONSOLE_COLOR_YELLOW);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			PrintInfo(_Format, ArgList);
			va_end(ArgList);
			ChangeStdoutConsoleColors(CONSOLE_COLOR_WHITE);
		};
		VOID Fail(LPCSTR _Format, ...)
		{
			ChangeStderrConsoleColors(CONSOLE_COLOR_RED);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			PrintError(_Format, ArgList);
			va_end(ArgList);
			ChangeStderrConsoleColors(CONSOLE_COLOR_WHITE);
		};
	};

	namespace Reportf
	{
		VOID ApiError(LPCSTR _Api, LPCSTR _Format, ...)
		{
			ChangeStderrConsoleColors(CONSOLE_COLOR_RED);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			ReportApiError(_Api, _Format, ArgList);
			va_end(ArgList);
			ChangeStderrConsoleColors(CONSOLE_COLOR_WHITE);
		};
		VOID ApiNtStatus(LPCSTR _Api, NTSTATUS ntCode, LPCSTR _Format, ...)
		{
			ChangeStderrConsoleColors(CONSOLE_COLOR_RED);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			ReportApiNtStatus(_Api, ntCode, _Format, ArgList);
			va_end(ArgList);
			ChangeStderrConsoleColors(CONSOLE_COLOR_WHITE);
		};
		VOID BadPE(LPCSTR _PE, LPCSTR _Format, ...)
		{
			ChangeStderrConsoleColors(CONSOLE_COLOR_RED);
			va_list ArgList = NULL;
			va_start(ArgList, _Format);
			ReportBadPE(_PE, _Format, ArgList);
			va_end(ArgList);
			ChangeStderrConsoleColors(CONSOLE_COLOR_WHITE);
		};
	};

	DWORD AlignUp(DWORD dwAddress, DWORD dwAlignment)
	{
		if (!(dwAddress % dwAlignment)) return dwAddress;
		return dwAddress + dwAlignment - dwAddress % dwAlignment;
	};
	BOOL RvaToOffset(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwRva, LPDWORD lpOffset)
	{
		DWORD dwOffset = 0;
		PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
		for (DWORD dwSecIndex = 0; dwSecIndex < lpNtHeader->FileHeader.NumberOfSections; dwSecIndex++, lpHeaderSection++) {
			if (dwRva >= lpHeaderSection->VirtualAddress &&
				dwRva < lpHeaderSection->VirtualAddress + lpHeaderSection->Misc.VirtualSize) {
				dwOffset = lpHeaderSection->PointerToRawData + dwRva - lpHeaderSection->VirtualAddress;
				break;
			}
		};
		if (dwOffset)
		{
			*lpOffset = dwOffset;
			return TRUE;
		};
		return FALSE;
	};
	BOOL IsValidReadPtr(LPVOID lpMem, DWORD dwSize)
	{
		if (IsBadReadPtr(
			lpMem,
			(UINT_PTR)dwSize
		))
		{
#if defined(_M_X64) || defined(__amd64__)
			Reportf::ApiError("IsBadReadPtr", "Memory at 0x%llx with size %d is not readable", (uintptr_t)lpMem, dwSize);
#else
			Reportf::ApiError("IsBadReadPtr", "Memory at 0x%lx with size %d is not readable", (uintptr_t)lpMem, dwSize);
#endif
			return FALSE;
		};
		return TRUE;
	};
	BOOL IsValidWritePtr(LPVOID lpMem, DWORD dwSize)
	{
		if (IsBadWritePtr(
			lpMem,
			(UINT_PTR)dwSize
		))
		{
#if defined(_M_X64) || defined(__amd64__)
			Reportf::ApiError("IsBadWritePtr", "Memory at 0x%llx with size %d is not writable", (uintptr_t)lpMem, dwSize);
#else
			Reportf::ApiError("IsBadWritePtr", "Memory at 0x%lx with size %d is not writable", (uintptr_t)lpMem, dwSize);
#endif
			return FALSE;
		};
		return TRUE;
	};
	BOOL GetPageProtectionFromSCNProtection(DWORD dwImageSCNCharacteristics, PDWORD lpPageProtection)
	{
		*lpPageProtection = PAGE_NOACCESS;
		if ((dwImageSCNCharacteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(dwImageSCNCharacteristics & IMAGE_SCN_MEM_READ) &&
			(dwImageSCNCharacteristics & IMAGE_SCN_MEM_WRITE)) {
			*lpPageProtection = PAGE_EXECUTE_READWRITE;
		}
		else if ((dwImageSCNCharacteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(dwImageSCNCharacteristics & IMAGE_SCN_MEM_READ)) {
			*lpPageProtection = PAGE_EXECUTE_READ;
		}
		else if ((dwImageSCNCharacteristics & IMAGE_SCN_MEM_EXECUTE) &&
			(dwImageSCNCharacteristics & IMAGE_SCN_MEM_WRITE)) {
			*lpPageProtection = PAGE_EXECUTE_WRITECOPY;
		}
		else if ((dwImageSCNCharacteristics & IMAGE_SCN_MEM_READ) &&
			(dwImageSCNCharacteristics & IMAGE_SCN_MEM_WRITE)) {
			*lpPageProtection = PAGE_READWRITE;
		}
		else if (dwImageSCNCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
			*lpPageProtection = PAGE_EXECUTE;
		}
		else if (dwImageSCNCharacteristics & IMAGE_SCN_MEM_READ) {
			*lpPageProtection = PAGE_READONLY;
		}
		else if (dwImageSCNCharacteristics & IMAGE_SCN_MEM_WRITE) {
			*lpPageProtection = PAGE_WRITECOPY;
		}
		else {
			return FALSE;
		}
		return TRUE;
	};
	BOOL SafeMemoryCopy(LPVOID lpDest, DWORD dwDestSize, LPVOID lpSource, DWORD dwSourceSize)
	{
		if (!IsValidWritePtr(
			lpDest,
			dwSourceSize < dwDestSize ? dwSourceSize : dwDestSize
		)) return FALSE;

		if (!IsValidReadPtr(
			lpSource,
			dwSourceSize < dwDestSize ? dwSourceSize : dwDestSize
		)) return FALSE;

		memcpy_s(
			lpDest,
			dwDestSize,
			lpSource,
			dwSourceSize
		);

		return TRUE;
	};
};

VOID ChangeStdoutConsoleColors(WORD _Color) {

	GetStdoutConsoleHandle();
	if (!StdoutConsoleHandle)
	{
		PrintError("Error happened at getting the console stdout handle");
		return;
	};
	
	if (!SetConsoleTextAttribute(
		StdoutConsoleHandle,
		_Color
	))
	{
		PrintError("Error happened at changing the console stdout color");
		return;
	};
};
VOID ChangeStderrConsoleColors(WORD _Color) {

	GetStderrConsoleHandle();
	if (!StderrConsoleHandle)
	{
		PrintError("Error happened at getting the console stderr handle");
		return;
	};

	if (!SetConsoleTextAttribute(
		StderrConsoleHandle,
		_Color
	))
	{
		PrintError("Error happened at changing the console stderr color");
		return;
	};
};

VOID GetStdoutConsoleHandle()
{
	if (!StdoutConsoleHandle)
	{
		StdoutConsoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	};
};
VOID GetStderrConsoleHandle()
{
	if (!StderrConsoleHandle)
	{
		StderrConsoleHandle = GetStdHandle(STD_ERROR_HANDLE);
	};
};

VOID PrintSuccess(LPCSTR _Format, va_list _ArgList)
{
	fputs("[+] ", stdout);
	PutToStream(stdout, _Format, _ArgList);
	fputc('\n', stdout);
};
VOID PrintInfo(LPCSTR _Format, va_list _ArgList)
{
	fputs("[!] ", stdout);
	PutToStream(stdout, _Format, _ArgList);
	fputc('\n', stdout);
};
VOID PrintError(LPCSTR _Format, va_list _ArgList)
{
	fputs("[-] ", stderr);
	PutToStream(stderr, _Format, _ArgList);
	fputc('\n', stderr);
};

VOID ReportApiError(LPCSTR _Api, LPCSTR _Format, va_list _ArgList)
{
	fprintf(stderr, "[-] Error occured at running the api %s, ", _Api);
	PutToStream(stderr, _Format, _ArgList);
	fprintf(stderr, ", Last error code/msg is %s", GetLastErrorFormat());
	fputc('\n', stderr);
};
VOID ReportApiNtStatus(LPCSTR _Api, NTSTATUS ntCode, LPCSTR _Format, va_list _ArgList)
{
	fprintf(stderr, "[-] Error occured at running the api %s, ", _Api);
	PutToStream(stderr, _Format, _ArgList);
	fprintf(stderr, ", Last ntstatus code/msg is %s", GetNtStatusFormat(ntCode));
	fputc('\n', stderr);
};
VOID ReportBadPE(LPCSTR _PE, LPCSTR _Format, va_list _ArgList)
{
	fprintf(stderr, "[-] Error occured at handling the PE file %s, ", _PE);
	PutToStream(stderr, _Format, _ArgList);
	fputc('\n', stderr);
};

VOID PutToStream(FILE* _Stream, LPCSTR _Format, va_list _ArgList)
{
	if (_ArgList)
	{
		vfprintf(_Stream, _Format, _ArgList);
	}
	else
	{
		fputs(_Format, _Stream);
	};
};

LPCSTR GetLastErrorFormat(ULONG dwErrorCode)
{
	if (dwErrorCode == -1) dwErrorCode = GetLastError();
	if (!FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		ErrorMsg,
		sizeof(ErrorMsg),
		NULL
	))
	{
		sprintf_s(ErrorMsg, "0x%lx", dwErrorCode);
	};
	if (ErrorMsg[strlen(ErrorMsg) - 1] == '\n')
	{
		ErrorMsg[strlen(ErrorMsg) - 1] = 0;
	};
	return ErrorMsg;
};
LPCSTR GetNtStatusFormat(NTSTATUS ntCode)
{
	ULONG dwErrorCode = RtlNtStatusToDosError(ntCode);
	if (dwErrorCode == ERROR_MR_MID_NOT_FOUND)
	{
		sprintf_s(ErrorMsg, "0x%lx", dwErrorCode);
		return ErrorMsg;
	};
	return GetLastErrorFormat(dwErrorCode);
};
