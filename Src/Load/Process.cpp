#include "Load.h"

namespace Load
{
	namespace Process
	{
		BOOL GetHandle(DWORD dwPid, PHANDLE lpHandle, DWORD dwDesiredAccess)
		{
			HANDLE hProcess = NULL;
			if (hProcess != OpenProcess(
				dwDesiredAccess,
				FALSE,
				dwPid
			))
			{
				Utils::Reportf::ApiError("OpenProcess", "Cannot open the desired pid %d", dwPid);
				return FALSE;
			};
			*lpHandle = hProcess;
			return TRUE;
		};
		BOOL GetArch(HANDLE hProcess, PDWORD lpArch)
		{
			ULONG ulWrittenSize = 0;
			LPVOID lpIsWow64 = NULL;
			NTSTATUS ntProcessStatus = 0;
			if ((ntProcessStatus = (*(NTSTATUS(WINAPI*)(
				HANDLE,
				PROCESSINFOCLASS,
				PVOID,
				ULONG,
				PULONG
				)) _NtQueryInformationProcess)(
					hProcess,
					ProcessWow64Information,
					&lpIsWow64,
					sizeof(lpIsWow64),
					&ulWrittenSize
					)) || ulWrittenSize != sizeof(lpIsWow64))
			{
				Utils::Reportf::ApiNtStatus("NtQueryInformationProcess", ntProcessStatus,
					"Cannot check if the process with handle 0x%x is WoW64 process", hProcess);
				return FALSE;
			};

#if defined(_M_X64) || defined(__amd64__)
			if (lpIsWow64) *lpArch = x32;
			else *lpArch = x64;
#else
			HMODULE hKernel32 = NULL;
			if (!(hKernel32 = GetModuleHandleA("kernel32")))
			{
				Utils::Reportf::ApiError("GetModuleHandleA", "Cannot get the handle of kernel.dll");
				return FALSE;
			};

			LPVOID fnGetSystemWow64DirectoryA = NULL;
			if ((fnGetSystemWow64DirectoryA = (LPVOID)GetProcAddress(hKernel32, "GetSystemWow64DirectoryA")))
			{
				CHAR WoW64Dir[1] = { 0 };
				if ((*(UINT(WINAPI*)(LPSTR, UINT)) fnGetSystemWow64DirectoryA)(
					WoW64Dir,
					sizeof(WoW64Dir)
					))
				{
					if (lpIsWow64) *lpArch = x32;
					else *lpArch = x64;
				}
				else if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
				{
					*lpArch = x32;
				}
				else
				{
					Utils::Reportf::ApiError("GetSystemWow64DirectoryA", "Cannot check if the system has the WoW64 layer");
					return FALSE;
				};
			}
			else if (GetLastError() == ERROR_PROC_NOT_FOUND)
			{
				*lpArch = x32;
			}
			else
			{
				Utils::Reportf::ApiError("GetProcAdress", "Cannot get address of the api GetSystemWow64DirectoryA");
				return FALSE;
			};
#endif
			return TRUE;
		};
		BOOL GetPEB(HANDLE hProcess, PPEB lpProcessPeb, LPVOID* lpPebAddress)
		{
			if (!Utils::IsValidWritePtr(
				lpProcessPeb,
				sizeof(PEB)
			)) return FALSE;

			ZeroMemory(
				(LPVOID)lpProcessPeb,
				sizeof(PEB)
			);

			DWORD ulWrittenSize = 0;
			BYTE bProcessBasicInfo[sizeof(PROCESS_BASIC_INFORMATION)] = { 0 };
			NTSTATUS ntProcessStatus = 0;

			if ((ntProcessStatus = (*(NTSTATUS(WINAPI*)(
				HANDLE,
				PROCESSINFOCLASS,
				PVOID,
				ULONG,
				PULONG
				)) _NtQueryInformationProcess)(
					hProcess,
					ProcessBasicInformation,
					(PVOID)bProcessBasicInfo,
					sizeof(PROCESS_BASIC_INFORMATION),
					&ulWrittenSize
					)) || ulWrittenSize != sizeof(PROCESS_BASIC_INFORMATION))
			{
				Utils::Reportf::ApiNtStatus("NtQueryInformationProcess", ntProcessStatus,
					"Cannot get the basic information of the process with handle 0x%x", hProcess);
				return FALSE;
			};
				
			PPROCESS_BASIC_INFORMATION lpProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)bProcessBasicInfo;
			*lpPebAddress = lpProcessBasicInfo->PebBaseAddress;

			BYTE bPeb[sizeof(PEB)] = { 0 };
			SIZE_T stReadBytes = 0;
			if (!ReadProcessMemory(
				hProcess,
				lpProcessBasicInfo->PebBaseAddress,
				bPeb,
				sizeof(bPeb),
				&stReadBytes
			) || stReadBytes != sizeof(bPeb))
			{
				Utils::Reportf::ApiError("ReadProcessMemory",
					"Cannot read the PEB from the process with handle 0x%x", hProcess);
				return FALSE;
			};
			PPEB lpPeb = (PPEB)bPeb;
			
			if (!Utils::SafeMemoryCopy(
				(LPVOID)lpProcessPeb,
				sizeof(PEB),
				(LPVOID)lpPeb,
				sizeof(PEB)
			)) return FALSE;
			return TRUE;
		};
		BOOL GetModNtHeader(HANDLE hProcess, LPVOID lpModBase, LPVOID lpNtHeader)
		{
			if (!Utils::IsValidWritePtr(
				lpNtHeader,
				sizeof(IMAGE_NT_HEADERS)
			)) return FALSE;

			ZeroMemory(
				(LPVOID)lpNtHeader,
				sizeof(IMAGE_NT_HEADERS)
			);

			BYTE bDosHeader[sizeof(IMAGE_DOS_HEADER)] = { 0 };
			SIZE_T stReadBytes = 0;
			if (!ReadProcessMemory(
				hProcess,
				lpModBase,
				bDosHeader,
				sizeof(bDosHeader),
				&stReadBytes
			) || stReadBytes != sizeof(bDosHeader))
			{
				Utils::Reportf::ApiError("ReadProcessMemory", "Cannot read the dos header for this module");
				return FALSE;
			};
			PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)bDosHeader;

			BYTE bNtHeader[sizeof(IMAGE_NT_HEADERS)] = { 0 };
			if (!ReadProcessMemory(
				hProcess,
				(LPVOID)((uintptr_t)lpModBase + lpDosHeader->e_lfanew),
				bNtHeader,
				sizeof(bNtHeader),
				&stReadBytes
			) || stReadBytes != sizeof(bNtHeader))
			{
				Utils::Reportf::ApiError("ReadProcessMemory", "Cannot read the nt header for this module");
				return FALSE;
			};
			PIMAGE_NT_HEADERS _lpNtHeader = (PIMAGE_NT_HEADERS)bNtHeader;

			if (!Utils::SafeMemoryCopy(
				(LPVOID)lpNtHeader,
				sizeof(IMAGE_NT_HEADERS),
				(LPVOID)_lpNtHeader,
				sizeof(IMAGE_NT_HEADERS)
			)) return FALSE;
			return TRUE;
		};
	};
};
