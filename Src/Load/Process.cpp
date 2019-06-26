#include "Load.h"

namespace Utils
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
			if ((ntProcessStatus = NtQueryInformationProcess(
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
				if ((*(UINT(*)(LPSTR, UINT)) fnGetSystemWow64DirectoryA)(
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
		BOOL GetPEB(HANDLE hProcess, PPEB lpProcessPeb)
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
			if ((ntProcessStatus = NtQueryInformationProcess(
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
				Utils::Reportf::ApiNtStatus("ReadProcessMemory", ntProcessStatus,
					"Cannot read the PEB from the process with handle 0x%x", hProcess);
				return FALSE;
			};
			PPEB lpPeb = (PPEB)bPeb;
			
			if (!Utils::SafeMemoryCopy(
				(LPVOID)lpProcessBasicInfo,
				sizeof(PEB),
				(LPVOID)lpPeb,
				sizeof(PEB)
			)) return FALSE;
			return TRUE;
		};
	};
};