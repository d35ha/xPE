#include "Load.h"

namespace Load
{
	namespace PE
	{
		BOOL GetDosHeader(PRAW_FILE_INFO lpFileInfo, PIMAGE_DOS_HEADER* lplpDosHeader)
		{
			*lplpDosHeader = NULL;
			if (!Utils::IsValidReadPtr(
				lpFileInfo->lpDataBuffer,
				sizeof(IMAGE_DOS_HEADER)
			)) return FALSE;
			
			*lplpDosHeader = (PIMAGE_DOS_HEADER)lpFileInfo->lpDataBuffer;
			if ((*lplpDosHeader)->e_magic != IMAGE_DOS_SIGNATURE)
			{
				Utils::Reportf::BadPE(lpFileInfo->Path, "Invalid DOS header");
				*lplpDosHeader = NULL;
				return FALSE;
			};
			return TRUE;
		};
		BOOL GetNtHeader(PRAW_FILE_INFO lpFileInfo, PIMAGE_NT_HEADERS* lplpNtHeader)
		{
			*lplpNtHeader = NULL;
			PIMAGE_DOS_HEADER lpDosHeader = NULL;
			if (GetDosHeader(
				lpFileInfo,
				&lpDosHeader
			))
			{
				*lplpNtHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpFileInfo->lpDataBuffer + lpDosHeader->e_lfanew);
				if (!Utils::IsValidReadPtr(
					(LPVOID)*lplpNtHeader,
					sizeof(IMAGE_NT_HEADERS)
				)) return FALSE;

				if ((*lplpNtHeader)->Signature != IMAGE_NT_SIGNATURE)
				{
					Utils::Reportf::BadPE(lpFileInfo->Path, "Invalid NT header");
					*lplpNtHeader = NULL;
					return FALSE;

				};
				return TRUE;
			};
			Utils::Printf::Fail("Cannot get the NT header");
			return FALSE;
		};
		BOOL GetArch(PRAW_FILE_INFO lpFileInfo, PDWORD Arch)
		{
			PIMAGE_NT_HEADERS lpNtHeader = NULL;
			if (GetNtHeader(
				lpFileInfo,
				&lpNtHeader
			))
			{
				switch (lpNtHeader->OptionalHeader.Magic)
				{
				case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
					*Arch = x32;
					return TRUE;
				case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
					*Arch = x64;
					return TRUE;
				default:
					Utils::Reportf::BadPE(lpFileInfo->Path, "Invalid or unsupported arch");
					return FALSE;
				};
			};
			Utils::Printf::Fail("Cannot get the PE arch");
			return FALSE;
		};
		BOOL GetType(PRAW_FILE_INFO lpFileInfo, PDWORD Type)
		{
			PIMAGE_NT_HEADERS lpNtHeader = NULL;
			if (GetNtHeader(
				lpFileInfo,
				&lpNtHeader
			))
			{
				if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
				{
					*Type = exe;
					return TRUE;
				}
				else if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
				{
					*Type = dll;
					return TRUE;
				}
				else if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM)
				{
					*Type = sys;
					return TRUE;
				}
				else
				{
					Utils::Reportf::BadPE(lpFileInfo->Path, "Invalid or unsupported type");
					return FALSE;
				};
			};
			Utils::Printf::Fail("Cannot get the PE type");
			return FALSE;
		};
		BOOL CheckRelocation(PRAW_FILE_INFO lpFileInfo, PBOOL IsRelocatable)
		{
			PIMAGE_NT_HEADERS lpNtHeader = NULL;
			if (GetNtHeader(
				lpFileInfo,
				&lpNtHeader
			))
			{
				if (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)* IsRelocatable = FALSE;
				else *IsRelocatable = TRUE;
				return TRUE;
			};
			Utils::Printf::Fail("Cannot check if the PE is relocatable");
			return FALSE;
		};
		BOOL Map(PRAW_FILE_INFO lpFileInfo, LPVOID* lplpMappedPE)
		{
			*lplpMappedPE = NULL;
			PIMAGE_NT_HEADERS lpNtHeader = NULL;
			if (GetNtHeader(
				lpFileInfo,
				&lpNtHeader
			))
			{
				LPVOID lpImage = NULL;
				if (!(lpImage = VirtualAlloc(
					NULL,
					lpNtHeader->OptionalHeader.SizeOfImage,
					(MEM_COMMIT | MEM_RESERVE),
					PAGE_READWRITE
				)))
				{
					Utils::Reportf::ApiError("VirtualAlloc", "Error while allocating %d bytes of memory", lpNtHeader->OptionalHeader.SizeOfImage);
					return FALSE;
				};

				ZeroMemory(
					lpImage,
					lpNtHeader->OptionalHeader.SizeOfImage
				);

				if (!Utils::SafeMemoryCopy(
					lpImage,
					lpNtHeader->OptionalHeader.SizeOfImage,
					lpFileInfo->lpDataBuffer,
					lpNtHeader->OptionalHeader.SizeOfHeaders
				)) return FALSE;

				PIMAGE_SECTION_HEADER lpSectionHeaderArray = IMAGE_FIRST_SECTION(lpNtHeader);
				for (int SecIndex = 0; SecIndex < lpNtHeader->FileHeader.NumberOfSections; SecIndex++)
				{
					if (lpSectionHeaderArray[SecIndex].PointerToRawData)
					{
						if (!Utils::SafeMemoryCopy(
							(LPVOID)((uintptr_t)lpImage + lpSectionHeaderArray[SecIndex].VirtualAddress),
							lpNtHeader->OptionalHeader.SizeOfImage -
							lpSectionHeaderArray[SecIndex].VirtualAddress,
							(LPVOID)((uintptr_t)lpFileInfo->lpDataBuffer + lpSectionHeaderArray[SecIndex].PointerToRawData),
							lpSectionHeaderArray[SecIndex].SizeOfRawData
						)) return FALSE;
					};
				};

				*lplpMappedPE = lpImage;
				return TRUE;
			};
			Utils::Printf::Fail("Cannot map this PE");
			return FALSE;
		};
		BOOL UnMap(LPVOID lpMappedPE, DWORD dwImageSize, PRAW_FILE_INFO lpUnMappedFileInfo)
		{
			if (!Utils::IsValidReadPtr(
				lpMappedPE,
				dwImageSize
			)) return FALSE;

			if (!Utils::IsValidReadPtr(
				(LPVOID)lpUnMappedFileInfo,
				sizeof(RAW_FILE_INFO)
			)) return FALSE;

			ZeroMemory (
				(LPVOID)lpUnMappedFileInfo,
				sizeof(RAW_FILE_INFO)
			);

			BYTE bFileInfo[sizeof(RAW_FILE_INFO)] = { 0 };
			PRAW_FILE_INFO lpFileInfo = (PRAW_FILE_INFO)bFileInfo;
			lpFileInfo->dwSize = dwImageSize;
			lpFileInfo->lpDataBuffer = lpMappedPE;
			strcpy_s(lpFileInfo->Path, sizeof(lpFileInfo->Path), "[MAPPED_FILE]");
			
			PIMAGE_NT_HEADERS lpNtHeader = NULL;
			if (GetNtHeader(
				lpFileInfo,
				&lpNtHeader
			))
			{
				DWORD dwRawSize = Utils::AlignUp(
					lpNtHeader->OptionalHeader.SizeOfHeaders,
					lpNtHeader->OptionalHeader.FileAlignment
				);

				PIMAGE_SECTION_HEADER lpSectionHeaderArray = IMAGE_FIRST_SECTION(lpNtHeader);
				for (int SecIndex = 0; SecIndex < lpNtHeader->FileHeader.NumberOfSections; SecIndex++)
				{
					dwRawSize += Utils::AlignUp(
						lpSectionHeaderArray[SecIndex].SizeOfRawData,
						lpNtHeader->OptionalHeader.FileAlignment
					);
				};

				LPVOID lpImage = NULL;
				if (!(lpImage = VirtualAlloc(
					NULL,
					dwRawSize,
					(MEM_COMMIT | MEM_RESERVE),
					PAGE_READWRITE
				)))
				{
					Utils::Reportf::ApiError("VirtualAlloc", "Error while allocating %d bytes of memory", lpNtHeader->OptionalHeader.SizeOfImage);
					return FALSE;
				};

				ZeroMemory(
					lpImage,
					dwRawSize
				);

				if (!Utils::SafeMemoryCopy(
					lpImage,
					dwRawSize,
					lpFileInfo->lpDataBuffer,
					lpNtHeader->OptionalHeader.SizeOfHeaders
				)) return FALSE;

				lpSectionHeaderArray = IMAGE_FIRST_SECTION(lpNtHeader);
				for (int SecIndex = 0; SecIndex < lpNtHeader->FileHeader.NumberOfSections; SecIndex++)
				{
					if (lpSectionHeaderArray[SecIndex].PointerToRawData) {
						if (!Utils::SafeMemoryCopy(
							(LPVOID)((uintptr_t)lpImage + lpSectionHeaderArray[SecIndex].PointerToRawData),
							dwRawSize - lpSectionHeaderArray[SecIndex].PointerToRawData,
							(LPVOID)((uintptr_t)lpFileInfo->lpDataBuffer + lpSectionHeaderArray[SecIndex].VirtualAddress),
							Utils::AlignUp(
								lpSectionHeaderArray[SecIndex].Misc.VirtualSize,
								lpNtHeader->OptionalHeader.SectionAlignment
							)
						)) return FALSE;
					};
				};

				if (!Utils::SafeMemoryCopy(
					lpUnMappedFileInfo,
					sizeof(RAW_FILE_INFO),
					lpFileInfo,
					sizeof(RAW_FILE_INFO)
				))  return TRUE;

				return TRUE;
			};
			Utils::Printf::Fail("Cannot unmap this PE");
			return FALSE;
		};
		BOOL IsDirExists(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PBOOL IsExists)
		{
			if (dwDirectory > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR || dwDirectory < IMAGE_DIRECTORY_ENTRY_EXPORT)
			{
				Utils::Printf::Fail("Invalid directory table of %d", dwDirectory);
				return FALSE;
			};
			*IsExists = GET_DIRECTORY_ENTRY(lpNtHeader, dwDirectory) && GET_DIRECTORY_SIZE(lpNtHeader, dwDirectory);
			return TRUE;
		};
		BOOL GetDirectoryInfo(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PDWORD lpDirEntry, PDWORD lpDirSize, BOOL IsMapped)
		{
			BOOL IsExists = FALSE;
			if (IsDirExists(lpNtHeader, dwDirectory, &IsExists))
			{
				if (!IsExists)
				{
					Utils::Printf::Fail("Directory table %s doesn't exist in the PE", GetDirTableName(dwDirectory));
					return FALSE;
				};

				DWORD dwBaseOffset = GET_DIRECTORY_ENTRY(lpNtHeader, dwDirectory);
				DWORD dwTableSize = GET_DIRECTORY_SIZE(lpNtHeader, dwDirectory);

				if (!IsMapped && dwDirectory != IMAGE_DIRECTORY_ENTRY_SECURITY)
				{
					if (!Utils::RvaToOffset(lpNtHeader, dwBaseOffset, &dwBaseOffset))
					{
						Utils::Printf::Fail("Invalid directory table %s entry of %d", GetDirTableName(dwDirectory), dwBaseOffset);
						return FALSE;
					};
				};

				*lpDirEntry = dwBaseOffset;
				*lpDirSize = dwTableSize;
				return TRUE;
			};
			Utils::Printf::Fail("Cannot retrieve directory information");
			return FALSE;
		};
		LPCSTR GetDirTableName(DWORD dwDirectory)
		{
			switch (dwDirectory)
			{
			case IMAGE_DIRECTORY_ENTRY_EXPORT:
				return "IMAGE_DIRECTORY_ENTRY_EXPORT";
			case IMAGE_DIRECTORY_ENTRY_IMPORT:
				return "IMAGE_DIRECTORY_ENTRY_IMPORT";
			case IMAGE_DIRECTORY_ENTRY_RESOURCE:
				return "IMAGE_DIRECTORY_ENTRY_RESOURCE";
			case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				return "IMAGE_DIRECTORY_ENTRY_EXCEPTION";
			case IMAGE_DIRECTORY_ENTRY_SECURITY:
				return "IMAGE_DIRECTORY_ENTRY_SECURITY";
			case IMAGE_DIRECTORY_ENTRY_BASERELOC:
				return "IMAGE_DIRECTORY_ENTRY_BASERELOC";
			case IMAGE_DIRECTORY_ENTRY_DEBUG:
				return "IMAGE_DIRECTORY_ENTRY_DEBUG";
			case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
				return "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE";
			case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				return "IMAGE_DIRECTORY_ENTRY_GLOBALPTR";
			case IMAGE_DIRECTORY_ENTRY_TLS:
				return "IMAGE_DIRECTORY_ENTRY_TLS";
			case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				return "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG";
			case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				return "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT";
			case IMAGE_DIRECTORY_ENTRY_IAT:
				return "IMAGE_DIRECTORY_ENTRY_IAT";
			case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				return "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT";
			case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				return "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";
			default:
				return "[UNDEFINED_TABLE]";
			}
		};
	};
};
