#include "Relocate.h"
#include "../Load/Load.h"

BOOL GetDirectoryInfo(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PDWORD lpDirEntry, PDWORD lpDirSize, BOOL IsMapped);
LPCSTR GetDirTableName(DWORD dwDirectory);
BOOL IsDirExists(PIMAGE_NT_HEADERS lpNtHeader, DWORD dwDirectory, PBOOL IsExists);
BOOL ApplyRegionRelocaetion(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	DWORD dwPtrRva, BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);

BOOL RelocationTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ExportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ResourceTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ExceptionTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL SecurityTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL DebugTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ArchitectureTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL GlobalPtrTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL TlsTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL LoadConfigTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL IATTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL DelayImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL BoundImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);
BOOL ComDescImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize);

namespace Relocate
{
	BOOL Module(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped)
	{
		PIMAGE_NT_HEADERS lpNtHeader = NULL;
		if (Load::PE::GetNtHeader(
			lpPEInfo,
			&lpNtHeader
		))
		{
			BOOL IsRelocatable = FALSE;
			if (!Load::PE::CheckRelocation(lpPEInfo, &IsRelocatable) ||
				!IsRelocatable ||
				!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, &IsRelocatable) ||
				!IsRelocatable
				)
			{
				Utils::Printf::Fail("This PE is not relocatable");
				return FALSE;
			};
			if (!RelocationTableRegionReloc(
				lpPEInfo,
				lpNtHeader,
				NewBase,
				IsMapped,
				0,
				lpNtHeader->OptionalHeader.SizeOfImage
			)) return FALSE;
		};

		Utils::Printf::Fail("Cannot relocate the PE");
		return FALSE;
	};
	BOOL Section(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped, DWORD dwSecIndex)
	{
		PIMAGE_NT_HEADERS lpNtHeader = NULL;
		if (Load::PE::GetNtHeader(
			lpPEInfo,
			&lpNtHeader
		))
		{
			if (dwSecIndex && dwSecIndex < lpNtHeader->FileHeader.NumberOfSections)
			{
				return Relocate::Region(
					lpPEInfo,
					NewBase,
					IsMapped,
					IMAGE_FIRST_SECTION(lpNtHeader)[dwSecIndex].VirtualAddress,
					IMAGE_FIRST_SECTION(lpNtHeader)[dwSecIndex].Misc.VirtualSize
				);
			};
		};

		Utils::Printf::Fail("Cannot relocate this section at index %d", dwSecIndex);
		return FALSE;

	};
	BOOL Region(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
	{
		PIMAGE_NT_HEADERS lpNtHeader = NULL;
		if (Load::PE::GetNtHeader(
			lpPEInfo,
			&lpNtHeader
		))
		{
			BOOL IsExists = FALSE;
			BOOL IsRelocatable = FALSE;
			if (!Load::PE::CheckRelocation(lpPEInfo, &IsRelocatable) ||
				!IsRelocatable ||
				!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, &IsExists) ||
				!IsExists
				)
			{
				Utils::Printf::Fail("This PE is not relocatable");
				return FALSE;
			};

			if (!RelocationTableRegionReloc(
				lpPEInfo,
				lpNtHeader,
				NewBase,
				IsMapped,
				dwRegionBaseRva,
				dwRegionSize
			)) return FALSE;

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, &IsExists)) return FALSE;
				
			if (IsExists)
			{
				if (!ExportTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!ImportTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_RESOURCE, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!ResourceTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!ExceptionTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_SECURITY, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!SecurityTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DEBUG, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!DebugTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!ArchitectureTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!GlobalPtrTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_TLS, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!TlsTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!LoadConfigTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IAT, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!IATTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!DelayImportTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!BoundImportTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};

			if (!IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &IsExists)) return FALSE;

			if (IsExists)
			{
				if (!ComDescImportTableRegionReloc(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};
		};

		Utils::Printf::Fail("Cannot relocate the region");
		return FALSE;
	};
};

BOOL ApplyRegionRelocaetion(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase, 
	DWORD dwPtrRva, BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwRegionBaseRva, &dwRegionBaseRva)
			|| !Utils::RvaToOffset(lpNtHeader, dwPtrRva, &dwPtrRva)) return FALSE;
	};

	if (!Utils::IsValidReadPtr(
		(LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwRegionBaseRva),
		dwRegionSize
	) || !Utils::IsValidReadPtr(
		(LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwPtrRva),
		sizeof(PVOID)
	)) return FALSE;
	
	if (dwPtrRva >= dwRegionBaseRva && dwPtrRva < dwRegionBaseRva + dwRegionSize)
	{
		uintptr_t *lpPtrAddr = (uintptr_t*)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwPtrRva);
		*lpPtrAddr -= (uintptr_t)lpNtHeader->OptionalHeader.ImageBase;
		*lpPtrAddr += NewBase;
	};
	return TRUE;
};
BOOL ApplyRvaRelocation(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	LPVOID RvaPtr, BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize) 
{
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwRegionBaseRva, &dwRegionBaseRva)) return FALSE;
	};

	if (!Utils::IsValidReadPtr(
		(LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwRegionBaseRva),
		dwRegionSize
	) || !Utils::IsValidReadPtr(
		RvaPtr,
		sizeof(DWORD)
	)) return FALSE;

	if (*(PDWORD)RvaPtr >= dwRegionBaseRva && *(PDWORD)RvaPtr < dwRegionBaseRva + dwRegionSize)
	{
		DWORD dwDiff = 0;
		if (NewBase > (uintptr_t)lpNtHeader->OptionalHeader.ImageBase)
		{
			dwDiff = NewBase - (uintptr_t)lpNtHeader->OptionalHeader.ImageBase;
			*(PDWORD)RvaPtr += dwDiff;
		}
		else
		{
			dwDiff = (uintptr_t)lpNtHeader->OptionalHeader.ImageBase - NewBase;
			*(PDWORD)RvaPtr -= dwDiff;
		};
	};
	return TRUE;
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

		if (!IsMapped)
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

BOOL RelocationTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase, 
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	DWORD dwRelocBaseOffset = 0;
	DWORD dwRelocSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_BASERELOC,
		&dwRelocBaseOffset,
		&dwRelocSize,
		IsMapped
	)) return FALSE;

	LPVOID lpRelocBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwRelocBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpRelocBase,
		dwRelocSize
	)) return FALSE;

	for (DWORD dwMemIndex = 0; dwMemIndex < dwRelocSize;)
	{
		PIMAGE_BASE_RELOCATION lpBaseRelocBlock = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lpRelocBase + dwMemIndex);
		LPVOID lpBlocksEntry = (LPVOID)((DWORD_PTR)lpBaseRelocBlock + sizeof(lpBaseRelocBlock->SizeOfBlock) + sizeof(lpBaseRelocBlock->VirtualAddress));

		DWORD dwNumberOfBlocks = (lpBaseRelocBlock->SizeOfBlock - sizeof(lpBaseRelocBlock->SizeOfBlock) - sizeof(lpBaseRelocBlock->VirtualAddress)) / sizeof(WORD);
		PWORD lpBlocks = (PWORD)lpBlocksEntry;

		for (DWORD dwBlockIndex = 0; dwBlockIndex < dwNumberOfBlocks; dwBlockIndex++)
		{
			WORD wBlockType = (lpBlocks[dwBlockIndex] & 0xf000) >> 0xC;
			WORD wBlockOffset = lpBlocks[dwBlockIndex] & 0x0fff;

			if ((wBlockType == IMAGE_REL_BASED_HIGHLOW) || (wBlockType == IMAGE_REL_BASED_DIR64))
			{
				if (!ApplyRegionRelocaetion(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					lpBaseRelocBlock->VirtualAddress + wBlockOffset,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			}
			else if (lpBlocks[dwBlockIndex] != 0)
			{
				Utils::Printf::Fail("Invalid relocation table");
				return FALSE;
			};
		};

		dwMemIndex += lpBaseRelocBlock->SizeOfBlock;
	};

	return TRUE;
};
BOOL ExportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{

	DWORD dwExportBaseOffset = 0;
	DWORD dwExportSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&dwExportBaseOffset,
		&dwExportSize,
		IsMapped
	)) return FALSE;

	LPVOID lpExportBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwExportBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpExportBase,
		dwExportSize
	)) return FALSE;

	PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)lpExportBase;
	DWORD dwAddressOfFunctionsOffset = lpExportDirectory->AddressOfFunctions;

	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwAddressOfFunctionsOffset, &dwAddressOfFunctionsOffset)) return FALSE;
	};

	PDWORD lpFunctions = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwAddressOfFunctionsOffset);
	for (DWORD dwFuncIndex = 0; dwFuncIndex < lpExportDirectory->NumberOfFunctions; dwFuncIndex++) {

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpFunctions[dwFuncIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	DWORD dwAddressOfNamesOffset = lpExportDirectory->AddressOfNames;

	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwAddressOfNamesOffset, &dwAddressOfNamesOffset)) return FALSE;
	};  

	PDWORD lpNames = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwAddressOfNamesOffset);
	for (DWORD dwNameIndex = 0; dwNameIndex < lpExportDirectory->NumberOfNames; dwNameIndex++) {

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpNames[dwNameIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpExportDirectory->Name,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpExportDirectory->AddressOfFunctions,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpExportDirectory->AddressOfNameOrdinals,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpExportDirectory->AddressOfNames,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL ImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	DWORD dwImportBaseOffset = 0;
	DWORD dwImportSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&dwImportBaseOffset,
		&dwImportSize,
		IsMapped
	)) return FALSE;

	LPVOID lpImportBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwImportBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpImportBase,
		dwImportSize
	)) return FALSE;

	PIMAGE_IMPORT_DESCRIPTOR lpImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)lpImportBase;

	DWORD dwCThunkOffset;
	PIMAGE_THUNK_DATA dwCThunk;
	while (lpImportDirectory->Name != NULL)
	{
		dwCThunkOffset = lpImportDirectory->OriginalFirstThunk;
		if (!IsMapped)
		{
			if (!Utils::RvaToOffset(lpNtHeader, dwCThunkOffset, &dwCThunkOffset)) return FALSE;
		};

		dwCThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwCThunkOffset);

		while (dwCThunk->u1.AddressOfData)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(dwCThunk->u1.Ordinal)) {
				if (!ApplyRvaRelocation(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					&dwCThunk->u1.AddressOfData,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};
			dwCThunkOffset += sizeof(IMAGE_THUNK_DATA);
			dwCThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwCThunkOffset);
		}

		dwCThunkOffset = lpImportDirectory->FirstThunk;
		if (!IsMapped)
		{
			if (!Utils::RvaToOffset(lpNtHeader, dwCThunkOffset, &dwCThunkOffset)) return FALSE;
		};

		dwCThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwCThunkOffset);

		while (dwCThunk->u1.AddressOfData)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(dwCThunk->u1.Ordinal)) {
				if (!ApplyRvaRelocation(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					&dwCThunk->u1.AddressOfData,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			};
			dwCThunkOffset += sizeof(IMAGE_THUNK_DATA);
			dwCThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwCThunkOffset);
		}

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpImportDirectory->OriginalFirstThunk,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpImportDirectory->FirstThunk,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpImportDirectory->Name,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;

		lpImportDirectory++;
	};


	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL ResourceTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{

	DWORD dwResourceBaseOffset = 0;
	DWORD dwResourceSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&dwResourceBaseOffset,
		&dwResourceSize,
		IsMapped
	)) return FALSE;

	LPVOID lpResourceBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwResourceBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpResourceBase,
		dwResourceSize
	)) return FALSE;

	
	PIMAGE_RESOURCE_DIRECTORY lpResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)lpResourceBase;
	LPVOID lpBaseOffset = (LPVOID)lpResourceDirectory;

	auto HandleResDirTable = [&](PIMAGE_RESOURCE_DIRECTORY lpResourceDirectory, auto& HandleResDirTable) {

		PIMAGE_RESOURCE_DIRECTORY_ENTRY lpResDirEntriesArray = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD_PTR)lpResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));

		if (lpResourceDirectory->NumberOfIdEntries + lpResourceDirectory->NumberOfNamedEntries == 0) return FALSE;
		
		for (DWORD dwEntryIndex = 0; dwEntryIndex < lpResourceDirectory->NumberOfNamedEntries; dwEntryIndex++) {
			if (lpResDirEntriesArray->DataIsDirectory) {
				PIMAGE_RESOURCE_DIRECTORY lpEntryResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)lpBaseOffset + lpResDirEntriesArray->OffsetToDirectory);
				HandleResDirTable(lpEntryResourceDirectory, HandleResDirTable);
			}
			else
			{
				PIMAGE_RESOURCE_DATA_ENTRY lpEntryDataDirectory = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)lpBaseOffset + lpResDirEntriesArray->OffsetToData);
				if (!ApplyRvaRelocation(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					&lpEntryDataDirectory->OffsetToData,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			}
			lpResDirEntriesArray++;
		};

		for (DWORD dwEntryIndex = 0; dwEntryIndex < lpResourceDirectory->NumberOfIdEntries; dwEntryIndex++) {
			if (lpResDirEntriesArray->DataIsDirectory) {
				PIMAGE_RESOURCE_DIRECTORY lpEntryResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)lpBaseOffset + lpResDirEntriesArray->OffsetToDirectory);
				HandleResDirTable(lpEntryResourceDirectory, HandleResDirTable);
			}
			else
			{
				PIMAGE_RESOURCE_DATA_ENTRY lpEntryDataDirectory = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)lpBaseOffset + lpResDirEntriesArray->OffsetToData);
				if (!ApplyRvaRelocation(
					lpPEInfo,
					lpNtHeader,
					NewBase,
					&lpEntryDataDirectory->OffsetToData,
					IsMapped,
					dwRegionBaseRva,
					dwRegionSize
				)) return FALSE;
			}
			lpResDirEntriesArray++;
		};

		return TRUE;
	};
	if (!HandleResDirTable(lpResourceDirectory, HandleResDirTable)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_RESOURCE),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL ExceptionTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{

	DWORD dwExceptionBaseOffset = 0;
	DWORD dwExceptionSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&dwExceptionBaseOffset,
		&dwExceptionSize,
		IsMapped
	)) return FALSE;

	LPVOID lpExceptionBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwExceptionBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpExceptionBase,
		dwExceptionSize
	)) return FALSE;

	typedef struct
	{
		DWORD BeginAddress;
		DWORD EndAddress;
		DWORD UnwindInfoAddress;
	} IMAGE_EXCEPTION_DESCRIPTOR, * PIMAGE_EXCEPTION_DESCRIPTOR;

	DWORD dwNumberOfEntries = dwExceptionSize / sizeof(IMAGE_EXCEPTION_DESCRIPTOR);
	PIMAGE_EXCEPTION_DESCRIPTOR lpExceptionDirectory = (PIMAGE_EXCEPTION_DESCRIPTOR)lpExceptionBase;

	for (DWORD dwEntryIndex = 0; dwEntryIndex < dwNumberOfEntries; dwEntryIndex++) {

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpExceptionDirectory[dwEntryIndex].BeginAddress,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpExceptionDirectory[dwEntryIndex].EndAddress,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpExceptionDirectory[dwEntryIndex].UnwindInfoAddress,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL SecurityTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_SECURITY),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL DebugTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	DWORD dwDebugBaseOffset = 0;
	DWORD dwDebugSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_DEBUG,
		&dwDebugBaseOffset,
		&dwDebugSize,
		IsMapped
	)) return FALSE;

	LPVOID lpDebugBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwDebugBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpDebugBase,
		dwDebugSize
	)) return FALSE;

	PIMAGE_DEBUG_DIRECTORY lpDebugDirectory = (PIMAGE_DEBUG_DIRECTORY)lpDebugBase;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpDebugDirectory->AddressOfRawData,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DEBUG),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&lpDebugDirectory->PointerToRawData,
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;

	return TRUE;
};
BOOL ArchitectureTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	DWORD dwArchitectutreBaseOffset = 0;
	DWORD dwArchitectutreSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
		&dwArchitectutreBaseOffset,
		&dwArchitectutreSize,
		IsMapped
	)) return FALSE;

	LPVOID lpArchitectutreBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwArchitectutreBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpArchitectutreBase,
		dwArchitectutreSize
	)) return FALSE;

	PIMAGE_ARCHITECTURE_HEADER lpArchDirectory = (PIMAGE_ARCHITECTURE_HEADER)lpArchitectutreBase;

	for (DWORD dwArchTableIndex = 0; *(DWORD*)& lpArchDirectory[dwArchTableIndex] != (DWORD)-1; dwArchTableIndex++)
	{
		DWORD dwFirstEntryOffset = lpArchDirectory[dwArchTableIndex].FirstEntryRVA;
		if (!IsMapped)
		{
			if (!Utils::RvaToOffset(lpNtHeader, dwFirstEntryOffset, &dwFirstEntryOffset)) return FALSE;
		};

		PIMAGE_ARCHITECTURE_ENTRY lpArchEntriesArray = (PIMAGE_ARCHITECTURE_ENTRY)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwFirstEntryOffset);

		for (DWORD dwArchEntryIndex = 0; *(DWORD*)& lpArchEntriesArray[dwArchEntryIndex] != (DWORD)-1; dwArchEntryIndex++)
		{
			if (!ApplyRvaRelocation(
				lpPEInfo,
				lpNtHeader,
				NewBase,
				&lpArchEntriesArray[dwArchEntryIndex].FixupInstRVA,
				IsMapped,
				dwRegionBaseRva,
				dwRegionSize
			)) return FALSE;
		};

		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpArchDirectory[dwArchTableIndex].FirstEntryRVA,
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;
	return TRUE;
};
BOOL GlobalPtrTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_GLOBALPTR),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;
	return TRUE;
};
BOOL TlsTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_TLS),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;
	return TRUE;
};
BOOL LoadConfigTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	DWORD dwLoadConfigBaseOffset = 0;
	DWORD dwLoadConfigSize = 0;
	if (!GetDirectoryInfo(
		lpNtHeader,
		IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
		&dwLoadConfigBaseOffset,
		&dwLoadConfigSize,
		IsMapped
	)) return FALSE;

	LPVOID lpLoadConfigBase = (LPVOID)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwLoadConfigBaseOffset);
	if (!Utils::IsValidReadPtr(
		lpLoadConfigBase,
		dwLoadConfigSize
	)) return FALSE;

	typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
		WORD    Flags;
		WORD    Catalog;
		DWORD   CatalogOffset;
		DWORD   Reserved;
	} IMAGE_LOAD_CONFIG_CODE_INTEGRITY, * PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

#if defined(_M_X64) || defined(__amd64__)
	typedef struct _FULL_IMAGE_LOAD_CONFIG_DIRECTORY {
		DWORD                            Size;
		DWORD                            TimeDateStamp;
		WORD                             MajorVersion;
		WORD                             MinorVersion;
		DWORD                            GlobalFlagsClear;
		DWORD                            GlobalFlagsSet;
		DWORD                            CriticalSectionDefaultTimeout;
		ULONGLONG                        DeCommitFreeBlockThreshold;
		ULONGLONG                        DeCommitTotalFreeThreshold;
		ULONGLONG                        LockPrefixTable;
		ULONGLONG                        MaximumAllocationSize;
		ULONGLONG                        VirtualMemoryThreshold;
		ULONGLONG                        ProcessAffinityMask;
		DWORD                            ProcessHeapFlags;
		WORD                             CSDVersion;
		WORD                             DependentLoadFlags;
		ULONGLONG                        EditList;
		ULONGLONG                        SecurityCookie;
		ULONGLONG                        SEHandlerTable;
		ULONGLONG                        SEHandlerCount;
		ULONGLONG                        GuardCFCheckFunctionPointer;
		ULONGLONG                        GuardCFDispatchFunctionPointer;
		ULONGLONG                        GuardCFFunctionTable;
		ULONGLONG                        GuardCFFunctionCount;
		DWORD                            GuardFlags;
		IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		ULONGLONG                        GuardAddressTakenIatEntryTable;
		ULONGLONG                        GuardAddressTakenIatEntryCount;
		ULONGLONG                        GuardLongJumpTargetTable;
		ULONGLONG                        GuardLongJumpTargetCount;
		ULONGLONG                        DynamicValueRelocTable;
		ULONGLONG                        CHPEMetadataPointer;
		ULONGLONG                        GuardRFFailureRoutine;
		ULONGLONG                        GuardRFFailureRoutineFunctionPointer;
		DWORD                            DynamicValueRelocTableOffset;
		WORD                             DynamicValueRelocTableSection;
		WORD                             Reserved2;
		ULONGLONG                        GuardRFVerifyStackPointerFunctionPointer;
		DWORD                            HotPatchTableOffset;
		DWORD                            Reserved3;
		ULONGLONG                        EnclaveConfigurationPointer;
		ULONGLONG                        VolatileMetadataPointer;
	} FULL_IMAGE_LOAD_CONFIG_DIRECTORY, * PFULL_IMAGE_LOAD_CONFIG_DIRECTORY;
#else
	typedef struct _FULL_IMAGE_LOAD_CONFIG_DIRECTORY {
		DWORD                            Size;
		DWORD                            TimeDateStamp;
		WORD                             MajorVersion;
		WORD                             MinorVersion;
		DWORD                            GlobalFlagsClear;
		DWORD                            GlobalFlagsSet;
		DWORD                            CriticalSectionDefaultTimeout;
		DWORD                            DeCommitFreeBlockThreshold;
		DWORD                            DeCommitTotalFreeThreshold;
		DWORD                            LockPrefixTable;
		DWORD                            MaximumAllocationSize;
		DWORD                            VirtualMemoryThreshold;
		DWORD                            ProcessHeapFlags;
		DWORD                            ProcessAffinityMask;
		WORD                             CSDVersion;
		WORD                             DependentLoadFlags;
		DWORD                            EditList;
		DWORD                            SecurityCookie;
		DWORD                            SEHandlerTable;
		DWORD                            SEHandlerCount;
		DWORD                            GuardCFCheckFunctionPointer;
		DWORD                            GuardCFDispatchFunctionPointer;
		DWORD                            GuardCFFunctionTable;
		DWORD                            GuardCFFunctionCount;
		DWORD                            GuardFlags;
		IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		DWORD                            GuardAddressTakenIatEntryTable;
		DWORD                            GuardAddressTakenIatEntryCount;
		DWORD                            GuardLongJumpTargetTable;
		DWORD                            GuardLongJumpTargetCount;
		DWORD                            DynamicValueRelocTable;
		DWORD                            CHPEMetadataPointer;
		DWORD                            GuardRFFailureRoutine;
		DWORD                            GuardRFFailureRoutineFunctionPointer;
		DWORD                            DynamicValueRelocTableOffset;
		WORD                             DynamicValueRelocTableSection;
		WORD                             Reserved2;
		DWORD                            GuardRFVerifyStackPointerFunctionPointer;
		DWORD                            HotPatchTableOffset;
		DWORD                            Reserved3;
		DWORD                            EnclaveConfigurationPointer;
		DWORD                            VolatileMetadataPointer;
	} FULL_MAGE_LOAD_CONFIG_DIRECTORY, * PFULL_IMAGE_LOAD_CONFIG_DIRECTORY;
#endif

	PFULL_IMAGE_LOAD_CONFIG_DIRECTORY lpLoadConfigDirectory = (PFULL_IMAGE_LOAD_CONFIG_DIRECTORY)lpLoadConfigBase;
	DWORD dwSEHTableRva = (DWORD)(lpLoadConfigDirectory->SEHandlerTable - lpNtHeader->OptionalHeader.ImageBase);
	DWORD dwGuardCFTableRva = (DWORD)(lpLoadConfigDirectory->GuardCFFunctionTable - lpNtHeader->OptionalHeader.ImageBase);
	DWORD dwGuardLongJumpTargetTableRva = (DWORD)(lpLoadConfigDirectory->GuardLongJumpTargetTable - lpNtHeader->OptionalHeader.ImageBase);
	DWORD dwGuardAddressTakenIatEntryTableRva = (DWORD)(lpLoadConfigDirectory->GuardAddressTakenIatEntryTable - lpNtHeader->OptionalHeader.ImageBase);

	DWORD dwSEHTableOffset = dwSEHTableRva;
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwSEHTableOffset, &dwSEHTableOffset)) return FALSE;
	};

	DWORD dwGuardCFTableOffset = dwGuardCFTableRva;
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwGuardCFTableOffset, &dwGuardCFTableOffset)) return FALSE;
	};

	DWORD dwGuardLongJumpTargetTableOffset = dwGuardLongJumpTargetTableRva;
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwGuardLongJumpTargetTableOffset, &dwGuardLongJumpTargetTableOffset)) return FALSE;
	};

	DWORD dwGuardAddressTakenIatEntryTableOffset = dwGuardAddressTakenIatEntryTableRva;
	if (!IsMapped)
	{
		if (!Utils::RvaToOffset(lpNtHeader, dwGuardAddressTakenIatEntryTableOffset, &dwGuardAddressTakenIatEntryTableOffset)) return FALSE;
	};

	PDWORD lpSEHTable = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwSEHTableOffset);
	for (DWORD dwSEHIndex = 0; dwSEHIndex < lpLoadConfigDirectory->SEHandlerCount; dwSEHIndex++)
	{
		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpSEHTable[dwSEHIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	PDWORD lpGuardCFTable = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwGuardCFTableOffset);
	for (DWORD dwGuardCFIndex = 0; dwGuardCFIndex < lpLoadConfigDirectory->GuardCFFunctionCount; dwGuardCFIndex++)
	{
		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpGuardCFTable[dwGuardCFIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	PDWORD lpGuardLongJumpTargetTable = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwGuardLongJumpTargetTableOffset);
	for (DWORD dwGuardCFIndex = 0; dwGuardCFIndex < lpLoadConfigDirectory->GuardLongJumpTargetCount; dwGuardCFIndex++)
	{
		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpGuardLongJumpTargetTable[dwGuardCFIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	PDWORD lpGuardAddressTakenIatEntryTable = (PDWORD)((DWORD_PTR)lpPEInfo->lpDataBuffer + dwGuardAddressTakenIatEntryTableOffset);
	for (DWORD dwGuardAddressTakenIatEntryIndex = 0; dwGuardAddressTakenIatEntryIndex < lpLoadConfigDirectory->GuardAddressTakenIatEntryCount; dwGuardAddressTakenIatEntryIndex++)
	{
		if (!ApplyRvaRelocation(
			lpPEInfo,
			lpNtHeader,
			NewBase,
			&lpGuardAddressTakenIatEntryTable[dwGuardAddressTakenIatEntryIndex],
			IsMapped,
			dwRegionBaseRva,
			dwRegionSize
		)) return FALSE;
	};

	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;
	return TRUE;
};
BOOL IATTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	if (!ApplyRvaRelocation(
		lpPEInfo,
		lpNtHeader,
		NewBase,
		&GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_IAT),
		IsMapped,
		dwRegionBaseRva,
		dwRegionSize
	)) return FALSE;
	return TRUE;
};
BOOL DelayImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	Utils::Printf::Fail("[-] Relocating regions with delay import table is not supported yet");
	return FALSE;
};
BOOL BoundImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	Utils::Printf::Fail("[-] Relocating regions with bound import table is not supported yet");
	return FALSE;
};
BOOL ComDescImportTableRegionReloc(PRAW_FILE_INFO lpPEInfo, PIMAGE_NT_HEADERS lpNtHeader, uintptr_t NewBase,
	BOOL IsMapped, DWORD dwRegionBaseRva, DWORD dwRegionSize)
{
	Utils::Printf::Fail("[-] Relocating regions in .NET PE is not supported yet");
	return FALSE;
};
