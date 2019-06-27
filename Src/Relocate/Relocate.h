#include "../Utils/Utils.h"

namespace Relocate
{
	BOOL Module(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped);
	BOOL Section(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped, DWORD dwSecIndex);
	BOOL Region(PRAW_FILE_INFO lpPEInfo, uintptr_t NewBase, BOOL IsMapped, DWORD dwStartRVA, DWORD dwEndRVA);
};
