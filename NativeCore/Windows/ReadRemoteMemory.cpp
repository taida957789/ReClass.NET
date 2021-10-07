#include <windows.h>
#include "../Dependencies/libmhyprot/libmhyprot.h"
#include "NativeCore.hpp"

bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);

	SIZE_T numberOfBytesRead;
	uint32_t pid = GetProcessId((HANDLE)handle);
	return libmhyprot::read_process_memory(pid, (uint64_t)address, (void*)buffer, size);
}
