#include <windows.h>

#include "NativeCore.hpp"
#include "../Dependencies/libmhyprot/libmhyprot.h"

bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);
	uint32_t pid = GetProcessId((HANDLE)handle);
	return libmhyprot::write_process_memory(pid, (uint64_t)address, (void*)buffer, size);
}
