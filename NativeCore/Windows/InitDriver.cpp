#include "../Dependencies/libmhyprot/libmhyprot.h"
#include <windows.h>
#include "NativeCore.hpp"

extern "C" bool RC_CallConv InitDriver()
{
	return libmhyprot::mhyprot_init();
}