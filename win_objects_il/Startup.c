#include "pch.h"
#include <corecrt_startup.h>

int wmain(int argc, wchar_t* argv[]);

DWORD Startup(LPVOID lpParameter) {
	_configure_wide_argv(_crt_argv_unexpanded_arguments);
	int result = wmain(__argc, __wargv);
	ExitProcess(result);
	return result;
}